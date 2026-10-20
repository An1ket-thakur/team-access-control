import { Router } from "express";
import { and, asc, count, desc, eq, gt, ilike, isNotNull, isNull, lte, sql } from "drizzle-orm";
import { z } from "zod";
import { config } from "../../config";
import { db } from "../../db";
import { invitations, memberships, organizations, roles, users } from "../../schema";
import { randomToken, sha256 } from "../../lib/crypto";
import { Errors } from "../../lib/errors";
import { isUniqueViolation } from "../../lib/pgErrors";
import { likeEscape, offsetOf, pageMeta, paginationQuery } from "../../lib/pagination";
import { ROLE_NAMES } from "../../lib/permissions";
import { authenticate, userPrincipal } from "../../middleware/auth";
import { rateLimit } from "../../middleware/rateLimit";
import { requirePermission } from "../../middleware/permissions";
import { emailSchema } from "../auth/auth.schemas";
import { canAssignRank, findOrgRole } from "../orgs/orgs.service";
import { audit } from "../../lib/audit";

/** Mounted at /orgs/:orgId/invitations (manage the invitations of one organization). */
export const invitationsRouter = Router({ mergeParams: true });

const createBody = z.object({
  email: emailSchema,
  role: z.enum(ROLE_NAMES as [string, ...string[]]).default("member"),
});

const listQuery = paginationQuery.extend({
  status: z.enum(["pending", "accepted", "revoked", "expired"]).optional(),
  search: z.string().trim().max(100).optional(),
  order: z.enum(["asc", "desc"]).default("desc"),
});

// POST /orgs/:orgId/invitations   { email, role }
invitationsRouter.post("/", requirePermission("users.invite"), async (req, res) => {
  const actor = userPrincipal(req);
  const orgId = req.org!.orgId;
  const body = createBody.parse(req.body);

  const role = await findOrgRole(orgId, body.role);
  if (!role) throw Errors.notFound("Role");
  if (!canAssignRank(req.org!.role!, role.rank)) {
    throw Errors.forbidden("You cannot invite someone to a role at or above your own");
  }

  // Already a member?
  const [existing] = await db
    .select({ id: memberships.id })
    .from(memberships)
    .innerJoin(users, eq(users.id, memberships.userId))
    .where(and(eq(memberships.orgId, orgId), eq(users.email, body.email), isNull(users.deletedAt)))
    .limit(1);
  if (existing) throw Errors.conflict("That person is already a member of this organization");

  const token = randomToken(32);
  const expiresAt = new Date(Date.now() + config.INVITE_TTL_HOURS * 3_600_000);

  let invitation: typeof invitations.$inferSelect;
  try {
    invitation = await db.transaction(async (tx) => {
      // An expired-but-unanswered invite must not block a fresh one.
      await tx
        .update(invitations)
        .set({ revokedAt: new Date() })
        .where(
          and(
            eq(invitations.orgId, orgId),
            eq(invitations.email, body.email),
            isNull(invitations.acceptedAt),
            isNull(invitations.revokedAt),
            lte(invitations.expiresAt, new Date()),
          ),
        );
      const [row] = await tx
        .insert(invitations)
        .values({
          orgId,
          email: body.email,
          roleId: role.id,
          tokenHash: sha256(token),
          invitedBy: actor.userId,
          expiresAt,
        })
        .returning();
      await audit(
        req,
        {
          action: "invitation.created",
          orgId,
          targetType: "invitation",
          targetId: row.id,
          metadata: { email: body.email, role: role.name },
        },
        tx,
      );
      return row;
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw Errors.conflict("A pending invitation already exists for that email");
    throw err;
  }

  // Integration point: email `token` to the invitee. We only echo it back in dev mode.
  res.status(201).json({
    invitation: serialize(invitation, role.name),
    ...(config.EXPOSE_DEV_TOKENS && { inviteToken: token }),
  });
});

// GET /orgs/:orgId/invitations?status=&search=&order=&page=&limit=
invitationsRouter.get("/", requirePermission("users.invite"), async (req, res) => {
  const orgId = req.org!.orgId;
  const q = listQuery.parse(req.query);
  const now = new Date();

  const statusCondition = {
    pending: and(isNull(invitations.acceptedAt), isNull(invitations.revokedAt), gt(invitations.expiresAt, now)),
    accepted: isNotNull(invitations.acceptedAt),
    revoked: and(isNull(invitations.acceptedAt), isNotNull(invitations.revokedAt)),
    expired: and(isNull(invitations.acceptedAt), isNull(invitations.revokedAt), lte(invitations.expiresAt, now)),
  };

  const where = and(
    eq(invitations.orgId, orgId),
    q.status ? statusCondition[q.status] : undefined,
    q.search ? ilike(invitations.email, `%${likeEscape(q.search)}%`) : undefined,
  );

  const [{ total }] = await db.select({ total: count() }).from(invitations).where(where);
  const rows = await db
    .select({ inv: invitations, roleName: roles.name })
    .from(invitations)
    .innerJoin(roles, eq(roles.id, invitations.roleId))
    .where(where)
    .orderBy((q.order === "asc" ? asc : desc)(invitations.createdAt))
    .limit(q.limit)
    .offset(offsetOf(q));

  res.json({ data: rows.map((r) => serialize(r.inv, r.roleName)), meta: pageMeta(q, total) });
});

// DELETE /orgs/:orgId/invitations/:invitationId   (revoke a pending invitation)
invitationsRouter.delete("/:invitationId", requirePermission("users.invite"), async (req, res) => {
  const orgId = req.org!.orgId;
  const id = z.string().uuid().safeParse(req.params.invitationId);
  if (!id.success) throw Errors.notFound("Invitation");

  const revoked = await db.transaction(async (tx) => {
    const rows = await tx
      .update(invitations)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(invitations.id, id.data),
          eq(invitations.orgId, orgId),
          isNull(invitations.acceptedAt),
          isNull(invitations.revokedAt),
        ),
      )
      .returning({ id: invitations.id, email: invitations.email });
    if (rows.length > 0) {
      await audit(
        req,
        {
          action: "invitation.revoked",
          orgId,
          targetType: "invitation",
          targetId: id.data,
          metadata: { email: rows[0].email },
        },
        tx,
      );
    }
    return rows.length > 0;
  });
  if (!revoked) throw Errors.notFound("Pending invitation");
  res.status(204).end();
});

function serialize(inv: typeof invitations.$inferSelect, roleName: string) {
  const status = inv.acceptedAt
    ? "accepted"
    : inv.revokedAt
      ? "revoked"
      : inv.expiresAt.getTime() <= Date.now()
        ? "expired"
        : "pending";
  return {
    id: inv.id,
    email: inv.email,
    role: roleName,
    status,
    invitedBy: inv.invitedBy,
    createdAt: inv.createdAt,
    expiresAt: inv.expiresAt,
    acceptedAt: inv.acceptedAt,
  };
}

/** Mounted at /invitations (the invitee's side). */
export const inviteAcceptRouter = Router();

const acceptLimiter = rateLimit({
  name: "invite-accept",
  max: config.RATE_LIMIT_AUTH_MAX,
  windowSeconds: config.RATE_LIMIT_AUTH_WINDOW_SECONDS,
});

// POST /invitations/accept   { token }   (you must be signed in as the invited email)
inviteAcceptRouter.post("/accept", acceptLimiter, authenticate, async (req, res) => {
  const { userId } = userPrincipal(req);
  const { token } = z.object({ token: z.string().min(10).max(200) }).parse(req.body);

  const result = await db.transaction(async (tx) => {
    const [user] = await tx
      .select({ email: users.email })
      .from(users)
      .where(and(eq(users.id, userId), isNull(users.deletedAt)))
      .limit(1);
    if (!user) throw Errors.unauthenticated();

    // Lock the row so two concurrent accepts cannot both succeed.
    const locked = await tx.execute(sql`
      SELECT i.id FROM invitations i
      WHERE i.token_hash = ${sha256(token)} FOR UPDATE
    `);
    const lockedId = (locked.rows[0] as { id: string } | undefined)?.id;
    if (!lockedId) throw Errors.invitationInvalid();

    const [row] = await tx
      .select({
        inv: invitations,
        roleName: roles.name,
        orgName: organizations.name,
        orgDeleted: organizations.deletedAt,
      })
      .from(invitations)
      .innerJoin(roles, eq(roles.id, invitations.roleId))
      .innerJoin(organizations, eq(organizations.id, invitations.orgId))
      .where(eq(invitations.id, lockedId))
      .limit(1);

    const inv = row?.inv;
    // The same generic error for every failure mode: do not reveal which part was wrong.
    if (
      !row ||
      !inv ||
      inv.acceptedAt ||
      inv.revokedAt ||
      inv.expiresAt <= new Date() ||
      row.orgDeleted ||
      inv.email !== user.email
    ) {
      throw Errors.invitationInvalid();
    }

    const [already] = await tx
      .select({ id: memberships.id })
      .from(memberships)
      .where(and(eq(memberships.userId, userId), eq(memberships.orgId, inv.orgId)))
      .limit(1);
    if (already) throw Errors.conflict("You are already a member of this organization");

    await tx.insert(memberships).values({ userId, orgId: inv.orgId, roleId: inv.roleId });
    await tx.update(invitations).set({ acceptedAt: new Date(), acceptedBy: userId }).where(eq(invitations.id, inv.id));
    await audit(
      req,
      {
        action: "invitation.accepted",
        orgId: inv.orgId,
        targetType: "invitation",
        targetId: inv.id,
        metadata: { role: row.roleName },
      },
      tx,
    );
    return { orgId: inv.orgId, orgName: row.orgName, role: row.roleName };
  });

  res.json({ organization: { id: result.orgId, name: result.orgName }, role: result.role });
});
