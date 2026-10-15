import { Router } from "express";
import { and, asc, count, desc, eq, ilike, isNull, or, sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../../db";
import { memberships, roles, users } from "../../schema";
import { Errors } from "../../lib/errors";
import { likeEscape, offsetOf, pageMeta, paginationQuery } from "../../lib/pagination";
import { ROLE_NAMES } from "../../lib/permissions";
import { userPrincipal } from "../../middleware/auth";
import { requirePermission } from "../../middleware/permissions";
import { canAssignRank, findOrgRole } from "../orgs/orgs.service";

/** Mounted at /orgs/:orgId/members. */
export const membersRouter = Router({ mergeParams: true });

const roleEnum = z.enum(ROLE_NAMES as [string, ...string[]]);

const listQuery = paginationQuery.extend({
  search: z.string().trim().max(100).optional(),
  role: roleEnum.optional(),
  sort: z.enum(["joinedAt", "name", "email"]).default("joinedAt"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

// GET /orgs/:orgId/members?search=&role=&sort=&order=&page=&limit=
membersRouter.get("/", requirePermission("users.read"), async (req, res) => {
  const orgId = req.org!.orgId;
  const q = listQuery.parse(req.query);
  const pattern = q.search ? `%${likeEscape(q.search)}%` : undefined;

  const where = and(
    eq(memberships.orgId, orgId),
    isNull(users.deletedAt),
    q.role ? eq(roles.name, q.role) : undefined,
    pattern ? or(ilike(users.name, pattern), ilike(users.email, pattern)) : undefined,
  );

  const sortColumn = { joinedAt: memberships.createdAt, name: users.name, email: users.email }[q.sort];
  const direction = q.order === "asc" ? asc : desc;

  const [{ total }] = await db
    .select({ total: count() })
    .from(memberships)
    .innerJoin(users, eq(users.id, memberships.userId))
    .innerJoin(roles, eq(roles.id, memberships.roleId))
    .where(where);

  const data = await db
    .select({
      userId: users.id,
      name: users.name,
      email: users.email,
      role: roles.name,
      joinedAt: memberships.createdAt,
    })
    .from(memberships)
    .innerJoin(users, eq(users.id, memberships.userId))
    .innerJoin(roles, eq(roles.id, memberships.roleId))
    .where(where)
    .orderBy(direction(sortColumn), asc(users.id))
    .limit(q.limit)
    .offset(offsetOf(q));

  res.json({ data, meta: pageMeta(q, total) });
});

async function activeOwnerCount(orgId: string): Promise<number> {
  const result = await db.execute(sql`
    SELECT count(*)::int AS n FROM memberships m
    JOIN roles r ON r.id = m.role_id AND r.name = 'owner'
    JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
    WHERE m.org_id = ${orgId}
  `);
  return (result.rows[0] as { n: number }).n;
}

async function loadTarget(orgId: string, userId: string) {
  const [target] = await db
    .select({ membershipId: memberships.id, roleName: roles.name, rank: roles.rank })
    .from(memberships)
    .innerJoin(roles, eq(roles.id, memberships.roleId))
    .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, userId)))
    .limit(1);
  return target;
}

// DELETE /orgs/:orgId/members/me   (leave the organization)
// Defined before '/:userId' so "me" is never treated as a user id.
membersRouter.delete("/me", async (req, res) => {
  const { userId } = userPrincipal(req);
  const orgId = req.org!.orgId;
  const me = await loadTarget(orgId, userId);
  if (!me) throw Errors.notFound("Membership");
  if (me.roleName === "owner" && (await activeOwnerCount(orgId)) <= 1) {
    throw Errors.conflict("You are the last owner. Promote another owner or delete the organization.");
  }
  await db.delete(memberships).where(eq(memberships.id, me.membershipId));
  res.status(204).end();
});

// PATCH /orgs/:orgId/members/:userId   { role }
membersRouter.patch("/:userId", requirePermission("users.manage"), async (req, res) => {
  const actor = userPrincipal(req);
  const orgId = req.org!.orgId;
  const actorRole = req.org!.role;
  const targetUserId = z.string().uuid().safeParse(req.params.userId);
  if (!targetUserId.success) throw Errors.notFound("Member");
  const { role: newRoleName } = z.object({ role: roleEnum }).parse(req.body);

  if (targetUserId.data === actor.userId) {
    throw Errors.forbidden("You cannot change your own role");
  }

  const target = await loadTarget(orgId, targetUserId.data);
  if (!target) throw Errors.notFound("Member");
  const newRole = await findOrgRole(orgId, newRoleName);
  if (!newRole) throw Errors.notFound("Role");

  // Escalation rules: you must outrank (or be an owner over) both the current and the new role.
  if (!canAssignRank(actorRole, target.rank) || !canAssignRank(actorRole, newRole.rank)) {
    throw Errors.forbidden("You cannot assign or modify a role at or above your own");
  }
  if (target.roleName === newRoleName) {
    return res.json({ userId: targetUserId.data, role: newRoleName });
  }

  await db.update(memberships).set({ roleId: newRole.id }).where(eq(memberships.id, target.membershipId));
  res.json({ userId: targetUserId.data, role: newRoleName });
});

// DELETE /orgs/:orgId/members/:userId
membersRouter.delete("/:userId", requirePermission("users.manage"), async (req, res) => {
  const actor = userPrincipal(req);
  const orgId = req.org!.orgId;
  const targetUserId = z.string().uuid().safeParse(req.params.userId);
  if (!targetUserId.success) throw Errors.notFound("Member");
  if (targetUserId.data === actor.userId) {
    throw Errors.forbidden("Use DELETE /members/me to leave the organization");
  }

  const target = await loadTarget(orgId, targetUserId.data);
  if (!target) throw Errors.notFound("Member");
  if (!canAssignRank(req.org!.role, target.rank)) {
    throw Errors.forbidden("You cannot remove a member at or above your own role");
  }

  await db.delete(memberships).where(eq(memberships.id, target.membershipId));
  res.status(204).end();
});
