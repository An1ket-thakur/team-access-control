import { Router } from "express";
import { and, count, desc, eq, isNull, sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../../db";
import { auditLogs, memberships, organizations, roles, users } from "../../schema";
import { Errors } from "../../lib/errors";
import { verifyPassword } from "../../lib/password";
import { authenticate, userPrincipal } from "../../middleware/auth";
import { revokeAllUserSessions } from "../sessions/sessions.service";
import { audit } from "../../lib/audit";
import { offsetOf, pageMeta, paginationQuery } from "../../lib/pagination";

/** Mounted at /me. */
const usersRouter = Router();
usersRouter.use(authenticate);

// GET /me  (profile + the organizations I belong to)
usersRouter.get("/", async (req, res) => {
  const { userId } = userPrincipal(req);
  const [user] = await db
    .select({ id: users.id, email: users.email, name: users.name, createdAt: users.createdAt })
    .from(users)
    .where(and(eq(users.id, userId), isNull(users.deletedAt)))
    .limit(1);
  if (!user) throw Errors.unauthenticated();

  const orgs = await db
    .select({ id: organizations.id, name: organizations.name, slug: organizations.slug, role: roles.name })
    .from(memberships)
    .innerJoin(organizations, eq(organizations.id, memberships.orgId))
    .innerJoin(roles, eq(roles.id, memberships.roleId))
    .where(and(eq(memberships.userId, userId), isNull(organizations.deletedAt)));

  res.json({ user, organizations: orgs });
});

// DELETE /me   (soft delete; requires the password)
usersRouter.delete("/", async (req, res) => {
  const { userId } = userPrincipal(req);
  const { password } = z.object({ password: z.string().min(1).max(128) }).parse(req.body);

  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, userId), isNull(users.deletedAt)))
    .limit(1);
  if (!user) throw Errors.unauthenticated();
  if (!(await verifyPassword(user.passwordHash, password))) throw Errors.invalidCredentials();

  // Never orphan an organization: refuse while this user is the only owner of a live org.
  const blocking = await db.execute(sql`
    SELECT o.id, o.name
    FROM memberships m
    JOIN roles r ON r.id = m.role_id AND r.name = 'owner'
    JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
    WHERE m.user_id = ${userId}
      AND (
        SELECT count(*) FROM memberships m2
        JOIN roles r2 ON r2.id = m2.role_id AND r2.name = 'owner'
        JOIN users u2 ON u2.id = m2.user_id AND u2.deleted_at IS NULL
        WHERE m2.org_id = m.org_id
      ) = 1
  `);
  if (blocking.rows.length > 0) {
    throw Errors.conflict(
      "You are the only owner of an organization. Promote another owner or delete the organization first.",
    );
  }

  // Soft delete: the row stays (for history), but the account can no longer sign in.
  await db.transaction(async (tx) => {
    await tx.update(users).set({ deletedAt: new Date(), updatedAt: new Date() }).where(eq(users.id, userId));
    await audit(req, { action: "user.deleted", targetType: "user", targetId: userId }, tx);
  });
  await revokeAllUserSessions(userId, "account_deleted");
  res.status(204).end();
});

// GET /me/audit-logs
usersRouter.get("/audit-logs", async (req, res) => {
  const { userId } = userPrincipal(req);
  const q = paginationQuery.extend({ action: z.string().max(60).optional() }).parse(req.query);
  const where = and(eq(auditLogs.actorUserId, userId), q.action ? eq(auditLogs.action, q.action) : undefined);

  const [{ total }] = await db.select({ total: count() }).from(auditLogs).where(where);
  const data = await db
    .select()
    .from(auditLogs)
    .where(where)
    .orderBy(desc(auditLogs.createdAt), desc(auditLogs.id))
    .limit(q.limit)
    .offset(offsetOf(q));

  res.json({ data, meta: pageMeta(q, total) });
});

export { usersRouter };
