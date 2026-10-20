import { Router } from "express";
import { and, count, desc, eq, gte, inArray, isNull, like, lte, or } from "drizzle-orm";
import { z } from "zod";
import { db } from "../../db";
import { auditLogs, memberships, users } from "../../schema";
import { likeEscape, offsetOf, pageMeta, paginationQuery } from "../../lib/pagination";
import { requirePermission } from "../../middleware/permissions";

export const auditRouter = Router({ mergeParams: true });

const bool = z.enum(["true", "false"]).transform((v) => v === "true");

const listQuery = paginationQuery.extend({
  action: z.string().trim().max(60).optional(),
  actionPrefix: z.string().trim().max(60).optional(),
  actorUserId: z.string().uuid().optional(),
  targetType: z.string().trim().max(40).optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  // Also show sign-in / sign-out activity of this organization's members (auth.* events have no org).
  includeAuthEvents: bool.default(true),
  order: z.enum(["asc", "desc"]).default("desc"),
});

// GET /orgs/:orgId/audit-logs
auditRouter.get("/", requirePermission("audit.read"), async (req, res) => {
  const orgId = req.org!.orgId;
  const q = listQuery.parse(req.query);

  const memberIds = db.select({ id: memberships.userId }).from(memberships).where(eq(memberships.orgId, orgId));
  const scope = q.includeAuthEvents
    ? or(
        eq(auditLogs.orgId, orgId),
        and(isNull(auditLogs.orgId), like(auditLogs.action, "auth.%"), inArray(auditLogs.actorUserId, memberIds)),
      )
    : eq(auditLogs.orgId, orgId);

  const where = and(
    scope,
    q.action ? eq(auditLogs.action, q.action) : undefined,
    q.actionPrefix ? like(auditLogs.action, `${likeEscape(q.actionPrefix)}%`) : undefined,
    q.actorUserId ? eq(auditLogs.actorUserId, q.actorUserId) : undefined,
    q.targetType ? eq(auditLogs.targetType, q.targetType) : undefined,
    q.from ? gte(auditLogs.createdAt, q.from) : undefined,
    q.to ? lte(auditLogs.createdAt, q.to) : undefined,
  );

  const [{ total }] = await db.select({ total: count() }).from(auditLogs).where(where);
  const rows = await db
    .select({
      id: auditLogs.id,
      action: auditLogs.action,
      targetType: auditLogs.targetType,
      targetId: auditLogs.targetId,
      metadata: auditLogs.metadata,
      requestId: auditLogs.requestId,
      ip: auditLogs.ip,
      createdAt: auditLogs.createdAt,
      actorUserId: auditLogs.actorUserId,
      actorApiKeyId: auditLogs.actorApiKeyId,
      actorEmail: users.email,
      actorName: users.name,
    })
    .from(auditLogs)
    .leftJoin(users, eq(users.id, auditLogs.actorUserId))
    .where(where)
    .orderBy(
      q.order === "asc" ? auditLogs.createdAt : desc(auditLogs.createdAt),
      q.order === "asc" ? auditLogs.id : desc(auditLogs.id),
    )
    .limit(q.limit)
    .offset(offsetOf(q));

  res.json({
    data: rows.map(({ actorEmail, actorName, ...r }) => ({
      ...r,
      actor: r.actorUserId
        ? { type: "user", id: r.actorUserId, email: actorEmail, name: actorName }
        : r.actorApiKeyId
          ? { type: "apikey", id: r.actorApiKeyId }
          : null,
    })),
    meta: pageMeta(q, total),
  });
});
