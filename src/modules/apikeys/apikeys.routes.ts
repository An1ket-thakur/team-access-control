import { randomInt } from "crypto";
import { Router } from "express";
import { and, count, desc, eq, isNotNull, isNull } from "drizzle-orm";
import { z } from "zod";
import { db } from "../../db";
import { apiKeys } from "../../schema";
import { randomToken, sha256 } from "../../lib/crypto";
import { Errors } from "../../lib/errors";
import { isUniqueViolation } from "../../lib/pgErrors";
import { offsetOf, pageMeta, paginationQuery } from "../../lib/pagination";
import { ALL_PERMISSION_KEYS } from "../../lib/permissions";
import { requireUser, userPrincipal } from "../../middleware/auth";
import { requirePermission } from "../../middleware/permissions";
import { audit } from "../../lib/audit";

export const apiKeysRouter = Router({ mergeParams: true });

// Keys can only be managed by people, never by other keys.
apiKeysRouter.use(requireUser, requirePermission("apikeys.manage"));

const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const randomPrefix = () => Array.from({ length: 8 }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");

const createBody = z.object({
  name: z.string().trim().min(1).max(80),
  permissions: z.array(z.enum(ALL_PERMISSION_KEYS as [string, ...string[]])).min(1),
  expiresInDays: z.number().int().min(1).max(365).optional(),
});

const publicKey = (k: typeof apiKeys.$inferSelect) => ({
  id: k.id,
  name: k.name,
  prefix: `tak_${k.keyPrefix}`,
  permissions: k.permissions,
  createdBy: k.createdBy,
  createdAt: k.createdAt,
  lastUsedAt: k.lastUsedAt,
  expiresAt: k.expiresAt,
  revokedAt: k.revokedAt,
});

// POST /orgs/:orgId/api-keys   -> the full key is returned once and never stored
apiKeysRouter.post("/", async (req, res) => {
  const { userId } = userPrincipal(req);
  const orgId = req.org!.orgId;
  const body = createBody.parse(req.body);

  // A key can never be more powerful than the person creating it.
  const notHeld = body.permissions.filter((p) => !req.org!.permissions.has(p));
  if (notHeld.length > 0) {
    throw Errors.forbidden("You cannot create a key with permissions you do not have", { permissions: notHeld });
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    const prefix = randomPrefix();
    const key = `tak_${prefix}_${randomToken(32)}`;
    try {
      const created = await db.transaction(async (tx) => {
        const [row] = await tx
          .insert(apiKeys)
          .values({
            orgId,
            name: body.name,
            keyPrefix: prefix,
            keyHash: sha256(key),
            permissions: [...new Set(body.permissions)].sort(),
            createdBy: userId,
            expiresAt: body.expiresInDays ? new Date(Date.now() + body.expiresInDays * 86_400_000) : null,
          })
          .returning();
        await audit(
          req,
          {
            action: "apikey.created",
            orgId,
            targetType: "api_key",
            targetId: row.id,
            metadata: { name: row.name, permissions: row.permissions },
          },
          tx,
        );
        return row;
      });
      return res.status(201).json({ apiKey: publicKey(created), key });
    } catch (err) {
      if (!isUniqueViolation(err)) throw err; // prefix collision: retry with a new one
    }
  }
  throw new Error("could not allocate a unique API key prefix");
});

const listQuery = paginationQuery.extend({
  status: z.enum(["active", "revoked", "all"]).default("active"),
});

// GET /orgs/:orgId/api-keys
apiKeysRouter.get("/", async (req, res) => {
  const orgId = req.org!.orgId;
  const q = listQuery.parse(req.query);
  const where = and(
    eq(apiKeys.orgId, orgId),
    q.status === "active"
      ? isNull(apiKeys.revokedAt)
      : q.status === "revoked"
        ? isNotNull(apiKeys.revokedAt)
        : undefined,
  );
  const [{ total }] = await db.select({ total: count() }).from(apiKeys).where(where);
  const rows = await db
    .select()
    .from(apiKeys)
    .where(where)
    .orderBy(desc(apiKeys.createdAt))
    .limit(q.limit)
    .offset(offsetOf(q));
  res.json({ data: rows.map(publicKey), meta: pageMeta(q, total) });
});

// DELETE /orgs/:orgId/api-keys/:keyId   (revoke)
apiKeysRouter.delete("/:keyId", async (req, res) => {
  const orgId = req.org!.orgId;
  const id = z.string().uuid().safeParse(req.params.keyId);
  if (!id.success) throw Errors.notFound("API key");

  const revoked = await db.transaction(async (tx) => {
    const rows = await tx
      .update(apiKeys)
      .set({ revokedAt: new Date() })
      .where(and(eq(apiKeys.id, id.data), eq(apiKeys.orgId, orgId), isNull(apiKeys.revokedAt)))
      .returning({ id: apiKeys.id, name: apiKeys.name });
    if (rows.length > 0) {
      await audit(
        req,
        { action: "apikey.revoked", orgId, targetType: "api_key", targetId: id.data, metadata: { name: rows[0].name } },
        tx,
      );
    }
    return rows.length > 0;
  });
  if (!revoked) throw Errors.notFound("API key");
  res.status(204).end();
});
