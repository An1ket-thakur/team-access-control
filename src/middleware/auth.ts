import type { RequestHandler } from "express";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "../db";
import { apiKeys, organizations } from "../schema";
import { Errors } from "../lib/errors";
import { sha256, safeEqual } from "../lib/crypto";
import { isSessionRevoked, verifyAccessToken } from "../modules/sessions/sessions.service";

// API key format: tak_<8 char prefix>_<secret>. The prefix is a lookup handle; only a hash of the
// full key is stored, so a database leak does not reveal usable keys.
export const API_KEY_PATTERN = /^tak_([A-Za-z0-9]{8})_[A-Za-z0-9_-]{32,}$/;

/**
 * Authenticates the request from either `Authorization: Bearer <jwt>` or `X-API-Key: <key>` and
 * sets `req.principal`. Anything missing or invalid is a 401 (deny by default).
 */
export const authenticate: RequestHandler = async (req, _res, next) => {
  try {
    const apiKey = req.header("x-api-key");
    if (apiKey) {
      req.principal = await authenticateApiKey(apiKey);
      return next();
    }

    const header = req.header("authorization");
    const match = header?.match(/^Bearer\s+(.+)$/i);
    if (!match) throw Errors.unauthenticated();

    const claims = verifyAccessToken(match[1]);
    if (!claims) throw Errors.invalidToken();
    if (await isSessionRevoked(claims.sessionId)) throw Errors.invalidToken("Session has been revoked");

    req.principal = { type: "user", userId: claims.userId, sessionId: claims.sessionId };
    next();
  } catch (err) {
    next(err);
  }
};

async function authenticateApiKey(raw: string) {
  const m = raw.match(API_KEY_PATTERN);
  if (!m) throw Errors.invalidToken("Invalid API key");

  const [row] = await db
    .select({
      key: apiKeys,
      orgDeleted: organizations.deletedAt,
    })
    .from(apiKeys)
    .innerJoin(organizations, eq(organizations.id, apiKeys.orgId))
    .where(and(eq(apiKeys.keyPrefix, m[1]), isNull(apiKeys.revokedAt)))
    .limit(1);

  if (
    !row ||
    row.orgDeleted ||
    !safeEqual(row.key.keyHash, sha256(raw)) ||
    (row.key.expiresAt && row.key.expiresAt < new Date())
  ) {
    throw Errors.invalidToken("Invalid API key");
  }

  // Throttle last_used_at writes to once a minute.
  const last = row.key.lastUsedAt?.getTime() ?? 0;
  if (Date.now() - last > 60_000) {
    await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, row.key.id));
  }

  return {
    type: "apikey" as const,
    apiKeyId: row.key.id,
    orgId: row.key.orgId,
    permissions: row.key.permissions,
  };
}

/** Routes that only make sense for a human session (sessions, profile, accepting invites...). */
export const requireUser: RequestHandler = (req, _res, next) => {
  if (req.principal?.type !== "user") return next(Errors.forbidden("This endpoint requires a user session"));
  next();
};

/** Typed accessor for handlers behind `authenticate` + `requireUser`. */
export function userPrincipal(req: Express.Request) {
  if (req.principal?.type !== "user") throw Errors.forbidden("This endpoint requires a user session");
  return req.principal;
}
