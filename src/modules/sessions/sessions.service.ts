import { randomUUID } from "crypto";
import jwt from "jsonwebtoken";
import { and, eq, isNull, ne } from "drizzle-orm";
import { config } from "../../config";
import { db, type DbOrTx } from "../../db";
import { redis } from "../../redis";
import { logger } from "../../logger";
import { sessions } from "../../schema";
import { randomToken, sha256 } from "../../lib/crypto";

const ISSUER = "team-access-api";
const revokedKey = (sid: string) => `sess:revoked:${sid}`;

// ---------- Access tokens (short-lived JWT) ----------

export function signAccessToken(userId: string, sessionId: string): string {
  return jwt.sign({ sid: sessionId }, config.JWT_SECRET, {
    algorithm: "HS256",
    subject: userId,
    issuer: ISSUER,
    audience: ISSUER,
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
  });
}

export function verifyAccessToken(token: string): { userId: string; sessionId: string } | null {
  try {
    const payload = jwt.verify(token, config.JWT_SECRET, {
      algorithms: ["HS256"], // pin the algorithm: never trust the token header
      issuer: ISSUER,
      audience: ISSUER,
    });
    if (typeof payload === "string" || !payload.sub || typeof payload.sid !== "string") return null;
    return { userId: payload.sub, sessionId: payload.sid };
  } catch {
    return null;
  }
}

// ---------- Redis-backed instant invalidation ----------
// Access tokens are stateless, so revoking a session writes a denylist entry that lives as long
// as any access token issued for that session could. The DB row stays the source of truth.

async function markRevoked(sessionIds: string[]) {
  if (sessionIds.length === 0) return;
  try {
    const pipeline = redis.multi();
    for (const sid of sessionIds) {
      pipeline.set(revokedKey(sid), "1", "EX", config.ACCESS_TOKEN_TTL_SECONDS + 30);
    }
    await pipeline.exec();
  } catch (err) {
    logger.error({ err: (err as Error).message }, "could not write session denylist to redis");
  }
}

/** Fast path via Redis; falls back to the DB if Redis is unavailable (fail closed on doubt). */
export async function isSessionRevoked(sessionId: string): Promise<boolean> {
  try {
    return (await redis.exists(revokedKey(sessionId))) === 1;
  } catch {
    const [row] = await db
      .select({ revokedAt: sessions.revokedAt, expiresAt: sessions.expiresAt })
      .from(sessions)
      .where(eq(sessions.id, sessionId))
      .limit(1);
    return !row || row.revokedAt !== null || row.expiresAt < new Date();
  }
}

// ---------- Session lifecycle ----------

export interface SessionMeta {
  userAgent?: string | null;
  ip?: string | null;
}

export const refreshExpiry = () => new Date(Date.now() + config.REFRESH_TOKEN_TTL_DAYS * 86_400_000);

/** Refresh tokens look like `<sessionId>.<secret>`; only a SHA-256 of the whole token is stored. */
export const buildRefreshToken = (sessionId: string) => `${sessionId}.${randomToken(32)}`;

export function parseRefreshToken(token: string): { sessionId: string } | null {
  const [sid, secret, ...rest] = token.split(".");
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!sid || !secret || rest.length > 0 || !uuid.test(sid)) return null;
  return { sessionId: sid };
}

export async function createSession(userId: string, meta: SessionMeta, handle: DbOrTx = db) {
  const id = randomUUID();
  const refreshToken = buildRefreshToken(id);
  await handle.insert(sessions).values({
    id,
    userId,
    refreshTokenHash: sha256(refreshToken),
    userAgent: meta.userAgent?.slice(0, 300) ?? null,
    ip: meta.ip ?? null,
    expiresAt: refreshExpiry(),
  });
  return {
    sessionId: id,
    refreshToken,
    accessToken: signAccessToken(userId, id),
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
  };
}

export async function revokeSession(sessionId: string, reason: string): Promise<boolean> {
  const rows = await db
    .update(sessions)
    .set({ revokedAt: new Date(), revokedReason: reason })
    .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt)))
    .returning({ id: sessions.id });
  await markRevoked(rows.map((r) => r.id));
  return rows.length > 0;
}

export async function revokeAllUserSessions(userId: string, reason: string, exceptSessionId?: string): Promise<number> {
  const conditions = [eq(sessions.userId, userId), isNull(sessions.revokedAt)];
  if (exceptSessionId) conditions.push(ne(sessions.id, exceptSessionId));
  const rows = await db
    .update(sessions)
    .set({ revokedAt: new Date(), revokedReason: reason })
    .where(and(...conditions))
    .returning({ id: sessions.id });
  await markRevoked(rows.map((r) => r.id));
  return rows.length;
}
