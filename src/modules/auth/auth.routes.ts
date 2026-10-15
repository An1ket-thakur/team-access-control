import { Router } from "express";
import { and, eq, isNull } from "drizzle-orm";
import { config } from "../../config";
import { db } from "../../db";
import { sessions, users } from "../../schema";
import { safeEqual, sha256 } from "../../lib/crypto";
import { Errors } from "../../lib/errors";
import { isUniqueViolation } from "../../lib/pgErrors";
import { burnPasswordCheck, hashPassword, verifyPassword } from "../../lib/password";
import { authenticate, userPrincipal } from "../../middleware/auth";
import { emailKey, rateLimit } from "../../middleware/rateLimit";
import {
  buildRefreshToken,
  createSession,
  parseRefreshToken,
  refreshExpiry,
  revokeSession,
  signAccessToken,
} from "../sessions/sessions.service";
import { loginBody, refreshBody, signupBody } from "./auth.schemas";

export const authRouter = Router();

// Two buckets: one per client IP, one per email address being attacked.
const ipLimiter = rateLimit({
  name: "auth-ip",
  max: config.RATE_LIMIT_AUTH_MAX,
  windowSeconds: config.RATE_LIMIT_AUTH_WINDOW_SECONDS,
});
const emailLimiter = rateLimit({
  name: "auth-email",
  max: config.RATE_LIMIT_AUTH_MAX,
  windowSeconds: config.RATE_LIMIT_AUTH_WINDOW_SECONDS,
  key: emailKey,
});

const publicUser = (u: typeof users.$inferSelect) => ({
  id: u.id,
  email: u.email,
  name: u.name,
  createdAt: u.createdAt,
});

function tokenResponse(t: Awaited<ReturnType<typeof createSession>>) {
  return {
    accessToken: t.accessToken,
    refreshToken: t.refreshToken,
    tokenType: "Bearer" as const,
    expiresIn: t.expiresIn,
  };
}

// POST /auth/signup
authRouter.post("/signup", ipLimiter, async (req, res) => {
  const body = signupBody.parse(req.body);
  const passwordHash = await hashPassword(body.password);

  let user: typeof users.$inferSelect;
  try {
    [user] = await db.insert(users).values({ email: body.email, name: body.name, passwordHash }).returning();
  } catch (err) {
    if (isUniqueViolation(err)) throw Errors.conflict("An account with this email already exists");
    throw err;
  }

  const tokens = await createSession(user.id, { userAgent: req.get("user-agent"), ip: req.ip });
  res.status(201).json({ user: publicUser(user), ...tokenResponse(tokens) });
});

// POST /auth/login
authRouter.post("/login", ipLimiter, emailLimiter, async (req, res) => {
  const body = loginBody.parse(req.body);

  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.email, body.email), isNull(users.deletedAt)))
    .limit(1);

  if (!user) {
    // Same cost as a real check, so response time does not reveal which emails exist.
    await burnPasswordCheck(body.password);
    throw Errors.invalidCredentials();
  }
  if (!(await verifyPassword(user.passwordHash, body.password))) {
    throw Errors.invalidCredentials();
  }

  const tokens = await createSession(user.id, { userAgent: req.get("user-agent"), ip: req.ip });
  res.json({ user: publicUser(user), ...tokenResponse(tokens) });
});

// POST /auth/refresh  (refresh token rotation with reuse detection)
authRouter.post("/refresh", ipLimiter, async (req, res) => {
  const { refreshToken } = refreshBody.parse(req.body);
  const parsed = parseRefreshToken(refreshToken);
  if (!parsed) throw Errors.invalidToken();

  const presentedHash = sha256(refreshToken);
  const [session] = await db.select().from(sessions).where(eq(sessions.id, parsed.sessionId)).limit(1);

  if (!session || session.revokedAt || session.expiresAt < new Date()) throw Errors.invalidToken();

  if (!safeEqual(session.refreshTokenHash, presentedHash)) {
    // An older token from this session was replayed => it was probably stolen. Kill the session.
    if (session.previousRefreshTokenHash && safeEqual(session.previousRefreshTokenHash, presentedHash)) {
      await revokeSession(session.id, "refresh_token_reuse");
    }
    throw Errors.invalidToken();
  }

  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, session.userId), isNull(users.deletedAt)))
    .limit(1);
  if (!user) throw Errors.invalidToken();

  const newRefreshToken = buildRefreshToken(session.id);
  // Compare-and-swap: only one concurrent request can rotate a given token.
  const rotated = await db
    .update(sessions)
    .set({
      refreshTokenHash: sha256(newRefreshToken),
      previousRefreshTokenHash: presentedHash,
      lastUsedAt: new Date(),
      expiresAt: refreshExpiry(),
      ip: req.ip ?? session.ip,
    })
    .where(and(eq(sessions.id, session.id), eq(sessions.refreshTokenHash, presentedHash), isNull(sessions.revokedAt)))
    .returning({ id: sessions.id });
  if (rotated.length === 0) throw Errors.invalidToken();

  res.json({
    accessToken: signAccessToken(user.id, session.id),
    refreshToken: newRefreshToken,
    tokenType: "Bearer",
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
  });
});

// POST /auth/logout  (revokes the session this token belongs to)
authRouter.post("/logout", authenticate, async (req, res) => {
  const { sessionId } = userPrincipal(req);
  await revokeSession(sessionId, "logout");
  res.status(204).end();
});
