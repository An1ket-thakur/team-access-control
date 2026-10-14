import { Router } from "express";
import { and, eq, isNull } from "drizzle-orm";
import { config } from "../../config";
import { db } from "../../db";
import { users } from "../../schema";
import { Errors } from "../../lib/errors";
import { isUniqueViolation } from "../../lib/pgErrors";
import { burnPasswordCheck, hashPassword, verifyPassword } from "../../lib/password";
import { emailKey, rateLimit } from "../../middleware/rateLimit";
import { signAccessToken } from "../sessions/sessions.service";
import { loginBody, signupBody } from "./auth.schemas";

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

const tokenResponse = (userId: string) => ({
  accessToken: signAccessToken(userId),
  tokenType: "Bearer" as const,
  expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
});

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

  res.status(201).json({ user: publicUser(user), ...tokenResponse(user.id) });
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

  res.json({ user: publicUser(user), ...tokenResponse(user.id) });
});
