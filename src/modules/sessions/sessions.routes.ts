import { Router } from "express";
import { and, desc, eq, gt, isNull } from "drizzle-orm";
import { z } from "zod";
import { db } from "../../db";
import { sessions } from "../../schema";
import { Errors } from "../../lib/errors";
import { authenticate, userPrincipal } from "../../middleware/auth";
import { revokeAllUserSessions, revokeSession } from "./sessions.service";

/** Mounted at /me/sessions. Everything here acts only on the caller's own sessions. */
export const sessionsRouter = Router();
sessionsRouter.use(authenticate);

// GET /me/sessions
sessionsRouter.get("/", async (req, res) => {
  const { userId, sessionId } = userPrincipal(req);
  const rows = await db
    .select({
      id: sessions.id,
      userAgent: sessions.userAgent,
      ip: sessions.ip,
      createdAt: sessions.createdAt,
      lastUsedAt: sessions.lastUsedAt,
      expiresAt: sessions.expiresAt,
    })
    .from(sessions)
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt), gt(sessions.expiresAt, new Date())))
    .orderBy(desc(sessions.lastUsedAt));

  res.json({ data: rows.map((s) => ({ ...s, current: s.id === sessionId })) });
});

// POST /me/sessions/revoke-others   ("sign out everywhere else")
sessionsRouter.post("/revoke-others", async (req, res) => {
  const { userId, sessionId } = userPrincipal(req);
  const revoked = await revokeAllUserSessions(userId, "revoked_by_user", sessionId);
  res.json({ revoked });
});

// DELETE /me/sessions/:sessionId   (ownership check: you can only touch your own sessions)
sessionsRouter.delete("/:sessionId", async (req, res) => {
  const { userId } = userPrincipal(req);
  const id = z.string().uuid().safeParse(req.params.sessionId);
  if (!id.success) throw Errors.notFound("Session");

  const [owned] = await db
    .select({ id: sessions.id })
    .from(sessions)
    .where(and(eq(sessions.id, id.data), eq(sessions.userId, userId), isNull(sessions.revokedAt)))
    .limit(1);
  // Someone else's session and a nonexistent one look identical.
  if (!owned) throw Errors.notFound("Session");

  await revokeSession(owned.id, "revoked_by_user");
  res.status(204).end();
});
