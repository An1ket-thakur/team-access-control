import type { RequestHandler } from "express";
import { Errors } from "../lib/errors";
import { verifyAccessToken } from "../modules/sessions/sessions.service";

/**
 * Reads `Authorization: Bearer <jwt>` and sets `req.principal`.
 * Anything missing or invalid is a 401 (deny by default).
 */
export const authenticate: RequestHandler = (req, _res, next) => {
  const match = req.header("authorization")?.match(/^Bearer\s+(.+)$/i);
  if (!match) return next(Errors.unauthenticated());

  const claims = verifyAccessToken(match[1]);
  if (!claims) return next(Errors.invalidToken());

  req.principal = { type: "user", userId: claims.userId };
  next();
};
