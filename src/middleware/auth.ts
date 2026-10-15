import type { RequestHandler } from "express";
import { Errors } from "../lib/errors";
import { isSessionRevoked, verifyAccessToken } from "../modules/sessions/sessions.service";

/**
 * Reads `Authorization: Bearer <jwt>`, checks the signature AND that the session has not been
 * revoked, then sets `req.principal`. Anything missing or invalid is a 401 (deny by default).
 */
export const authenticate: RequestHandler = async (req, _res, next) => {
  try {
    const match = req.header("authorization")?.match(/^Bearer\s+(.+)$/i);
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

/** Typed accessor for handlers that sit behind `authenticate`. */
export function userPrincipal(req: Express.Request) {
  if (!req.principal) throw Errors.unauthenticated();
  return req.principal;
}
