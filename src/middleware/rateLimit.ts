import type { Request, RequestHandler } from "express";
import { redis } from "../redis";
import { sha256 } from "../lib/crypto";
import { Errors } from "../lib/errors";
import { logger } from "../logger";

interface Options {
  /** Namespace for the Redis key, e.g. "login-ip". */
  name: string;
  max: number;
  windowSeconds: number;
  /** Custom bucket key. Return null to skip limiting for this request. Defaults to client IP. */
  key?: (req: Request) => string | null;
}

/**
 * Fixed-window rate limiter backed by Redis (INCR + EXPIRE, atomic via MULTI).
 * If Redis is unreachable the limiter fails open and logs, so a cache outage does not take
 * the API down. Brute-force protection for passwords additionally relies on Argon2 cost.
 */
export function rateLimit(opts: Options): RequestHandler {
  return async (req, res, next) => {
    const id = opts.key ? opts.key(req) : (req.ip ?? "unknown");
    if (id === null) return next();

    const key = `rl:${opts.name}:${id}`;
    try {
      const results = await redis.multi().incr(key).ttl(key).exec();
      const count = Number(results?.[0]?.[1] ?? 0);
      let ttl = Number(results?.[1]?.[1] ?? -1);
      if (count === 1 || ttl < 0) {
        await redis.expire(key, opts.windowSeconds);
        ttl = opts.windowSeconds;
      }

      res.setHeader("RateLimit-Limit", String(opts.max));
      res.setHeader("RateLimit-Remaining", String(Math.max(0, opts.max - count)));
      res.setHeader("RateLimit-Reset", String(ttl));

      if (count > opts.max) return next(Errors.rateLimited(ttl));
    } catch (err) {
      logger.warn({ err: (err as Error).message, limiter: opts.name }, "rate limiter unavailable, failing open");
    }
    next();
  };
}

/** Bucket by the (hashed, lower-cased) email in the request body. */
export const emailKey = (req: Request): string | null => {
  const email = (req.body as { email?: unknown } | undefined)?.email;
  if (typeof email !== "string" || !email) return null;
  return sha256(email.trim().toLowerCase());
};
