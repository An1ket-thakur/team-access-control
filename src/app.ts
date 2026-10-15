import express from "express";
import helmet from "helmet";
import { sql } from "drizzle-orm";
import { config } from "./config";
import { db, pool } from "./db";
import { redis } from "./redis";
import { requestId } from "./middleware/requestId";
import { sessionsRouter } from "./modules/sessions/sessions.routes";
import { rateLimit } from "./middleware/rateLimit";
import { errorHandler, notFoundHandler } from "./middleware/errorHandler";
import { authRouter } from "./modules/auth/auth.routes";
import { usersRouter } from "./modules/users/users.routes";
import { orgsRouter } from "./modules/orgs/orgs.routes";

export function createApp() {
  const app = express();
  app.disable("x-powered-by");
  if (config.TRUST_PROXY) app.set("trust proxy", 1);

  app.use(requestId);
  app.use(helmet());
  app.use(express.json({ limit: "100kb" }));

  // Health check: no auth, no rate limit
  app.get("/health", async (_req, res) => {
    const checks: Record<string, string> = { database: "ok", redis: "ok" };
    try {
      await db.execute(sql`SELECT 1`);
    } catch {
      checks.database = "down";
    }
    try {
      await redis.ping();
    } catch {
      checks.redis = "down";
    }
    const healthy = Object.values(checks).every((v) => v === "ok");
    res.status(healthy ? 200 : 503).json({ status: healthy ? "ok" : "degraded", checks });
  });

  app.use(
    rateLimit({
      name: "global",
      max: config.RATE_LIMIT_GLOBAL_MAX,
      windowSeconds: config.RATE_LIMIT_GLOBAL_WINDOW_SECONDS,
    }),
  );

  app.use("/auth", authRouter);
  app.use("/me/sessions", sessionsRouter);
  app.use("/me", usersRouter);
  app.use("/orgs", orgsRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

export async function shutdown() {
  await Promise.allSettled([pool.end(), redis.quit()]);
}
