import Redis from "ioredis";
import { config } from "./config";
import { logger } from "./logger";

export const redis = new Redis(config.REDIS_URL, {
  maxRetriesPerRequest: 2,
  enableOfflineQueue: false,
  lazyConnect: false,
});

redis.on("error", (err) => {
  logger.warn({ err: err.message }, "redis error");
});
