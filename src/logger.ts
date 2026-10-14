import pino from "pino";
import { config } from "./config";

export const logger = pino({
  level: config.NODE_ENV === "test" ? "silent" : config.LOG_LEVEL,
  redact: {
    paths: [
      "req.headers.authorization",
      'req.headers["x-api-key"]',
      "req.headers.cookie",
      "*.password",
      "*.refreshToken",
      "*.token",
    ],
    censor: "[redacted]",
  },
});
