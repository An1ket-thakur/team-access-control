import { config as loadEnv } from "dotenv";
loadEnv({ quiet: true });
import { z } from "zod";

const bool = z.enum(["true", "false", "1", "0"]).transform((v) => v === "true" || v === "1");

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  TRUST_PROXY: bool.default(false),
  LOG_LEVEL: z.string().default("info"),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(7),
  INVITE_TTL_HOURS: z.coerce.number().int().positive().default(72),
  PASSWORD_RESET_TTL_MINUTES: z.coerce.number().int().positive().default(30),
  RATE_LIMIT_AUTH_MAX: z.coerce.number().int().positive().default(10),
  RATE_LIMIT_AUTH_WINDOW_SECONDS: z.coerce.number().int().positive().default(60),
  RATE_LIMIT_GLOBAL_MAX: z.coerce.number().int().positive().default(300),
  RATE_LIMIT_GLOBAL_WINDOW_SECONDS: z.coerce.number().int().positive().default(60),
  EXPOSE_DEV_TOKENS: bool.default(false),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // Fail fast with a readable message; never print secret values.
  const problems = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("\n  ");
  throw new Error(`Invalid environment configuration:\n  ${problems}`);
}

if (parsed.data.NODE_ENV === "production" && parsed.data.EXPOSE_DEV_TOKENS) {
  throw new Error("EXPOSE_DEV_TOKENS must be false in production");
}

export const config = parsed.data;
