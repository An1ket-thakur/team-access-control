import { createHash, randomBytes, timingSafeEqual } from "crypto";

/** SHA-256 hex digest. Used for high-entropy random tokens (refresh, invite, reset, API keys). */
export const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

/** URL-safe random token with the given number of random bytes. */
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

/** Constant-time string comparison. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
