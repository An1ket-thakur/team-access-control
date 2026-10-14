import jwt from "jsonwebtoken";
import { config } from "../../config";

const ISSUER = "team-access-api";

// ---------- Access tokens (short-lived JWT) ----------

export function signAccessToken(userId: string): string {
  return jwt.sign({}, config.JWT_SECRET, {
    algorithm: "HS256",
    subject: userId,
    issuer: ISSUER,
    audience: ISSUER,
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
  });
}

export function verifyAccessToken(token: string): { userId: string } | null {
  try {
    const payload = jwt.verify(token, config.JWT_SECRET, {
      algorithms: ["HS256"], // pin the algorithm: never trust the token header
      issuer: ISSUER,
      audience: ISSUER,
    });
    if (typeof payload === "string" || !payload.sub) return null;
    return { userId: payload.sub };
  } catch {
    return null;
  }
}
