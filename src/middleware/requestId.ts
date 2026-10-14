import { randomUUID } from "crypto";
import type { RequestHandler } from "express";

const SAFE_ID = /^[A-Za-z0-9._-]{8,64}$/;

/** Accepts a well-formed upstream X-Request-Id or generates one; echoes it on the response. */
export const requestId: RequestHandler = (req, res, next) => {
  const incoming = req.header("x-request-id");
  req.requestId = incoming && SAFE_ID.test(incoming) ? incoming : randomUUID();
  res.setHeader("X-Request-Id", req.requestId);
  next();
};
