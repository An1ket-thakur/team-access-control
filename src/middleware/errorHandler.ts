import type { ErrorRequestHandler, RequestHandler } from "express";
import { ZodError } from "zod";
import { AppError } from "../lib/errors";
import { logger } from "../logger";

function send(
  res: Parameters<ErrorRequestHandler>[2],
  requestId: string | undefined,
  status: number,
  code: string,
  message: string,
  details?: unknown,
) {
  res.status(status).json({ error: { code, message, ...(details !== undefined && { details }), requestId } });
}

export const notFoundHandler: RequestHandler = (req, res) => {
  send(res, req.requestId, 404, "NOT_FOUND", "Route not found");
};

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  if (res.headersSent) return;

  if (err instanceof ZodError) {
    const details = err.issues.map((i) => ({ path: i.path.join("."), message: i.message }));
    return send(res, req.requestId, 400, "VALIDATION_ERROR", "Request validation failed", details);
  }

  if (err instanceof AppError) {
    if (err.code === "RATE_LIMITED") {
      const retry = (err.details as { retryAfterSeconds?: number } | undefined)?.retryAfterSeconds;
      if (retry) res.setHeader("Retry-After", String(retry));
    }
    return send(res, req.requestId, err.status, err.code, err.message, err.details);
  }

  // body-parser errors
  const type = (err as { type?: string }).type;
  if (type === "entity.parse.failed") {
    return send(res, req.requestId, 400, "VALIDATION_ERROR", "Malformed JSON body");
  }
  if (type === "entity.too.large") {
    return send(res, req.requestId, 413, "VALIDATION_ERROR", "Request body too large");
  }

  // Unknown error: log everything server-side, reveal nothing to the client.
  logger.error({ err, requestId: req.requestId, path: req.path }, "unhandled error");
  return send(res, req.requestId, 500, "INTERNAL_ERROR", "Something went wrong");
};
