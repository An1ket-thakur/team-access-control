export type ErrorCode =
  | "VALIDATION_ERROR"
  | "UNAUTHENTICATED"
  | "INVALID_CREDENTIALS"
  | "INVALID_TOKEN"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "CONFLICT"
  | "RATE_LIMITED"
  | "INVITATION_INVALID"
  | "INTERNAL_ERROR";

/** Errors that are safe to show to API clients. Anything else becomes a generic 500. */
export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: ErrorCode,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export const Errors = {
  validation: (details?: unknown, message = "Request validation failed") =>
    new AppError(400, "VALIDATION_ERROR", message, details),
  unauthenticated: (message = "Authentication required") => new AppError(401, "UNAUTHENTICATED", message),
  invalidCredentials: () => new AppError(401, "INVALID_CREDENTIALS", "Invalid email or password"),
  invalidToken: (message = "Invalid or expired token") => new AppError(401, "INVALID_TOKEN", message),
  forbidden: (message = "You do not have permission to perform this action", details?: unknown) =>
    new AppError(403, "FORBIDDEN", message, details),
  notFound: (what = "Resource") => new AppError(404, "NOT_FOUND", `${what} not found`),
  conflict: (message: string) => new AppError(409, "CONFLICT", message),
  rateLimited: (retryAfterSeconds: number) =>
    new AppError(429, "RATE_LIMITED", "Too many requests, please try again later", {
      retryAfterSeconds,
    }),
  invitationInvalid: () =>
    new AppError(400, "INVITATION_INVALID", "This invitation is invalid, expired or already used"),
};
