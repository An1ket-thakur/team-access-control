export type Principal =
  | { type: "user"; userId: string; sessionId: string }
  | { type: "apikey"; apiKeyId: string; orgId: string; permissions: string[] };

export interface OrgContext {
  orgId: string;
  /** null when the caller is an API key (keys carry permissions directly, not a role). */
  role: { id: string; name: string; rank: number } | null;
  permissions: Set<string>;
}

declare global {
  namespace Express {
    interface Request {
      requestId: string;
      principal?: Principal;
      org?: OrgContext;
    }
  }
}
