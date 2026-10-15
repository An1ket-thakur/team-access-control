export type Principal = { type: "user"; userId: string; sessionId: string };

// The caller's standing inside the organization named by :orgId. A later step adds permissions.
export interface OrgContext {
  orgId: string;
  role: { id: string; name: string; rank: number };
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
