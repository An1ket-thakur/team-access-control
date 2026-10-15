export type Principal = { type: 'user'; userId: string; sessionId: string };

declare global {
  namespace Express {
    interface Request {
      requestId: string;
      principal?: Principal;
    }
  }
}
