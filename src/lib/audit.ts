import type { Request } from "express";
import { db, type DbOrTx } from "../db";
import { auditLogs } from "../schema";

export type AuditAction =
  | "auth.signup"
  | "auth.login"
  | "auth.login_failed"
  | "auth.logout"
  | "auth.password_reset_requested"
  | "auth.password_reset"
  | "user.deleted"
  | "session.revoked"
  | "session.reuse_detected"
  | "org.created"
  | "org.deleted"
  | "invitation.created"
  | "invitation.accepted"
  | "invitation.revoked"
  | "member.role_changed"
  | "member.removed"
  | "member.left"
  | "permission.granted"
  | "permission.revoked"
  | "apikey.created"
  | "apikey.revoked"
  | "project.created"
  | "project.updated"
  | "project.deleted";

export interface AuditEntry {
  action: AuditAction;
  orgId?: string | null;
  actorUserId?: string | null;
  actorApiKeyId?: string | null;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Append an audit record. Pass a transaction handle for the state change being audited so the
 * change and its audit row commit (or roll back) together. Never put secrets in metadata.
 */
export async function audit(req: Request | null, entry: AuditEntry, handle: DbOrTx = db) {
  const p = req?.principal;
  await handle.insert(auditLogs).values({
    action: entry.action,
    orgId: entry.orgId ?? null,
    actorUserId: entry.actorUserId ?? (p?.type === "user" ? p.userId : null),
    actorApiKeyId: entry.actorApiKeyId ?? (p?.type === "apikey" ? p.apiKeyId : null),
    targetType: entry.targetType ?? null,
    targetId: entry.targetId ?? null,
    metadata: entry.metadata ?? {},
    requestId: req?.requestId ?? null,
    ip: req?.ip ?? null,
  });
}
