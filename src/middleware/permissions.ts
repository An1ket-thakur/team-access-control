import type { RequestHandler } from "express";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "../db";
import { memberships, organizations, permissions, rolePermissions, roles } from "../schema";
import { Errors } from "../lib/errors";
import type { PermissionKey } from "../lib/permissions";
import { z } from "zod";

const uuid = z.string().uuid();

/**
 * Resolves the caller's standing inside the organization named by `:orgId`.
 *
 * - User: must be a member of a live organization; permissions come from their role.
 * - API key: must belong to that organization; permissions come from the key's own scope.
 *
 * Non-members get a 404 (not 403) so organization ids cannot be probed.
 */
export const orgContext: RequestHandler = async (req, _res, next) => {
  try {
    const parsed = uuid.safeParse(req.params.orgId);
    if (!parsed.success) throw Errors.notFound("Organization");
    const orgId = parsed.data;
    const principal = req.principal;
    if (!principal) throw Errors.unauthenticated();

    if (principal.type === "apikey") {
      if (principal.orgId !== orgId) throw Errors.notFound("Organization");
      req.org = { orgId, role: null, permissions: new Set(principal.permissions) };
      return next();
    }

    const [membership] = await db
      .select({ roleId: roles.id, roleName: roles.name, rank: roles.rank })
      .from(memberships)
      .innerJoin(organizations, eq(organizations.id, memberships.orgId))
      .innerJoin(roles, eq(roles.id, memberships.roleId))
      .where(
        and(eq(memberships.userId, principal.userId), eq(memberships.orgId, orgId), isNull(organizations.deletedAt)),
      )
      .limit(1);
    if (!membership) throw Errors.notFound("Organization");

    const rows = await db
      .select({ key: permissions.key })
      .from(rolePermissions)
      .innerJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
      .where(eq(rolePermissions.roleId, membership.roleId));

    req.org = {
      orgId,
      role: { id: membership.roleId, name: membership.roleName, rank: membership.rank },
      permissions: new Set(rows.map((r) => r.key)),
    };
    next();
  } catch (err) {
    next(err);
  }
};

/** Route-level guard. All listed permissions are required. Deny by default. */
export function requirePermission(...required: PermissionKey[]): RequestHandler {
  return (req, _res, next) => {
    const ctx = req.org;
    if (!ctx) return next(Errors.forbidden()); // guard used without orgContext: deny
    const missing = required.filter((p) => !ctx.permissions.has(p));
    if (missing.length > 0) {
      return next(Errors.forbidden("You do not have permission to perform this action", { required: missing }));
    }
    next();
  };
}

export const hasPermission = (req: Express.Request, key: PermissionKey) => req.org?.permissions.has(key) ?? false;

/** The caller's role in this org. Only users have one; API keys carry permissions directly. */
export function userRole(req: Express.Request) {
  const role = req.org?.role;
  if (!role) throw Errors.forbidden("This endpoint requires a user session");
  return role;
}
