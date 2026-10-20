import { Router } from "express";
import { and, eq, inArray, sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../../db";
import { permissions, rolePermissions } from "../../schema";
import { Errors } from "../../lib/errors";
import { ALL_PERMISSION_KEYS, ROLE_NAMES } from "../../lib/permissions";
import { requirePermission } from "../../middleware/permissions";
import { findOrgRole } from "../orgs/orgs.service";
import { audit } from "../../lib/audit";

/** Mounted at /orgs/:orgId/roles. */
const rolesRouter = Router({ mergeParams: true });

// GET /orgs/:orgId/roles   (roles with their permissions and member counts)
rolesRouter.get("/", requirePermission("users.read"), async (req, res) => {
  const orgId = req.org!.orgId;
  const result = await db.execute(sql`
    SELECT r.id, r.name, r.description, r.rank,
      COALESCE(
        (SELECT array_agg(p.key ORDER BY p.key) FROM role_permissions rp
         JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = r.id),
        '{}') AS permissions,
      (SELECT count(*)::int FROM memberships m WHERE m.role_id = r.id) AS "memberCount"
    FROM roles r
    WHERE r.org_id = ${orgId}
    ORDER BY r.rank DESC
  `);

  res.json({ data: result.rows });
});

const setPermissionsBody = z.object({
  permissions: z.array(z.enum(ALL_PERMISSION_KEYS as [string, ...string[]])).max(ALL_PERMISSION_KEYS.length),
});

// PUT /orgs/:orgId/roles/:roleName/permissions   { permissions: [...] }   (replaces the set)
rolesRouter.put("/:roleName/permissions", requirePermission("roles.manage"), async (req, res) => {
  const orgId = req.org!.orgId;
  const actorRole = req.org!.role;
  const roleName = z.enum(ROLE_NAMES as [string, ...string[]]).safeParse(req.params.roleName);

  if (!roleName.success) throw Errors.notFound("Role");
  const desired = new Set(setPermissionsBody.parse(req.body).permissions);

  const role = await findOrgRole(orgId, roleName.data);
  if (!role) throw Errors.notFound("Role");

  // The owner role is fixed so an organization can never lock itself out.
  if (role.name === "owner") throw Errors.forbidden("The owner role cannot be modified");
  // You can only edit roles that rank below yours.
  if (role.rank >= actorRole!.rank) throw Errors.forbidden("You cannot modify a role at or above your own");

  const currentRows = await db
    .select({ key: permissions.key })
    .from(rolePermissions)
    .innerJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
    .where(eq(rolePermissions.roleId, role.id));
  const current = new Set(currentRows.map((r) => r.key));

  const added = [...desired].filter((k) => !current.has(k));
  const removed = [...current].filter((k) => !desired.has(k));

  // No escalation: you cannot grant a permission you do not hold yourself.
  const notHeld = added.filter((k) => !req.org!.permissions.has(k));
  if (notHeld.length > 0) {
    throw Errors.forbidden("You cannot grant permissions you do not have", { permissions: notHeld });
  }

  if (added.length > 0 || removed.length > 0) {
    await db.transaction(async (tx) => {
      if (added.length > 0) {
        const rows = await tx.select({ id: permissions.id }).from(permissions).where(inArray(permissions.key, added));
        await tx
          .insert(rolePermissions)
          .values(rows.map((p) => ({ roleId: role.id, permissionId: p.id })))
          .onConflictDoNothing();
      }
      if (removed.length > 0) {
        const rows = await tx.select({ id: permissions.id }).from(permissions).where(inArray(permissions.key, removed));
        await tx.delete(rolePermissions).where(
          and(
            eq(rolePermissions.roleId, role.id),
            inArray(
              rolePermissions.permissionId,
              rows.map((p) => p.id),
            ),
          ),
        );
      }
      for (const key of added) {
        await audit(
          req,
          {
            action: "permission.granted",
            orgId,
            targetType: "role",
            targetId: role.id,
            metadata: { role: role.name, permission: key },
          },
          tx,
        );
      }
      for (const key of removed) {
        await audit(
          req,
          {
            action: "permission.revoked",
            orgId,
            targetType: "role",
            targetId: role.id,
            metadata: { role: role.name, permission: key },
          },
          tx,
        );
      }
    });
  }

  res.json({ role: role.name, permissions: [...desired].sort(), added, removed });
});

export { rolesRouter };
