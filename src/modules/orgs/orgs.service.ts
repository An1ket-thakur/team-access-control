import { randomInt } from "crypto";
import { and, eq, sql } from "drizzle-orm";
import { db, type Tx } from "../../db";
import { memberships, organizations, roles } from "../../schema";

const slugify = (name: string) =>
  name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "org";

const randomSuffix = () => Array.from({ length: 6 }, () => randomInt(0, 36).toString(36)).join("");

/**
 * Creates an organization with its own copy of the system roles (and their permissions)
 * and makes `ownerUserId` the owner. Runs inside the caller's transaction, so it either
 * fully happens or not at all.
 */
export async function createOrganization(tx: Tx, ownerUserId: string, name: string) {
  const [org] = await tx
    .insert(organizations)
    .values({ name, slug: `${slugify(name)}-${randomSuffix()}`, createdBy: ownerUserId })
    .returning();

  // Copy the role templates (org_id IS NULL) into this organization...
  await tx.execute(sql`
    INSERT INTO roles (org_id, name, description, rank)
    SELECT ${org.id}::uuid, name, description, rank FROM roles WHERE org_id IS NULL
  `);
  // ...and the permissions each template grants.
  await tx.execute(sql`
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT nr.id, rp.permission_id
    FROM roles nr
    JOIN roles t ON t.org_id IS NULL AND t.name = nr.name
    JOIN role_permissions rp ON rp.role_id = t.id
    WHERE nr.org_id = ${org.id}::uuid
  `);

  const [ownerRole] = await tx
    .select({ id: roles.id })
    .from(roles)
    .where(and(eq(roles.orgId, org.id), eq(roles.name, "owner")))
    .limit(1);
  if (!ownerRole) throw new Error("System roles are not seeded. Run `npm run db:seed`.");

  await tx.insert(memberships).values({ userId: ownerUserId, orgId: org.id, roleId: ownerRole.id });
  return org;
}

export async function findOrgRole(orgId: string, name: string, handle: typeof db | Tx = db) {
  const [role] = await handle
    .select()
    .from(roles)
    .where(and(eq(roles.orgId, orgId), eq(roles.name, name)))
    .limit(1);
  return role;
}
