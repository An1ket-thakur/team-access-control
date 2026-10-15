import { Router } from "express";
import { and, count, desc, eq, isNull } from "drizzle-orm";
import { z } from "zod";
import { db } from "../../db";
import { memberships, organizations, roles } from "../../schema";
import { Errors } from "../../lib/errors";
import { PERMISSIONS } from "../../lib/permissions";
import { authenticate, userPrincipal } from "../../middleware/auth";
import { orgContext, requirePermission } from "../../middleware/permissions";
import { createOrganization } from "./orgs.service";
import { rolesRouter } from "../roles/roles.routes";

/** Mounted at /orgs. */
const orgsRouter = Router();
orgsRouter.use(authenticate);

const createBody = z.object({ name: z.string().trim().min(2).max(80) });

// POST /orgs   (the caller becomes the owner)
orgsRouter.post("/", async (req, res) => {
  const { userId } = userPrincipal(req);
  const { name } = createBody.parse(req.body);
  const org = await db.transaction((tx) => createOrganization(tx, userId, name));

  res.status(201).json({
    organization: { id: org.id, name: org.name, slug: org.slug, createdAt: org.createdAt },
    role: "owner",
  });
});

// GET /orgs  (organizations I belong to)
orgsRouter.get("/", async (req, res) => {
  const { userId } = userPrincipal(req);
  const data = await db
    .select({
      id: organizations.id,
      name: organizations.name,
      slug: organizations.slug,
      role: roles.name,
      joinedAt: memberships.createdAt,
    })
    .from(memberships)
    .innerJoin(organizations, eq(organizations.id, memberships.orgId))
    .innerJoin(roles, eq(roles.id, memberships.roleId))
    .where(and(eq(memberships.userId, userId), isNull(organizations.deletedAt)))
    .orderBy(desc(memberships.createdAt));

  res.json({ data });
});

// Everything below is scoped to one organization: the caller must be a member of :orgId.
orgsRouter.use("/:orgId", orgContext);

// GET /orgs/:orgId
orgsRouter.get("/:orgId", async (req, res) => {
  const ctx = req.org!;
  const [org] = await db
    .select({
      id: organizations.id,
      name: organizations.name,
      slug: organizations.slug,
      createdAt: organizations.createdAt,
    })
    .from(organizations)
    .where(eq(organizations.id, ctx.orgId))
    .limit(1);

  res.json({ organization: org, me: { role: ctx.role.name } });
});

// DELETE /orgs/:orgId   (soft delete; owner only via org.manage)
orgsRouter.delete("/:orgId", requirePermission("org.manage"), async (req, res) => {
  const orgId = req.org!.orgId;
  const { confirmName } = z.object({ confirmName: z.string() }).parse(req.body);
  const [org] = await db.select().from(organizations).where(eq(organizations.id, orgId)).limit(1);
  if (!org) throw Errors.notFound("Organization");
  if (confirmName !== org.name) {
    throw Errors.validation([{ path: "confirmName", message: "Must exactly match the organization name" }]);
  }

  await db.update(organizations).set({ deletedAt: new Date() }).where(eq(organizations.id, orgId));
  res.status(204).end();
});

// GET /orgs/:orgId/permissions   (the permission catalog)
orgsRouter.get("/:orgId/permissions", requirePermission("users.read"), (_req, res) => {
  res.json({ data: PERMISSIONS });
});

// GET /orgs/:orgId/billing   (demo endpoint guarded by billing.read)
orgsRouter.get("/:orgId/billing", requirePermission("billing.read"), async (req, res) => {
  const [{ seats }] = await db
    .select({ seats: count() })
    .from(memberships)
    .where(eq(memberships.orgId, req.org!.orgId));

  res.json({ plan: "free", seats, currency: "USD", nextInvoice: null });
});

orgsRouter.use("/:orgId/roles", rolesRouter);

export { orgsRouter };
