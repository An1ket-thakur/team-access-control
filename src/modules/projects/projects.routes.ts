import { Router } from "express";
import { and, asc, count, desc, eq, ilike, isNull } from "drizzle-orm";
import { z } from "zod";
import { db } from "../../db";
import { projects } from "../../schema";
import { Errors } from "../../lib/errors";
import { likeEscape, offsetOf, pageMeta, paginationQuery } from "../../lib/pagination";
import { canModifyProject } from "../../lib/policy";
import { requirePermission } from "../../middleware/permissions";
import { audit } from "../../lib/audit";

export const projectsRouter = Router({ mergeParams: true });

const createBody = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(2000).default(""),
});

const updateBody = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    description: z.string().trim().max(2000).optional(),
    status: z.enum(["active", "archived"]).optional(),
  })
  .refine((v) => Object.keys(v).length > 0, { message: "Provide at least one field to update" });

const listQuery = paginationQuery.extend({
  search: z.string().trim().max(100).optional(),
  status: z.enum(["active", "archived"]).optional(),
  owner: z.union([z.literal("me"), z.string().uuid()]).optional(),
  sort: z.enum(["createdAt", "name"]).default("createdAt"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

async function loadProject(orgId: string, rawId: unknown) {
  const id = z.string().uuid().safeParse(rawId);
  if (!id.success) throw Errors.notFound("Project");
  // Always scoped by org: a project id from another tenant is simply "not found".
  const [project] = await db
    .select()
    .from(projects)
    .where(and(eq(projects.id, id.data), eq(projects.orgId, orgId), isNull(projects.deletedAt)))
    .limit(1);
  if (!project) throw Errors.notFound("Project");
  return project;
}

// POST /orgs/:orgId/projects
projectsRouter.post("/", requirePermission("projects.write"), async (req, res) => {
  const orgId = req.org!.orgId;
  const body = createBody.parse(req.body);
  const ownerId = req.principal?.type === "user" ? req.principal.userId : null;

  const project = await db.transaction(async (tx) => {
    const [row] = await tx
      .insert(projects)
      .values({ orgId, name: body.name, description: body.description, ownerId })
      .returning();
    await audit(
      req,
      { action: "project.created", orgId, targetType: "project", targetId: row.id, metadata: { name: row.name } },
      tx,
    );
    return row;
  });
  res.status(201).json({ project });
});

// GET /orgs/:orgId/projects?search=&status=&owner=&sort=&order=&page=&limit=
projectsRouter.get("/", requirePermission("projects.read"), async (req, res) => {
  const orgId = req.org!.orgId;
  const q = listQuery.parse(req.query);
  const ownerId = q.owner === "me" ? (req.principal?.type === "user" ? req.principal.userId : undefined) : q.owner;

  const where = and(
    eq(projects.orgId, orgId),
    isNull(projects.deletedAt),
    q.status ? eq(projects.status, q.status) : undefined,
    ownerId ? eq(projects.ownerId, ownerId) : undefined,
    q.search ? ilike(projects.name, `%${likeEscape(q.search)}%`) : undefined,
  );
  const col = q.sort === "name" ? projects.name : projects.createdAt;

  const [{ total }] = await db.select({ total: count() }).from(projects).where(where);
  const data = await db
    .select()
    .from(projects)
    .where(where)
    .orderBy((q.order === "asc" ? asc : desc)(col), asc(projects.id))
    .limit(q.limit)
    .offset(offsetOf(q));

  res.json({ data, meta: pageMeta(q, total) });
});

// GET /orgs/:orgId/projects/:projectId
projectsRouter.get("/:projectId", requirePermission("projects.read"), async (req, res) => {
  res.json({ project: await loadProject(req.org!.orgId, req.params.projectId) });
});

// PATCH /orgs/:orgId/projects/:projectId   (route guard + ownership/ABAC rule)
projectsRouter.patch("/:projectId", requirePermission("projects.write"), async (req, res) => {
  const orgId = req.org!.orgId;
  const project = await loadProject(orgId, req.params.projectId);
  const body = updateBody.parse(req.body);

  const decision = canModifyProject(req, project);
  if (!decision.allow) throw Errors.forbidden(decision.reason);

  const updated = await db.transaction(async (tx) => {
    const [row] = await tx
      .update(projects)
      .set({ ...body, updatedAt: new Date() })
      .where(and(eq(projects.id, project.id), eq(projects.orgId, orgId)))
      .returning();
    await audit(
      req,
      {
        action: "project.updated",
        orgId,
        targetType: "project",
        targetId: project.id,
        metadata: { fields: Object.keys(body) },
      },
      tx,
    );
    return row;
  });
  res.json({ project: updated });
});

// DELETE /orgs/:orgId/projects/:projectId   (soft delete)
projectsRouter.delete("/:projectId", requirePermission("projects.write"), async (req, res) => {
  const orgId = req.org!.orgId;
  const project = await loadProject(orgId, req.params.projectId);

  const decision = canModifyProject(req, project);
  if (!decision.allow) throw Errors.forbidden(decision.reason);

  await db.transaction(async (tx) => {
    await tx.update(projects).set({ deletedAt: new Date() }).where(eq(projects.id, project.id));
    await audit(req, { action: "project.deleted", orgId, targetType: "project", targetId: project.id }, tx);
  });
  res.status(204).end();
});
