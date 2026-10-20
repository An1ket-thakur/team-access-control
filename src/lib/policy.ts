import type { Request } from "express";

export interface ProjectAttrs {
  ownerId: string | null;
  status: "active" | "archived";
}

export interface Decision {
  allow: boolean;
  reason?: string;
}

/**
 * ABAC-style rule for modifying or deleting a project. It combines attributes of the caller
 * (permissions, identity), the resource (owner, status) and keeps the decision explainable.
 *
 *  1. projects.manage_any  -> always allowed (admins / owners)
 *  2. otherwise the caller must be the project's owner
 *  3. ...and the project must not be archived (archived projects are frozen for non-managers)
 *
 * The route-level guard (`projects.write`) has already run; this is the resource-level check.
 */
export function canModifyProject(req: Request, project: ProjectAttrs): Decision {
  if (req.org?.permissions.has("projects.manage_any")) return { allow: true };

  const principal = req.principal;
  const isOwner = principal?.type === "user" && project.ownerId !== null && project.ownerId === principal.userId;
  if (!isOwner) return { allow: false, reason: "Only the project owner or a manager can modify this project" };
  if (project.status === "archived") {
    return { allow: false, reason: "Archived projects can only be modified by a manager" };
  }
  return { allow: true };
}
