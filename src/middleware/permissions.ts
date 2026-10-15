import type { RequestHandler } from "express";
import { and, eq, isNull } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db";
import { memberships, organizations, roles } from "../schema";
import { Errors } from "../lib/errors";
import { userPrincipal } from "./auth";

const uuid = z.string().uuid();

/**
 * Resolves the caller's standing inside the organization named by `:orgId`.
 * The caller must be a member of a live organization. Non-members get a 404 (not 403),
 * so organization ids cannot be probed.
 */
export const orgContext: RequestHandler = async (req, _res, next) => {
  try {
    const parsed = uuid.safeParse(req.params.orgId);
    if (!parsed.success) throw Errors.notFound("Organization");
    const orgId = parsed.data;
    const { userId } = userPrincipal(req);

    const [membership] = await db
      .select({ roleId: roles.id, roleName: roles.name, rank: roles.rank })
      .from(memberships)
      .innerJoin(organizations, eq(organizations.id, memberships.orgId))
      .innerJoin(roles, eq(roles.id, memberships.roleId))
      .where(and(eq(memberships.userId, userId), eq(memberships.orgId, orgId), isNull(organizations.deletedAt)))
      .limit(1);
    if (!membership) throw Errors.notFound("Organization");

    req.org = {
      orgId,
      role: { id: membership.roleId, name: membership.roleName, rank: membership.rank },
    };
    next();
  } catch (err) {
    next(err);
  }
};
