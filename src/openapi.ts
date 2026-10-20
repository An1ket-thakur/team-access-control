import { z } from "zod";
import { ALL_PERMISSION_KEYS, ROLE_NAMES } from "./lib/permissions";
import { forgotBody, loginBody, refreshBody, resetBody, signupBody } from "./modules/auth/auth.schemas";

type Json = Record<string, unknown>;

// Request bodies for auth endpoints come straight from the Zod DTOs so docs cannot drift.
const fromZod = (schema: z.ZodType, example: Json): Json => {
  const { $schema: _ignored, ...rest } = z.toJSONSchema(schema, {
    io: "input",
    unrepresentable: "any",
    target: "draft-07",
  }) as Json;
  return { ...rest, example };
};

const str = (extra: Json = {}): Json => ({ type: "string", ...extra });
const obj = (properties: Json, required: string[] = [], example?: Json): Json => ({
  type: "object",
  properties,
  ...(required.length && { required }),
  ...(example && { example }),
});
const uuid = str({ format: "uuid" });
const roleEnum = str({ enum: ROLE_NAMES });
const permEnum = str({ enum: ALL_PERMISSION_KEYS });

const pageParams: Json[] = [
  { name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
  { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 100, default: 20 } },
];
const q = (name: string, schema: Json, description?: string): Json => ({
  name,
  in: "query",
  schema,
  ...(description && { description }),
});
const orgParam: Json = { name: "orgId", in: "path", required: true, schema: uuid };
const idParam = (name: string): Json => ({ name, in: "path", required: true, schema: uuid });

/** Operations that can answer 409 CONFLICT (duplicates, last-owner guards, ...). */
const CONFLICTS = new Set([
  "post /auth/signup",
  "delete /me",
  "delete /orgs/{orgId}/members/me",
  "post /orgs/{orgId}/invitations",
  "post /invitations/accept",
]);

interface Op {
  method: "get" | "post" | "put" | "patch" | "delete";
  path: string;
  tag: string;
  summary: string;
  description?: string;
  /** 'none' = public, 'user' = bearer JWT only, 'any' = bearer JWT or API key */
  auth: "none" | "user" | "any";
  permission?: string;
  params?: Json[];
  body?: Json;
  status?: number;
  response?: Json;
}

const ops: Op[] = [
  // ---------- Auth ----------
  {
    method: "post",
    path: "/auth/signup",
    tag: "Auth",
    summary: "Create an account and sign in",
    auth: "none",
    body: fromZod(signupBody, { email: "alice@example.com", password: "correct-horse-battery", name: "Alice" }),
    status: 201,
  },
  {
    method: "post",
    path: "/auth/login",
    tag: "Auth",
    summary: "Sign in",
    auth: "none",
    body: fromZod(loginBody, { email: "alice@example.com", password: "correct-horse-battery" }),
    description: "Rate limited per IP and per email. Failed attempts return a generic 401.",
  },
  {
    method: "post",
    path: "/auth/refresh",
    tag: "Auth",
    summary: "Rotate the refresh token",
    auth: "none",
    body: fromZod(refreshBody, { refreshToken: "<sessionId>.<secret> from login or the previous refresh" }),
    description:
      "Every call returns a NEW refresh token and invalidates the old one. Replaying an old token revokes the whole session.",
  },
  {
    method: "post",
    path: "/auth/logout",
    tag: "Auth",
    summary: "Sign out (revokes the current session)",
    auth: "user",
    status: 204,
  },
  {
    method: "post",
    path: "/auth/password/forgot",
    tag: "Auth",
    summary: "Request a password reset",
    auth: "none",
    body: fromZod(forgotBody, { email: "alice@example.com" }),
    status: 202,
    description:
      "Always answers 202 so accounts cannot be enumerated. With EXPOSE_DEV_TOKENS=true the token is returned as devResetToken.",
  },
  {
    method: "post",
    path: "/auth/password/reset",
    tag: "Auth",
    summary: "Set a new password with a reset token",
    auth: "none",
    body: fromZod(resetBody, { token: "<devResetToken from /auth/password/forgot>", password: "a-brand-new-password" }),
    status: 204,
    description: "Single use. Signs the user out of every session.",
  },
  // ---------- Me & sessions ----------
  { method: "get", path: "/me", tag: "Me & Sessions", summary: "Current user and organizations", auth: "user" },
  {
    method: "delete",
    path: "/me",
    tag: "Me & Sessions",
    summary: "Soft-delete my account",
    auth: "user",
    body: obj({ password: str() }, ["password"], { password: "correct-horse-battery" }),
    status: 204,
    description: "Blocked while you are the only owner of an organization.",
  },
  { method: "get", path: "/me/sessions", tag: "Me & Sessions", summary: "List my active sessions", auth: "user" },
  {
    method: "delete",
    path: "/me/sessions/{sessionId}",
    tag: "Me & Sessions",
    summary: "Revoke one of my sessions",
    auth: "user",
    params: [idParam("sessionId")],
    status: 204,
    description: "Takes effect immediately for access tokens too (Redis denylist).",
  },
  {
    method: "post",
    path: "/me/sessions/revoke-others",
    tag: "Me & Sessions",
    summary: "Revoke all sessions except the current one",
    auth: "user",
  },
  {
    method: "get",
    path: "/me/audit-logs",
    tag: "Me & Sessions",
    summary: "My own account activity (logins, session changes)",
    auth: "user",
    params: [...pageParams, q("action", str())],
  },
  // ---------- Organizations ----------
  {
    method: "post",
    path: "/orgs",
    tag: "Organizations",
    summary: "Create an organization (caller becomes owner)",
    auth: "user",
    body: obj({ name: str({ minLength: 2, maxLength: 80 }) }, ["name"], { name: "Acme Inc" }),
    status: 201,
  },
  { method: "get", path: "/orgs", tag: "Organizations", summary: "Organizations I belong to", auth: "user" },
  {
    method: "get",
    path: "/orgs/{orgId}",
    tag: "Organizations",
    summary: "Organization details and my permissions",
    auth: "any",
    params: [orgParam],
  },
  {
    method: "delete",
    path: "/orgs/{orgId}",
    tag: "Organizations",
    summary: "Soft-delete the organization",
    auth: "user",
    permission: "org.manage",
    params: [orgParam],
    body: obj({ confirmName: str() }, ["confirmName"], { confirmName: "Acme Inc" }),
    status: 204,
  },
  {
    method: "get",
    path: "/orgs/{orgId}/permissions",
    tag: "Roles & Permissions",
    summary: "Permission catalog",
    auth: "any",
    permission: "users.read",
    params: [orgParam],
  },
  {
    method: "get",
    path: "/orgs/{orgId}/billing",
    tag: "Organizations",
    summary: "Billing summary (demo endpoint for billing.read)",
    auth: "any",
    permission: "billing.read",
    params: [orgParam],
  },
  // ---------- Members ----------
  {
    method: "get",
    path: "/orgs/{orgId}/members",
    tag: "Members",
    summary: "List members",
    auth: "any",
    permission: "users.read",
    params: [
      orgParam,
      ...pageParams,
      q("search", str(), "Name or email contains"),
      q("role", roleEnum),
      q("sort", str({ enum: ["joinedAt", "name", "email"] })),
      q("order", str({ enum: ["asc", "desc"] })),
    ],
  },
  {
    method: "patch",
    path: "/orgs/{orgId}/members/{userId}",
    tag: "Members",
    summary: "Change a member role",
    auth: "user",
    permission: "users.manage",
    params: [orgParam, idParam("userId")],
    body: obj({ role: roleEnum }, ["role"], { role: "admin" }),
    description:
      "You can only assign or modify roles below your own (owners can assign any). You cannot change your own role.",
  },
  {
    method: "delete",
    path: "/orgs/{orgId}/members/{userId}",
    tag: "Members",
    summary: "Remove a member",
    auth: "user",
    permission: "users.manage",
    params: [orgParam, idParam("userId")],
    status: 204,
  },
  {
    method: "delete",
    path: "/orgs/{orgId}/members/me",
    tag: "Members",
    summary: "Leave the organization",
    auth: "user",
    params: [orgParam],
    status: 204,
  },

  // ---------- Roles ----------
  {
    method: "get",
    path: "/orgs/{orgId}/roles",
    tag: "Roles & Permissions",
    summary: "Roles with their permissions",
    auth: "any",
    permission: "users.read",
    params: [orgParam],
  },
  {
    method: "put",
    path: "/orgs/{orgId}/roles/{roleName}/permissions",
    tag: "Roles & Permissions",
    summary: "Replace the permission set of a role",
    auth: "user",
    permission: "roles.manage",
    params: [orgParam, { name: "roleName", in: "path", required: true, schema: roleEnum }],
    body: obj({ permissions: { type: "array", items: permEnum } }, ["permissions"], {
      permissions: ["users.read", "projects.read", "projects.write"],
    }),
    description: "The owner role is immutable. You cannot grant permissions you do not hold. Every change is audited.",
  },

  // ---------- Invitations ----------
  {
    method: "post",
    path: "/orgs/{orgId}/invitations",
    tag: "Invitations",
    summary: "Invite a teammate (expiring token)",
    auth: "user",
    permission: "users.invite",
    params: [orgParam],
    body: obj({ email: str({ format: "email" }), role: roleEnum }, ["email"], {
      email: "bob@example.com",
      role: "member",
    }),
    status: 201,
    description: "With EXPOSE_DEV_TOKENS=true the token is returned as inviteToken (there is no email service).",
  },
  {
    method: "get",
    path: "/orgs/{orgId}/invitations",
    tag: "Invitations",
    summary: "List invitations",
    auth: "any",
    permission: "users.invite",
    params: [
      orgParam,
      ...pageParams,
      q("status", str({ enum: ["pending", "accepted", "revoked", "expired"] })),
      q("search", str()),
      q("order", str({ enum: ["asc", "desc"] })),
    ],
  },
  {
    method: "delete",
    path: "/orgs/{orgId}/invitations/{invitationId}",
    tag: "Invitations",
    summary: "Revoke a pending invitation",
    auth: "user",
    permission: "users.invite",
    params: [orgParam, idParam("invitationId")],
    status: 204,
  },
  {
    method: "post",
    path: "/invitations/accept",
    tag: "Invitations",
    summary: "Accept an invitation",
    auth: "user",
    body: obj({ token: str() }, ["token"], { token: "<inviteToken from the invitation response>" }),
    description: "You must be signed in as the invited email address.",
  },

  // ---------- API keys ----------
  {
    method: "post",
    path: "/orgs/{orgId}/api-keys",
    tag: "API Keys",
    summary: "Create an API key",
    auth: "user",
    permission: "apikeys.manage",
    params: [orgParam],
    body: obj(
      {
        name: str(),
        permissions: { type: "array", items: permEnum, minItems: 1 },
        expiresInDays: { type: "integer", minimum: 1, maximum: 365 },
      },
      ["name", "permissions"],
      { name: "ci-reader", permissions: ["projects.read"], expiresInDays: 30 },
    ),
    status: 201,
    description: "The full key is shown once. Send it as the X-API-Key header.",
  },
  {
    method: "get",
    path: "/orgs/{orgId}/api-keys",
    tag: "API Keys",
    summary: "List API keys",
    auth: "user",
    permission: "apikeys.manage",
    params: [orgParam, ...pageParams, q("status", str({ enum: ["active", "revoked", "all"] }))],
  },
  {
    method: "delete",
    path: "/orgs/{orgId}/api-keys/{keyId}",
    tag: "API Keys",
    summary: "Revoke an API key",
    auth: "user",
    permission: "apikeys.manage",
    params: [orgParam, idParam("keyId")],
    status: 204,
  },

  // ---------- Projects ----------
  {
    method: "post",
    path: "/orgs/{orgId}/projects",
    tag: "Projects",
    summary: "Create a project",
    auth: "any",
    permission: "projects.write",
    params: [orgParam],
    body: obj({ name: str(), description: str() }, ["name"], {
      name: "Website redesign",
      description: "Q4 marketing site",
    }),
    status: 201,
  },
  {
    method: "get",
    path: "/orgs/{orgId}/projects",
    tag: "Projects",
    summary: "List projects",
    auth: "any",
    permission: "projects.read",
    params: [
      orgParam,
      ...pageParams,
      q("search", str()),
      q("status", str({ enum: ["active", "archived"] })),
      q("owner", str(), "A user id or 'me'"),
      q("sort", str({ enum: ["createdAt", "name"] })),
      q("order", str({ enum: ["asc", "desc"] })),
    ],
  },
  {
    method: "get",
    path: "/orgs/{orgId}/projects/{projectId}",
    tag: "Projects",
    summary: "Get a project",
    auth: "any",
    permission: "projects.read",
    params: [orgParam, idParam("projectId")],
  },
  {
    method: "patch",
    path: "/orgs/{orgId}/projects/{projectId}",
    tag: "Projects",
    summary: "Update a project",
    auth: "any",
    permission: "projects.write",
    params: [orgParam, idParam("projectId")],
    body: obj({ name: str(), description: str(), status: str({ enum: ["active", "archived"] }) }, [], {
      status: "archived",
    }),
    description:
      "ABAC rule: projects.manage_any may edit anything; otherwise you must own the project and it must not be archived.",
  },
  {
    method: "delete",
    path: "/orgs/{orgId}/projects/{projectId}",
    tag: "Projects",
    summary: "Delete a project (soft)",
    auth: "any",
    permission: "projects.write",
    params: [orgParam, idParam("projectId")],
    status: 204,
    description: "Same ownership/ABAC rule as update.",
  },

  // ---------- Audit ----------
  {
    method: "get",
    path: "/orgs/{orgId}/audit-logs",
    tag: "Audit",
    summary: "Organization audit log",
    auth: "any",
    permission: "audit.read",
    params: [
      orgParam,
      ...pageParams,
      q("action", str(), "Exact action, e.g. member.role_changed"),
      q("actionPrefix", str(), "e.g. 'invitation.' or 'auth.'"),
      q("actorUserId", uuid),
      q("targetType", str()),
      q("from", str({ format: "date-time" })),
      q("to", str({ format: "date-time" })),
      q("includeAuthEvents", { type: "boolean", default: true }, "Include sign-in activity of members"),
      q("order", str({ enum: ["asc", "desc"] })),
    ],
  },
];

export function buildOpenApiDocument() {
  const paths: Record<string, Json> = {};

  for (const op of ops) {
    const security =
      op.auth === "none" ? [] : op.auth === "user" ? [{ bearerAuth: [] }] : [{ bearerAuth: [] }, { apiKeyAuth: [] }];
    const status = String(op.status ?? 200);
    const responses: Record<string, Json> = {
      [status]: {
        description: status === "204" ? "No content" : "Success",
        ...(status !== "204" && { content: { "application/json": { schema: { type: "object" } } } }),
      },
      "400": { $ref: "#/components/responses/ValidationError" },
    };
    if (op.auth !== "none") {
      responses["401"] = { $ref: "#/components/responses/Unauthenticated" };
      responses["403"] = { $ref: "#/components/responses/Forbidden" };
    }
    if (op.path.includes("{")) responses["404"] = { $ref: "#/components/responses/NotFound" };
    if (op.auth === "none" || op.path.startsWith("/invitations"))
      responses["429"] = { $ref: "#/components/responses/RateLimited" };

    if (CONFLICTS.has(`${op.method} ${op.path}`)) responses["409"] = { $ref: "#/components/responses/Conflict" };
    responses["500"] = { $ref: "#/components/responses/ServerError" };

    paths[op.path] ??= {};
    paths[op.path][op.method] = {
      tags: [op.tag],
      summary: op.summary,
      description:
        [op.description, op.permission && `**Requires permission:** \`${op.permission}\``]
          .filter(Boolean)
          .join("\n\n") || undefined,
      security,
      ...(op.params && { parameters: op.params }),
      ...(op.body && { requestBody: { required: true, content: { "application/json": { schema: op.body } } } }),
      responses,
    };
  }

  const requestId = "3f2b8c1e-7a41-4d0b-9c55-2e6a1f0d9b77";

  const example = (summary: string, code: string, message: string, details?: unknown): Json => ({
    summary,
    value: { error: { code, message, ...(details !== undefined && { details }), requestId } },
  });

  const errorResponse = (description: string, examples: Record<string, Json>, headers?: Json): Json => ({
    description,
    ...(headers && { headers }),
    content: { "application/json": { schema: { $ref: "#/components/schemas/Error" }, examples } },
  });

  return {
    openapi: "3.0.3",
    info: {
      title: "Team Access Control API",
      version: "1.0.0",
      description:
        "Multi-tenant IAM-style backend: users, organizations, memberships, roles, permissions, invitations, sessions, API keys and audit logs.\n\n" +
        "**Try it:** sign up via `POST /auth/signup`, click *Authorize* and paste the `accessToken`.",
    },
    servers: [{ url: "/" }],
    tags: [
      "Auth",
      "Me & Sessions",
      "Organizations",
      "Members",
      "Roles & Permissions",
      "Invitations",
      "API Keys",
      "Projects",
      "Audit",
    ].map((name) => ({ name })),
    paths,
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
        apiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" },
      },
      schemas: {
        Error: {
          type: "object",
          properties: {
            error: {
              type: "object",
              required: ["code", "message"],
              properties: {
                code: {
                  type: "string",
                  enum: [
                    "VALIDATION_ERROR",
                    "UNAUTHENTICATED",
                    "INVALID_CREDENTIALS",
                    "INVALID_TOKEN",
                    "FORBIDDEN",
                    "NOT_FOUND",
                    "CONFLICT",
                    "RATE_LIMITED",
                    "INVITATION_INVALID",
                    "INTERNAL_ERROR",
                  ],
                },
                message: { type: "string" },
                details: {},
                requestId: { type: "string" },
              },
            },
          },
        },
      },
      responses: {
        ValidationError: errorResponse("Bad request: validation failed, or an invalid invitation (400)", {
          validation: example("Validation failed", "VALIDATION_ERROR", "Request validation failed", [
            { path: "password", message: "Password must be at least 10 characters" },
          ]),
          invitation: example(
            "Invalid invitation",
            "INVITATION_INVALID",
            "This invitation is invalid, expired or already used",
          ),
        }),
        Unauthenticated: errorResponse("Missing, invalid or revoked credentials (401)", {
          missing: example("No credentials sent", "UNAUTHENTICATED", "Authentication required"),
          invalidToken: example("Bad, expired or revoked token / API key", "INVALID_TOKEN", "Invalid or expired token"),
          invalidCredentials: example(
            "Wrong email or password (login only)",
            "INVALID_CREDENTIALS",
            "Invalid email or password",
          ),
        }),
        Forbidden: errorResponse("Authenticated but not allowed (403)", {
          permission: example("Missing permission", "FORBIDDEN", "You do not have permission to perform this action", {
            required: ["billing.read"],
          }),
          rule: example("Blocked by a rule", "FORBIDDEN", "You cannot assign or modify a role at or above your own"),
        }),
        NotFound: errorResponse("Not found, or not visible to you (404)", {
          notFound: example("Resource not found", "NOT_FOUND", "Project not found"),
        }),
        Conflict: errorResponse("Conflicts with the current state (409)", {
          conflict: example(
            "Already exists / not allowed right now",
            "CONFLICT",
            "An account with this email already exists",
          ),
        }),
        RateLimited: errorResponse(
          "Too many requests (429)",
          {
            rateLimited: example("Rate limited", "RATE_LIMITED", "Too many requests, please try again later", {
              retryAfterSeconds: 30,
            }),
          },
          {
            "Retry-After": { description: "Seconds to wait before retrying", schema: { type: "integer", example: 30 } },
          },
        ),
        ServerError: errorResponse("Unexpected server error (500). Details are logged server-side, never returned.", {
          internal: example("Internal error", "INTERNAL_ERROR", "Something went wrong"),
        }),
      },
    },
  };
}
