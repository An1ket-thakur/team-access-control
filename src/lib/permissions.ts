/**
 * Permission catalog + default role templates. These are seeded into the database
 * (`npm run db:seed`) and copied into every new organization.
 */
export const PERMISSIONS = [
  { key: "users.read", description: "View organization members and roles" },
  { key: "users.invite", description: "Invite teammates and manage invitations" },
  { key: "users.manage", description: "Change member roles and remove members" },
  { key: "projects.read", description: "View projects" },
  { key: "projects.write", description: "Create projects and edit projects you own" },
  { key: "projects.manage_any", description: "Edit or delete any project, regardless of owner" },
  { key: "billing.read", description: "View billing information" },
  { key: "roles.manage", description: "Grant or revoke permissions on roles" },
  { key: "audit.read", description: "View the organization audit log" },
  { key: "apikeys.manage", description: "Create, list and revoke API keys" },
  { key: "org.manage", description: "Delete the organization" },
] as const;

export type PermissionKey = (typeof PERMISSIONS)[number]["key"];
export const ALL_PERMISSION_KEYS: PermissionKey[] = PERMISSIONS.map((p) => p.key);

export const ROLE_TEMPLATES: {
  name: string;
  rank: number;
  description: string;
  permissions: PermissionKey[];
}[] = [
  {
    name: "owner",
    rank: 40,
    description: "Full control of the organization",
    permissions: ALL_PERMISSION_KEYS,
  },
  {
    name: "admin",
    rank: 30,
    description: "Manage people, projects and API keys",
    permissions: [
      "users.read",
      "users.invite",
      "users.manage",
      "projects.read",
      "projects.write",
      "projects.manage_any",
      "billing.read",
      "audit.read",
      "apikeys.manage",
    ],
  },
  {
    name: "member",
    rank: 20,
    description: "Work on projects",
    permissions: ["users.read", "projects.read", "projects.write"],
  },
  {
    name: "viewer",
    rank: 10,
    description: "Read-only access",
    permissions: ["users.read", "projects.read"],
  },
];

export const ROLE_NAMES = ROLE_TEMPLATES.map((r) => r.name);
