import request from "supertest";
import { app, as, addMember, createOrg, signup, uniqueEmail, randomIp } from "./helpers";
import { pool } from "../src/db";
import { redis } from "../src/redis";

afterAll(async () => {
  await pool.end();
  await redis.quit();
});

describe("route-level permission guards (deny by default)", () => {
  it("allows and blocks by role", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const admin = await addMember(owner, orgId, "admin");
    const member = await addMember(owner, orgId, "member");
    const viewer = await addMember(owner, orgId, "viewer");

    // billing.read: owner + admin yes, member + viewer no
    expect((await as(owner).get(`/orgs/${orgId}/billing`)).status).toBe(200);
    expect((await as(admin).get(`/orgs/${orgId}/billing`)).status).toBe(200);
    const blocked = await as(member).get(`/orgs/${orgId}/billing`);
    expect(blocked.status).toBe(403);
    expect(blocked.body.error.details.required).toEqual(["billing.read"]);
    expect((await as(viewer).get(`/orgs/${orgId}/billing`)).status).toBe(403);

    // projects.write: member yes, viewer no
    expect((await as(member).post(`/orgs/${orgId}/projects`).send({ name: "P1" })).status).toBe(201);
    expect((await as(viewer).post(`/orgs/${orgId}/projects`).send({ name: "P2" })).status).toBe(403);
    expect((await as(viewer).get(`/orgs/${orgId}/projects`)).status).toBe(200);

    // users.invite: member cannot
    const inv = await as(member).post(`/orgs/${orgId}/invitations`).send({ email: uniqueEmail() });
    expect(inv.status).toBe(403);

    // audit.read: member cannot, admin can
    expect((await as(member).get(`/orgs/${orgId}/audit-logs`)).status).toBe(403);
    expect((await as(admin).get(`/orgs/${orgId}/audit-logs`)).status).toBe(200);
  });

  it("hides organizations from non-members (404, not 403) and blocks unauthenticated access", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const outsider = await signup("outsider");
    expect((await as(outsider).get(`/orgs/${orgId}`)).status).toBe(404);
    expect((await as(outsider).get(`/orgs/${orgId}/projects`)).status).toBe(404);
    expect((await request(app).get(`/orgs/${orgId}`)).status).toBe(401);
  });

  it("isolates tenants: a project id from another org is not found", async () => {
    const o1 = await signup("o1");
    const o2 = await signup("o2");
    const org1 = await createOrg(o1, "Org One");
    const org2 = await createOrg(o2, "Org Two");
    const p = await as(o1).post(`/orgs/${org1}/projects`).send({ name: "secret" });
    const res = await as(o2).get(`/orgs/${org2}/projects/${p.body.project.id}`);
    expect(res.status).toBe(404);
  });
});

describe("resource-level ownership / ABAC", () => {
  it("members edit only their own projects; admins can edit any; archived is frozen", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const alice = await addMember(owner, orgId, "member", "alice");
    const bob = await addMember(owner, orgId, "member", "bob");
    const admin = await addMember(owner, orgId, "admin");

    const p = await as(alice).post(`/orgs/${orgId}/projects`).send({ name: "Alice project" });
    const id = p.body.project.id;

    const bobEdit = await as(bob).patch(`/orgs/${orgId}/projects/${id}`).send({ name: "hijack" });
    expect(bobEdit.status).toBe(403);
    expect((await as(bob).delete(`/orgs/${orgId}/projects/${id}`)).status).toBe(403);

    expect((await as(alice).patch(`/orgs/${orgId}/projects/${id}`).send({ name: "renamed" })).status).toBe(200);
    expect((await as(admin).patch(`/orgs/${orgId}/projects/${id}`).send({ name: "by admin" })).status).toBe(200);

    // archive, then the owner can no longer modify it
    expect((await as(alice).patch(`/orgs/${orgId}/projects/${id}`).send({ status: "archived" })).status).toBe(200);
    const frozen = await as(alice).patch(`/orgs/${orgId}/projects/${id}`).send({ name: "nope" });
    expect(frozen.status).toBe(403);
    expect((await as(admin).patch(`/orgs/${orgId}/projects/${id}`).send({ status: "active" })).status).toBe(200);

    // soft delete hides it
    expect((await as(alice).delete(`/orgs/${orgId}/projects/${id}`)).status).toBe(204);
    expect((await as(alice).get(`/orgs/${orgId}/projects/${id}`)).status).toBe(404);
    const row = await pool.query("SELECT deleted_at FROM projects WHERE id = $1", [id]);
    expect(row.rows[0].deleted_at).not.toBeNull();
  });
});

describe("role changes & privilege escalation", () => {
  it("lets admins promote members to admin? no: only below their own rank", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const admin = await addMember(owner, orgId, "admin");
    const member = await addMember(owner, orgId, "member");

    const toAdmin = await as(admin).patch(`/orgs/${orgId}/members/${member.id}`).send({ role: "admin" });
    expect(toAdmin.status).toBe(403);
    const toViewer = await as(admin).patch(`/orgs/${orgId}/members/${member.id}`).send({ role: "viewer" });
    expect(toViewer.status).toBe(200);

    // admin cannot touch the owner, and cannot change own role
    expect((await as(admin).patch(`/orgs/${orgId}/members/${owner.id}`).send({ role: "viewer" })).status).toBe(403);
    expect((await as(admin).patch(`/orgs/${orgId}/members/${admin.id}`).send({ role: "owner" })).status).toBe(403);

    // role change is audited
    const logs = await as(owner).get(`/orgs/${orgId}/audit-logs?action=member.role_changed`);
    expect(logs.body.data[0].metadata).toEqual({ from: "member", to: "viewer" });
  });

  it("protects the last owner", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    expect((await as(owner).delete(`/orgs/${orgId}/members/me`)).status).toBe(409);
    expect((await as(owner).delete("/me").send({ password: "correct-password" })).status).toBe(409);
  });

  it("edits role permissions, audits grants, and keeps the owner role immutable", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const member = await addMember(owner, orgId, "member");
    expect((await as(member).get(`/orgs/${orgId}/billing`)).status).toBe(403);

    const grant = await as(owner)
      .put(`/orgs/${orgId}/roles/member/permissions`)
      .send({ permissions: ["users.read", "projects.read", "projects.write", "billing.read"] });
    expect(grant.status).toBe(200);
    expect(grant.body.added).toEqual(["billing.read"]);
    expect((await as(member).get(`/orgs/${orgId}/billing`)).status).toBe(200); // takes effect immediately

    expect((await as(owner).put(`/orgs/${orgId}/roles/owner/permissions`).send({ permissions: [] })).status).toBe(403);
    expect((await as(member).put(`/orgs/${orgId}/roles/viewer/permissions`).send({ permissions: [] })).status).toBe(
      403,
    );
    expect(
      (
        await as(owner)
          .put(`/orgs/${orgId}/roles/member/permissions`)
          .send({ permissions: ["nope.nothing"] })
      ).status,
    ).toBe(400);

    const logs = await as(owner).get(`/orgs/${orgId}/audit-logs?action=permission.granted`);
    expect(logs.body.data[0].metadata).toEqual({ role: "member", permission: "billing.read" });

    // edits in one org do not leak into another org
    const other = await signup("other");
    const otherOrg = await createOrg(other, "Other Org");
    const roles = await as(other).get(`/orgs/${otherOrg}/roles`);
    const m = roles.body.data.find((r: { name: string }) => r.name === "member");
    expect(m.permissions).not.toContain("billing.read");
  });
});

describe("invitations", () => {
  it("runs the invite -> accept flow, single use, email-bound", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const invitee = await signup("invitee");
    const stranger = await signup("stranger");

    const inv = await as(owner).post(`/orgs/${orgId}/invitations`).send({ email: invitee.email, role: "viewer" });
    expect(inv.status).toBe(201);
    const token = inv.body.inviteToken;

    // stored hashed
    const row = await pool.query("SELECT token_hash FROM invitations WHERE id = $1", [inv.body.invitation.id]);
    expect(row.rows[0].token_hash).not.toBe(token);

    // duplicate pending invite
    expect((await as(owner).post(`/orgs/${orgId}/invitations`).send({ email: invitee.email })).status).toBe(409);
    // wrong user cannot use the token
    expect((await as(stranger).post("/invitations/accept").send({ token })).status).toBe(400);

    const ok = await as(invitee).post("/invitations/accept").send({ token });
    expect(ok.status).toBe(200);
    expect(ok.body.role).toBe("viewer");
    // single use
    expect((await as(invitee).post("/invitations/accept").send({ token })).status).toBe(400);

    const members = await as(owner).get(`/orgs/${orgId}/members?search=invitee`);
    expect(members.body.data).toHaveLength(1);
    expect(members.body.data[0].role).toBe("viewer");
  });

  it("rejects expired and revoked invitations", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const a = await signup("a");
    const b = await signup("b");

    const invA = await as(owner).post(`/orgs/${orgId}/invitations`).send({ email: a.email });
    await pool.query("UPDATE invitations SET expires_at = now() - interval '1 minute' WHERE id = $1", [
      invA.body.invitation.id,
    ]);
    expect((await as(a).post("/invitations/accept").send({ token: invA.body.inviteToken })).status).toBe(400);

    const invB = await as(owner).post(`/orgs/${orgId}/invitations`).send({ email: b.email });
    expect((await as(owner).delete(`/orgs/${orgId}/invitations/${invB.body.invitation.id}`)).status).toBe(204);
    expect((await as(b).post("/invitations/accept").send({ token: invB.body.inviteToken })).status).toBe(400);

    // an expired invite does not block re-inviting
    expect((await as(owner).post(`/orgs/${orgId}/invitations`).send({ email: a.email })).status).toBe(201);
    const expired = await as(owner).get(`/orgs/${orgId}/invitations?status=pending`);
    expect(expired.body.data.every((i: { status: string }) => i.status === "pending")).toBe(true);
  });

  it("stops admins from inviting at or above their own role", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const admin = await addMember(owner, orgId, "admin");
    expect(
      (await as(admin).post(`/orgs/${orgId}/invitations`).send({ email: uniqueEmail(), role: "admin" })).status,
    ).toBe(403);
    expect(
      (await as(admin).post(`/orgs/${orgId}/invitations`).send({ email: uniqueEmail(), role: "owner" })).status,
    ).toBe(403);
    expect(
      (await as(admin).post(`/orgs/${orgId}/invitations`).send({ email: uniqueEmail(), role: "member" })).status,
    ).toBe(201);
  });
});

describe("API keys (machine-to-machine)", () => {
  it("creates a scoped key shown once, authenticates with it, and revokes it", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const member = await addMember(owner, orgId, "member");

    // members cannot manage keys
    expect(
      (
        await as(member)
          .post(`/orgs/${orgId}/api-keys`)
          .send({ name: "x", permissions: ["projects.read"] })
      ).status,
    ).toBe(403);

    const created = await as(owner)
      .post(`/orgs/${orgId}/api-keys`)
      .send({ name: "ci", permissions: ["projects.read", "projects.write"] });
    expect(created.status).toBe(201);
    const key = created.body.key;
    expect(key).toMatch(/^tak_/);
    const row = await pool.query("SELECT key_hash FROM api_keys WHERE id = $1", [created.body.apiKey.id]);
    expect(row.rows[0].key_hash).not.toContain(key);

    const useKey = (method: "get" | "post", url: string) =>
      request(app)[method](url).set("X-API-Key", key).set("X-Forwarded-For", owner.ip);

    expect((await useKey("get", `/orgs/${orgId}/projects`)).status).toBe(200);
    expect((await useKey("post", `/orgs/${orgId}/projects`).send({ name: "from key" })).status).toBe(201);
    expect((await useKey("get", `/orgs/${orgId}/billing`)).status).toBe(403); // not in scope
    expect((await useKey("get", `/orgs/${orgId}/api-keys`)).status).toBe(403); // keys cannot manage keys

    // a key only works in its own org
    const otherOrg = await createOrg(owner, "Second");
    expect((await useKey("get", `/orgs/${otherOrg}/projects`)).status).toBe(404);

    // cannot escalate: owner-held permissions only
    const adminUser = await addMember(owner, orgId, "admin");
    const esc = await as(adminUser)
      .post(`/orgs/${orgId}/api-keys`)
      .send({ name: "esc", permissions: ["org.manage"] });
    expect(esc.status).toBe(403);

    expect((await as(owner).delete(`/orgs/${orgId}/api-keys/${created.body.apiKey.id}`)).status).toBe(204);
    expect((await useKey("get", `/orgs/${orgId}/projects`)).status).toBe(401);
    expect((await request(app).get(`/orgs/${orgId}/projects`).set("X-API-Key", "tak_bogus_key")).status).toBe(401);
  });
});

describe("listing: pagination and filtering", () => {
  it("paginates, filters and sorts members, projects and audit logs", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    for (const n of ["alpha", "beta", "gamma"])
      await as(owner)
        .post(`/orgs/${orgId}/projects`)
        .send({ name: `proj-${n}` });
    await addMember(owner, orgId, "viewer", "v1");
    await addMember(owner, orgId, "viewer", "v2");

    const page1 = await as(owner).get(`/orgs/${orgId}/projects?limit=2&page=1&sort=name&order=asc`);
    expect(page1.body.data.map((p: { name: string }) => p.name)).toEqual(["proj-alpha", "proj-beta"]);
    expect(page1.body.meta).toMatchObject({ total: 3, totalPages: 2, page: 1, limit: 2 });
    const search = await as(owner).get(`/orgs/${orgId}/projects?search=gam`);
    expect(search.body.data).toHaveLength(1);
    // LIKE wildcards in user input are matched literally
    expect((await as(owner).get(`/orgs/${orgId}/projects?search=%25`)).body.data).toHaveLength(0);

    const viewers = await as(owner).get(`/orgs/${orgId}/members?role=viewer`);
    expect(viewers.body.meta.total).toBe(2);
    expect((await as(owner).get(`/orgs/${orgId}/members?limit=1000`)).status).toBe(400);

    const inv = await as(owner).get(`/orgs/${orgId}/audit-logs?actionPrefix=invitation.&limit=5`);
    expect(inv.body.data.length).toBeGreaterThan(0);
    expect(inv.body.data.every((l: { action: string }) => l.action.startsWith("invitation."))).toBe(true);

    // sign-in events of members show up in the org audit log
    const auth = await as(owner).get(`/orgs/${orgId}/audit-logs?actionPrefix=auth.`);
    expect(auth.body.data.length).toBeGreaterThan(0);
    const orgOnly = await as(owner).get(`/orgs/${orgId}/audit-logs?actionPrefix=auth.&includeAuthEvents=false`);
    expect(orgOnly.body.data).toHaveLength(0);
  });
});

describe("organization soft delete", () => {
  it("requires confirmation and then hides the org and kills its keys", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner, "Doomed Org");
    const key = await as(owner)
      .post(`/orgs/${orgId}/api-keys`)
      .send({ name: "k", permissions: ["projects.read"] });

    expect((await as(owner).delete(`/orgs/${orgId}`).send({ confirmName: "wrong" })).status).toBe(400);
    expect((await as(owner).delete(`/orgs/${orgId}`).send({ confirmName: "Doomed Org" })).status).toBe(204);

    expect((await as(owner).get(`/orgs/${orgId}`)).status).toBe(404);
    const row = await pool.query("SELECT deleted_at FROM organizations WHERE id = $1", [orgId]);
    expect(row.rows[0].deleted_at).not.toBeNull();
    const viaKey = await request(app)
      .get(`/orgs/${orgId}/projects`)
      .set("X-API-Key", key.body.key)
      .set("X-Forwarded-For", randomIp());
    expect(viaKey.status).toBe(401);
  });

  it("only owners can delete an organization", async () => {
    const owner = await signup("owner");
    const orgId = await createOrg(owner);
    const admin = await addMember(owner, orgId, "admin");
    expect((await as(admin).delete(`/orgs/${orgId}`).send({ confirmName: "Acme Inc" })).status).toBe(403);
  });
});
