import { randomUUID } from "crypto";
import request from "supertest";
import { createApp } from "../src/app";

export const app = createApp();

/** Every test "client" gets its own fake IP so rate limits never leak between tests. */
export const randomIp = () =>
  `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

export const PASSWORD = "correct-password";
export const uniqueEmail = (tag = "user") => `${tag}-${randomUUID().slice(0, 8)}@example.test`;

export interface TestUser {
  id: string;
  email: string;
  accessToken: string;
  refreshToken: string;
  ip: string;
}

export async function signup(tag = "user"): Promise<TestUser> {
  const ip = randomIp();
  const email = uniqueEmail(tag);
  const res = await request(app)
    .post("/auth/signup")
    .set("X-Forwarded-For", ip)
    .send({ email, password: PASSWORD, name: tag });
  if (res.status !== 201) throw new Error(`signup failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { id: res.body.user.id, email, accessToken: res.body.accessToken, refreshToken: res.body.refreshToken, ip };
}

export const as = (user: TestUser) => ({
  get: (url: string) =>
    request(app).get(url).set("Authorization", `Bearer ${user.accessToken}`).set("X-Forwarded-For", user.ip),
  post: (url: string) =>
    request(app).post(url).set("Authorization", `Bearer ${user.accessToken}`).set("X-Forwarded-For", user.ip),
  put: (url: string) =>
    request(app).put(url).set("Authorization", `Bearer ${user.accessToken}`).set("X-Forwarded-For", user.ip),
  patch: (url: string) =>
    request(app).patch(url).set("Authorization", `Bearer ${user.accessToken}`).set("X-Forwarded-For", user.ip),
  delete: (url: string) =>
    request(app).delete(url).set("Authorization", `Bearer ${user.accessToken}`).set("X-Forwarded-For", user.ip),
});

export async function createOrg(owner: TestUser, name = "Acme Inc") {
  const res = await as(owner).post("/orgs").send({ name });
  if (res.status !== 201) throw new Error(`createOrg failed: ${res.status}`);
  return res.body.organization.id as string;
}

/** Invite a fresh user with `role` and have them accept. Returns the new member. */
export async function addMember(owner: TestUser, orgId: string, role: string, tag = role): Promise<TestUser> {
  const member = await signup(tag);
  const inv = await as(owner).post(`/orgs/${orgId}/invitations`).send({ email: member.email, role });
  if (inv.status !== 201) throw new Error(`invite failed: ${inv.status} ${JSON.stringify(inv.body)}`);
  const acc = await as(member).post("/invitations/accept").send({ token: inv.body.inviteToken });
  if (acc.status !== 200) throw new Error(`accept failed: ${acc.status} ${JSON.stringify(acc.body)}`);
  return member;
}
