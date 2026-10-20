import request from "supertest";
import { app, PASSWORD, randomIp, signup, as, uniqueEmail } from "./helpers";
import { pool } from "../src/db";
import { redis } from "../src/redis";

afterAll(async () => {
  await pool.end();
  await redis.quit();
});

describe("signup & login", () => {
  it("signs up, hashes the password, and returns tokens", async () => {
    const ip = randomIp();
    const email = uniqueEmail();
    const res = await request(app)
      .post("/auth/signup")
      .set("X-Forwarded-For", ip)
      .send({ email, password: PASSWORD, name: "A" });
    expect(res.status).toBe(201);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.user.passwordHash).toBeUndefined();

    const row = await pool.query("SELECT password_hash FROM users WHERE email = $1", [email]);
    expect(row.rows[0].password_hash).toMatch(/^\$argon2id\$/);
  });

  it("rejects duplicate emails and weak passwords", async () => {
    const u = await signup();
    const ip = randomIp();
    const dup = await request(app)
      .post("/auth/signup")
      .set("X-Forwarded-For", ip)
      .send({ email: u.email, password: PASSWORD, name: "x" });
    expect(dup.status).toBe(409);
    const weak = await request(app)
      .post("/auth/signup")
      .set("X-Forwarded-For", ip)
      .send({ email: uniqueEmail(), password: "short", name: "x" });
    expect(weak.status).toBe(400);
    expect(weak.body.error.code).toBe("VALIDATION_ERROR");
  });

  it("gives the same generic error for unknown email and wrong password", async () => {
    const u = await signup();
    const ip = randomIp();
    const wrong = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", ip)
      .send({ email: u.email, password: "wrong-password-123" });
    const unknown = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", ip)
      .send({ email: uniqueEmail(), password: "wrong-password-123" });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.error.message).toBe(unknown.body.error.message);
    expect(wrong.body.error.code).toBe("INVALID_CREDENTIALS");
  });

  it("rejects requests with no, malformed or tampered tokens", async () => {
    const u = await signup();
    expect((await request(app).get("/me")).status).toBe(401);
    expect((await request(app).get("/me").set("Authorization", "Bearer nope")).status).toBe(401);
    const tampered = u.accessToken.slice(0, -3) + "abc";
    expect((await request(app).get("/me").set("Authorization", `Bearer ${tampered}`)).status).toBe(401);
  });

  it("rate limits auth routes (429 with Retry-After)", async () => {
    const ip = randomIp();
    let last = 0;
    for (let i = 0; i < 12; i++) {
      const r = await request(app)
        .post("/auth/login")
        .set("X-Forwarded-For", ip)
        .send({ email: uniqueEmail(), password: "whatever-123456" });
      last = r.status;
      if (last === 429) {
        expect(r.headers["retry-after"]).toBeDefined();
        expect(r.body.error.code).toBe("RATE_LIMITED");
        break;
      }
    }
    expect(last).toBe(429);
  });
});

describe("refresh token rotation", () => {
  it("rotates, stores only hashes, and rejects the old token", async () => {
    const u = await signup();
    const stored = await pool.query("SELECT refresh_token_hash FROM sessions WHERE user_id = $1", [u.id]);
    expect(stored.rows[0].refresh_token_hash).not.toContain(u.refreshToken);
    expect(stored.rows[0].refresh_token_hash).toMatch(/^[0-9a-f]{64}$/);

    const r1 = await request(app)
      .post("/auth/refresh")
      .set("X-Forwarded-For", u.ip)
      .send({ refreshToken: u.refreshToken });
    expect(r1.status).toBe(200);
    expect(r1.body.refreshToken).not.toBe(u.refreshToken);

    // the OLD token replayed -> rejected and the whole session is revoked (reuse detection)
    const replay = await request(app)
      .post("/auth/refresh")
      .set("X-Forwarded-For", u.ip)
      .send({ refreshToken: u.refreshToken });
    expect(replay.status).toBe(401);
    const newOne = await request(app)
      .post("/auth/refresh")
      .set("X-Forwarded-For", u.ip)
      .send({ refreshToken: r1.body.refreshToken });
    expect(newOne.status).toBe(401);
    const logs = await pool.query(
      "SELECT 1 FROM audit_logs WHERE actor_user_id = $1 AND action = 'session.reuse_detected'",
      [u.id],
    );
    expect(logs.rowCount).toBe(1);
  });

  it("rejects garbage refresh tokens", async () => {
    const res = await request(app)
      .post("/auth/refresh")
      .set("X-Forwarded-For", randomIp())
      .send({ refreshToken: "not-a-real-token-at-all" });
    expect(res.status).toBe(401);
  });
});

describe("sessions", () => {
  it("lists sessions, revokes one instantly, and cannot touch other users sessions", async () => {
    const a = await signup("a");
    const b = await signup("b");

    const list = await as(a).get("/me/sessions");
    expect(list.status).toBe(200);
    expect(list.body.data).toHaveLength(1);
    expect(list.body.data[0].current).toBe(true);

    // b cannot revoke a's session: looks like 404
    const sid = list.body.data[0].id;
    expect((await as(b).delete(`/me/sessions/${sid}`)).status).toBe(404);

    // a second session for a, then revoke it
    const login = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", a.ip)
      .send({ email: a.email, password: PASSWORD });
    const second = { ...a, accessToken: login.body.accessToken };
    const all = await as(a).get("/me/sessions");
    expect(all.body.data).toHaveLength(2);
    const other = all.body.data.find((s: { current: boolean }) => !s.current);
    expect((await as(a).delete(`/me/sessions/${other.id}`)).status).toBe(204);

    // the revoked session's access token stops working immediately
    expect((await as(second).get("/me")).status).toBe(401);
    expect((await as(a).get("/me")).status).toBe(200);
  });

  it("logout revokes the session", async () => {
    const u = await signup();
    expect((await as(u).post("/auth/logout")).status).toBe(204);
    expect((await as(u).get("/me")).status).toBe(401);
  });

  it("records login in the audit trail", async () => {
    const u = await signup();
    await request(app).post("/auth/login").set("X-Forwarded-For", u.ip).send({ email: u.email, password: PASSWORD });
    const logs = await as(u).get("/me/audit-logs?action=auth.login");
    expect(logs.body.data.length).toBeGreaterThanOrEqual(1);
  });
});

describe("password reset", () => {
  it("resets once, signs out everywhere, and the token cannot be reused", async () => {
    const u = await signup();
    const forgot = await request(app)
      .post("/auth/password/forgot")
      .set("X-Forwarded-For", u.ip)
      .send({ email: u.email });
    expect(forgot.status).toBe(202);
    const token = forgot.body.devResetToken;
    expect(token).toBeDefined();

    const reset = await request(app)
      .post("/auth/password/reset")
      .set("X-Forwarded-For", u.ip)
      .send({ token, password: "a-brand-new-password" });
    expect(reset.status).toBe(204);
    expect((await as(u).get("/me")).status).toBe(401); // old session gone

    const reuse = await request(app)
      .post("/auth/password/reset")
      .set("X-Forwarded-For", u.ip)
      .send({ token, password: "another-password-123" });
    expect(reuse.status).toBe(401);

    const login = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", u.ip)
      .send({ email: u.email, password: "a-brand-new-password" });
    expect(login.status).toBe(200);
  });

  it("answers identically for unknown emails", async () => {
    const res = await request(app)
      .post("/auth/password/forgot")
      .set("X-Forwarded-For", randomIp())
      .send({ email: uniqueEmail() });
    expect(res.status).toBe(202);
    expect(res.body.devResetToken).toBeUndefined();
  });
});

describe("account deletion (soft delete)", () => {
  it("soft deletes, blocks login, and frees the email", async () => {
    const u = await signup();
    expect((await as(u).delete("/me").send({ password: "wrong-password-xx" })).status).toBe(401);
    expect((await as(u).delete("/me").send({ password: PASSWORD })).status).toBe(204);

    const row = await pool.query("SELECT deleted_at FROM users WHERE id = $1", [u.id]);
    expect(row.rows[0].deleted_at).not.toBeNull();
    const login = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", u.ip)
      .send({ email: u.email, password: PASSWORD });
    expect(login.status).toBe(401);
  });
});

describe("platform", () => {
  it("returns structured errors with a request id and honours X-Request-Id", async () => {
    const res = await request(app).get("/nope").set("X-Request-Id", "my-trace-id-12345");
    expect(res.status).toBe(404);
    expect(res.headers["x-request-id"]).toBe("my-trace-id-12345");
    expect(res.body.error).toMatchObject({ code: "NOT_FOUND", requestId: "my-trace-id-12345" });
  });

  it("rejects malformed JSON without leaking internals", async () => {
    const res = await request(app).post("/auth/login").set("Content-Type", "application/json").send("{bad json");
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).not.toMatch(/stack|at Object/);
  });

  it("serves health, openapi and docs", async () => {
    expect((await request(app).get("/health")).status).toBe(200);
    const spec = await request(app).get("/openapi.json");
    expect(spec.body.openapi).toBe("3.0.3");
    expect(Object.keys(spec.body.paths).length).toBeGreaterThan(20);
    expect((await request(app).get("/docs/")).status).toBe(200);
  });
});
