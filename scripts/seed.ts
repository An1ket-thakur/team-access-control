import { Pool } from "pg";
import { config } from "../src/config";
import { PERMISSIONS, ROLE_TEMPLATES } from "../src/lib/permissions";

/**
 * Idempotent seed: the permission catalog, the system role templates (org_id IS NULL) and
 * the permissions each template grants. Safe to run as often as you like.
 * Organizations created before permissions existed get their roles filled in too.
 */
export async function seed(databaseUrl = config.DATABASE_URL) {
  const pool = new Pool({ connectionString: databaseUrl });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    for (const p of PERMISSIONS) {
      await client.query(
        `INSERT INTO permissions (key, description) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description`,
        [p.key, p.description],
      );
    }

    for (const r of ROLE_TEMPLATES) {
      const existing = await client.query("SELECT id FROM roles WHERE org_id IS NULL AND name = $1", [r.name]);
      let roleId: string;
      if (existing.rows[0]) {
        roleId = existing.rows[0].id;
      } else {
        const created = await client.query(
          "INSERT INTO roles (org_id, name, description, rank) VALUES (NULL, $1, $2, $3) RETURNING id",
          [r.name, r.description, r.rank],
        );
        roleId = created.rows[0].id;
      }
      for (const key of r.permissions) {
        await client.query(
          `INSERT INTO role_permissions (role_id, permission_id)
           SELECT $1, id FROM permissions WHERE key = $2 ON CONFLICT DO NOTHING`,
          [roleId, key],
        );
      }
    }

    // Backfill: organization roles that have no permissions yet get a copy of their template's.
    await client.query(`
      INSERT INTO role_permissions (role_id, permission_id)
      SELECT r.id, rp.permission_id
      FROM roles r
      JOIN roles t ON t.org_id IS NULL AND t.name = r.name
      JOIN role_permissions rp ON rp.role_id = t.id
      WHERE r.org_id IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM role_permissions x WHERE x.role_id = r.id)
      ON CONFLICT DO NOTHING
    `);

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

if (require.main === module) {
  seed().then(
    () => console.log("seed complete: permissions and role templates are in place"),
    (err) => {
      console.error(err);
      process.exit(1);
    },
  );
}
