import { Pool } from "pg";
import { config } from "../src/config";
import { ROLE_TEMPLATES } from "../src/lib/permissions";

/**
 * Idempotent seed of the system role templates (organization_id IS NULL).
 * New organizations copy these templates. Safe to run as often as you like.
 */
export async function seed(databaseUrl = config.DATABASE_URL) {
  const pool = new Pool({ connectionString: databaseUrl });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const r of ROLE_TEMPLATES) {
      const existing = await client.query("SELECT id FROM roles WHERE org_id IS NULL AND name = $1", [r.name]);
      if (existing.rows[0]) continue;
      await client.query("INSERT INTO roles (org_id, name, description, rank) VALUES (NULL, $1, $2, $3)", [
        r.name,
        r.description,
        r.rank,
      ]);
    }
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
    () => console.log("seed complete: role templates are in place"),
    (err) => {
      console.error(err);
      process.exit(1);
    },
  );
}
