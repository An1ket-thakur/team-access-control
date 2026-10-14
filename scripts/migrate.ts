import fs from "fs";
import path from "path";
import { Pool } from "pg";
import { config } from "../src/config";

/** Minimal forward-only migration runner: applies migrations/*.sql in name order, once each. */
export async function migrate(databaseUrl = config.DATABASE_URL, dir = path.join(process.cwd(), "migrations")) {
  const pool = new Pool({ connectionString: databaseUrl });
  const client = await pool.connect();
  try {
    await client.query(
      "CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
    );
    // Advisory lock so parallel starts (e.g. several containers) do not race.
    await client.query("SELECT pg_advisory_lock(727274)");
    const applied = new Set((await client.query("SELECT name FROM schema_migrations")).rows.map((r) => r.name));
    const files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".sql"))
      .sort();
    for (const file of files) {
      if (applied.has(file)) continue;
      const sqlText = fs.readFileSync(path.join(dir, file), "utf8");
      await client.query("BEGIN");
      try {
        await client.query(sqlText);
        await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [file]);
        await client.query("COMMIT");
        console.log(`applied ${file}`);
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      }
    }
    await client.query("SELECT pg_advisory_unlock(727274)");
  } finally {
    client.release();
    await pool.end();
  }
}

if (require.main === module) {
  migrate().then(
    () => console.log("migrations up to date"),
    (err) => {
      console.error(err);
      process.exit(1);
    },
  );
}
