import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { config } from "./config";
import * as schema from "./schema";

export const pool = new Pool({ connectionString: config.DATABASE_URL, max: 10 });
export const db = drizzle(pool, { schema });

export type DB = typeof db;
// Either the root db or a transaction handle; both expose the same query builder surface.
export type Tx = Parameters<Parameters<DB["transaction"]>[0]>[0];
export type DbOrTx = DB | Tx;
