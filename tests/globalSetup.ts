import path from "path";
import { migrate } from "../scripts/migrate";
import { seed } from "../scripts/seed";

export default async function globalSetup() {
  const url = process.env.TEST_DATABASE_URL ?? "postgres://tac:tac@localhost:5432/tac_test";
  await migrate(url, path.join(process.cwd(), "migrations"));
  await seed(url);
}
