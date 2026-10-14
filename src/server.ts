import { config } from "./config";
import { logger } from "./logger";
import { createApp, shutdown } from "./app";

const app = createApp();
const server = app.listen(config.PORT, () => {
  logger.info(`API listening on :${config.PORT}`);
});

async function stop(signal: string) {
  logger.info({ signal }, "shutting down");
  server.close(async () => {
    await shutdown();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => void stop("SIGTERM"));
process.on("SIGINT", () => void stop("SIGINT"));
