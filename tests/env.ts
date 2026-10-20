process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://tac:tac@localhost:5432/tac_test";
process.env.REDIS_URL = process.env.TEST_REDIS_URL ?? "redis://localhost:6379/1";
process.env.JWT_SECRET = "test-secret-test-secret-test-secret-123456";
process.env.TRUST_PROXY = "true";
process.env.EXPOSE_DEV_TOKENS = "true";
process.env.RATE_LIMIT_AUTH_MAX = "10";
process.env.RATE_LIMIT_GLOBAL_MAX = "100000";
