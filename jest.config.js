/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  globalSetup: "<rootDir>/tests/globalSetup.ts",
  setupFiles: ["<rootDir>/tests/env.ts"],
  testTimeout: 30000,
  transform: { "^.+\\.ts$": ["ts-jest", { diagnostics: { ignoreCodes: [151001] } }] },
};
