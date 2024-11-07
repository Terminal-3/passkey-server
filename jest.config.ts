// jest.config.js
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/*.spec.ts"],
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/$1",
  },
};
