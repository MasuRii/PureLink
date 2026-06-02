#!/usr/bin/env node
/* eslint-env node */

const path = require("path");
const { spawnSync } = require("child_process");

const BINARY_NAME = process.platform === "win32" ? "purelink.exe" : "purelink";
const BINARY_PATH = path.join(__dirname, "bin", BINARY_NAME);

function run() {
  const args = process.argv.slice(2);
  const result = spawnSync(BINARY_PATH, args, {
    stdio: "inherit",
    shell: false,
  });

  if (result.error) {
    console.error(`[purelink] Failed to spawn binary: ${result.error.message}`);
    process.exit(1);
  }

  process.exit(result.status ?? 0);
}

function verify() {
  const fs = require("fs");
  if (!fs.existsSync(BINARY_PATH)) {
    console.error("[purelink] Binary not found. Run 'npm install' after a published release.");
    process.exit(1);
  }
  const result = spawnSync(BINARY_PATH, ["--version"], { encoding: "utf-8" });
  if (result.status !== 0) {
    console.error("[purelink] Binary verification failed.");
    process.exit(1);
  }
  console.log(`[purelink] Verified: ${result.stdout.trim()}`);
}

module.exports = { run, verify };

if (require.main === module) {
  run();
}
