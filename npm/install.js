#!/usr/bin/env node
/* eslint-env node */

const fs = require("fs");
const path = require("path");
const https = require("https");
const os = require("os");
const { execSync } = require("child_process");

const PACKAGE_NAME = "purelink";
const GITHUB_REPO = "MasuRii/PureLink";
const PACKAGE_VERSION = require("./package.json").version;

const PLATFORM_MAP = {
  darwin: "darwin",
  linux: "linux",
  win32: "windows",
};

const ARCH_MAP = {
  x64: "amd64",
  arm64: "arm64",
};

function getPlatform() {
  const platform = os.platform();
  const arch = os.arch();
  const mappedPlatform = PLATFORM_MAP[platform];
  const mappedArch = ARCH_MAP[arch];
  if (!mappedPlatform || !mappedArch) {
    throw new Error(
      `Unsupported platform: ${platform} ${arch}. PureLink supports Linux/macOS/Windows on amd64/arm64.`
    );
  }
  return { platform: mappedPlatform, arch: mappedArch };
}

function getDownloadURL(version, platform, arch) {
  const ext = platform === "windows" ? "zip" : "tar.gz";
  const tag = version.startsWith("v") ? version : `v${version}`;
  return `https://github.com/${GITHUB_REPO}/releases/download/${tag}/${PACKAGE_NAME}_${tag}_${platform}_${arch}.${ext}`;
}

function getBinaryPath() {
  return path.join(__dirname, "bin", PACKAGE_NAME);
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, { headers: { "User-Agent": "purelink-npm-installer" } }, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          return downloadFile(response.headers.location, dest).then(resolve).catch(reject);
        }
        if (response.statusCode !== 200) {
          return reject(new Error(`Download failed with status ${response.statusCode}: ${url}`));
        }
        response.pipe(file);
        file.on("finish", () => {
          file.close(resolve);
        });
      })
      .on("error", (err) => {
        fs.unlink(dest, () => {});
        reject(err);
      });
  });
}

function extractTarGz(archivePath, destDir) {
  try {
    execSync(`tar -xzf "${archivePath}" -C "${destDir}"`, { stdio: "ignore" });
  } catch {
    throw new Error(`Failed to extract ${archivePath}. Ensure tar is available.`);
  }
}

function extractZip(archivePath, destDir) {
  try {
    execSync(`powershell -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${destDir}' -Force"`, { stdio: "ignore" });
  } catch {
    throw new Error(`Failed to extract ${archivePath}. Ensure PowerShell is available.`);
  }
}

function extract(archivePath, destDir, platform) {
  if (platform === "windows") {
    extractZip(archivePath, destDir);
  } else {
    extractTarGz(archivePath, destDir);
  }
}

async function main() {
  // Determine version. If running from purelink source build (dev), skip install.
  if (PACKAGE_VERSION === "0.0.0-dev" || PACKAGE_VERSION === "0.0.0") {
    console.log("[purelink] Development build detected — skipping binary download.");
    console.log("[purelink] Please run 'npm run verify' after the release is published.");
    process.exit(0);
  }

  const { platform, arch } = getPlatform();
  const url = getDownloadURL(PACKAGE_VERSION, platform, arch);
  const binDir = path.join(__dirname, "bin");
  const binPath = getBinaryPath();

  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  // Skip if binary already exists
  if (fs.existsSync(binPath)) {
    console.log("[purelink] Binary already exists — skipping download.");
    return;
  }

  const tmpFile = path.join(os.tmpdir(), `purelink-${Date.now()}.archive`);

  console.log(`[purelink] Downloading ${platform}/${arch} binary...`);
  await downloadFile(url, tmpFile);

  console.log("[purelink] Extracting binary...");
  extract(tmpFile, binDir, platform);

  fs.unlinkSync(tmpFile);

  // Ensure binary is executable on Unix
  if (platform !== "windows") {
    fs.chmodSync(binPath, 0o755);
  }

  console.log("[purelink] Installation complete.");
}

main().catch((err) => {
  console.error(`[purelink] Installation failed: ${err.message}`);
  process.exit(1);
});
