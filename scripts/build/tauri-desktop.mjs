import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const desktopDir = path.join(repoRoot, "apps", "desktop");
const args = process.argv.slice(2);

const targetIndex = args.indexOf("--target");
const inlineTarget = args.find((arg) => arg.startsWith("--target="))?.slice("--target=".length);
if (targetIndex >= 0 && !args[targetIndex + 1]) {
  console.error("--target requires a Rust target triple.");
  process.exit(2);
}

const hostTarget = () => {
  if (process.platform === "darwin") {
    return process.arch === "arm64" ? "aarch64-apple-darwin" : "x86_64-apple-darwin";
  }
  if (process.platform === "win32") {
    return process.arch === "arm64" ? "aarch64-pc-windows-msvc" : "x86_64-pc-windows-msvc";
  }
  return null;
};

const targetConfigs = new Map([
  ["aarch64-apple-darwin", "src-tauri/tauri.macos-arm64.conf.json"],
  ["x86_64-apple-darwin", "src-tauri/tauri.macos-x64.conf.json"],
  ["aarch64-pc-windows-msvc", "src-tauri/tauri.windows-arm64.conf.json"],
  ["x86_64-pc-windows-msvc", "src-tauri/tauri.windows-x64.conf.json"],
]);

const isBuild = args[0] === "build";
const forwarded = [...args];
if (isBuild) {
  if (args.some((arg) => arg === "--config" || arg.startsWith("--config="))) {
    console.error("Desktop builds choose their resource config from --target; do not pass --config manually.");
    process.exit(2);
  }
  const target = targetIndex >= 0 ? args[targetIndex + 1] : inlineTarget || hostTarget();
  const config = targetConfigs.get(target);
  if (!config) {
    console.error(`Unsupported CleanWeb desktop build target: ${target ?? "unknown host"}`);
    process.exit(2);
  }
  forwarded.push("--config", config);
  console.log(`CleanWeb desktop target ${target}: packaging exactly one Mihomo core via ${config}`);
}

const executable = path.join(
  repoRoot,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "tauri.cmd" : "tauri",
);
const result = spawnSync(executable, forwarded, {
  cwd: desktopDir,
  env: process.env,
  shell: process.platform === "win32",
  stdio: "inherit",
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
