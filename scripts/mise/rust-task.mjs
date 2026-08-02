import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const task = process.argv[2];
const taskConfig = {
  test: {
    target: "desktop-test",
    args: ["test", "--lib"],
  },
  lint: {
    target: "desktop-lint",
    args: ["clippy", "--all-targets", "--", "-D", "warnings"],
  },
};

if (!taskConfig[task]) {
  console.error(`Unknown Rust task: ${task ?? ""}`);
  process.exit(2);
}

const gitRoot = spawnSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"],
});

if (gitRoot.status !== 0) {
  process.exit(gitRoot.status ?? 1);
}

const root = gitRoot.stdout.trim();
const cacheRoot = process.env.CLEANWEB_MISE_CACHE_DIR
  ? path.resolve(process.env.CLEANWEB_MISE_CACHE_DIR)
  : path.join(os.homedir(), ".cache", "clean-web", "mise");
const tmpDir = path.join(cacheRoot, "tmp");
const cargoHome = path.join(cacheRoot, "cargo-home");
const cargoTarget = path.join(cacheRoot, "cargo-target", taskConfig[task].target);
const desktopTauri = path.join(root, "apps", "desktop", "src-tauri");

for (const directory of [tmpDir, cargoHome, cargoTarget]) {
  mkdirSync(directory, { recursive: true });
}

const env = {
  ...process.env,
  TMPDIR: tmpDir,
  TMP: tmpDir,
  TEMP: tmpDir,
  CARGO_HOME: cargoHome,
  CARGO_TARGET_DIR: cargoTarget,
};

const cargo = spawnSync("cargo", taskConfig[task].args, {
  cwd: desktopTauri,
  env,
  stdio: "inherit",
  shell: process.platform === "win32",
});

process.exit(cargo.status ?? 1);
