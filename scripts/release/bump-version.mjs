#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const rootDir = process.cwd();

function usage() {
  console.error(`Usage: scripts/release/bump-version.sh <version> [--dry-run]

Examples:
  scripts/release/bump-version.sh 0.2.0 --dry-run`);
}

const args = process.argv.slice(2);
const version = args.shift();
let dryRun = false;

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === "--dry-run") {
    dryRun = true;
  } else {
    console.error(`Unknown argument: ${arg}`);
    usage();
    process.exit(1);
  }
}

if (!version || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  usage();
  process.exit(1);
}

const changed = [];

function resolveRepoPath(repoPath) {
  return path.join(rootDir, repoPath);
}

function readFile(repoPath) {
  return fs.readFileSync(resolveRepoPath(repoPath), "utf8");
}

function writeFile(repoPath, content) {
  if (!dryRun) {
    fs.writeFileSync(resolveRepoPath(repoPath), content);
  }
  changed.push(repoPath);
}

function updateJsonVersionLine(repoPath, replacer) {
  const input = readFile(repoPath);
  JSON.parse(input);
  const output = replacer(input);
  if (output === input) {
    throw new Error(`Could not update JSON version in ${repoPath}`);
  }
  JSON.parse(output);
  writeFile(repoPath, output);
}

function updatePackageTomlVersion(repoPath) {
  const input = readFile(repoPath);
  const output = input.replace(
    /(^\[package\][\s\S]*?^version\s*=\s*")([^"]+)(")/m,
    `$1${version}$3`,
  );
  if (output === input) {
    throw new Error(`Could not find [package] version in ${repoPath}`);
  }
  writeFile(repoPath, output);
}

function updateLiteralVersion(repoPath, patterns) {
  let output = readFile(repoPath);
  for (const [pattern, replacement] of patterns) {
    output = output.replace(pattern, replacement);
  }
  writeFile(repoPath, output);
}

updateJsonVersionLine("package.json", (input) =>
  input.replace(/^(\s*"version"\s*:\s*")[^"]+(")/m, `$1${version}$2`),
);

updateJsonVersionLine("package-lock.json", (input) => {
  const output = input
    .replace(/^(\s*"version"\s*:\s*")[^"]+(")/m, `$1${version}$2`)
    .replace(
      /("packages"\s*:\s*\{\n\s*""\s*:\s*\{\n\s*"name"\s*:\s*"[^"]+",\n\s*"version"\s*:\s*")[^"]+(")/m,
      `$1${version}$2`,
    );
  const parsed = JSON.parse(output);
  if (parsed.version !== version || parsed.packages?.[""]?.version !== version) {
    throw new Error("Expected package-lock.json to contain root and package versions.");
  }
  return output;
});

updateJsonVersionLine("apps/desktop/src-tauri/tauri.conf.json", (input) =>
  input.replace(/^(\s*"version"\s*:\s*")[^"]+(")/m, `$1${version}$2`),
);

updateJsonVersionLine("apps/mobile/src-tauri/tauri.conf.json", (input) =>
  input.replace(/^(\s*"version"\s*:\s*")[^"]+(")/m, `$1${version}$2`),
);

for (const repoPath of [
  "apps/desktop/src-tauri/Cargo.toml",
  "apps/mobile/src-tauri/Cargo.toml",
  "crates/cleanweb-rules/Cargo.toml",
  "crates/cleanweb-subscriptions/Cargo.toml",
  "crates/cleanweb-proxy-import/Cargo.toml",
]) {
  updatePackageTomlVersion(repoPath);
}

updateLiteralVersion("README.md", [
  [/Current version: `[^`]+` beta/, `Current version: \`${version}\` beta`],
]);

updateLiteralVersion("README.zh-CN.md", [
  [/当前版本：`[^`]+` 测试版/, `当前版本：\`${version}\` 测试版`],
]);

updateLiteralVersion("packages/frontend/App.tsx", [
  [/CleanWeb v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?/g, `CleanWeb v${version}`],
]);

updateLiteralVersion("website/index.html", [
  [/(data-release-version>)[^<]+(<\/span>)/g, `$1${version}$2`],
]);

updateJsonVersionLine("website/release.json", (input) =>
  input.replace(/^(\s*"version"\s*:\s*")[^"]+(")/m, `$1${version}$2`),
);

console.log(`${dryRun ? "Would update" : "Updated"} ${changed.length} files to ${version}:`);
for (const repoPath of changed) {
  console.log(`- ${repoPath}`);
}
