import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const repoRoot = process.cwd();
const rulesDir = path.join(repoRoot, "resources", "rules");
const ruleFiles = (await readdir(rulesDir))
  .filter((file) => file.endsWith(".clash"))
  .sort();

const allowedTypes = new Set([
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN-WILDCARD",
  "IP-CIDR",
  "IP-CIDR6",
]);

const errors = [];

for (const file of ruleFiles) {
  const filePath = path.join(rulesDir, file);
  const text = await readFile(filePath, "utf8");
  const seen = new Map();

  text.split(/\r?\n/).forEach((rawLine, index) => {
    const lineNumber = index + 1;
    const line = rawLine.trim();

    if (!line || line.startsWith("#")) {
      return;
    }

    const [type, value, action, ...options] = line.split(",");
    const normalized = line.toLowerCase();

    if (seen.has(normalized)) {
      errors.push(`${file}:${lineNumber} duplicates line ${seen.get(normalized)}: ${line}`);
      return;
    }

    seen.set(normalized, lineNumber);

    if (!allowedTypes.has(type)) {
      errors.push(`${file}:${lineNumber} has unsupported rule type: ${type}`);
    }

    if (!value) {
      errors.push(`${file}:${lineNumber} is missing rule value`);
    }

    if (action !== "REJECT") {
      errors.push(`${file}:${lineNumber} must use REJECT action`);
    }

    if (options.length > 1 || (options.length === 1 && options[0] !== "no-resolve")) {
      errors.push(`${file}:${lineNumber} has unsupported options: ${options.join(",")}`);
    }
  });
}

if (errors.length > 0) {
  console.error(errors.join("\n"));
  process.exit(1);
}

console.log(`Validated ${ruleFiles.length} Clash rule files.`);
