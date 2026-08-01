import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("desktop Tauri capabilities", () => {
  it("allows the access log export save dialog", () => {
    const capabilityPath = resolve(
      process.cwd(),
      "apps/desktop/src-tauri/capabilities/default.json",
    );
    const capability = JSON.parse(readFileSync(capabilityPath, "utf8"));

    expect(capability.windows).toContain("main");
    expect(capability.permissions).toContain("dialog:allow-save");
  });
});
