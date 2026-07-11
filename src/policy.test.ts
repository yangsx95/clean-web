import { describe, expect, it } from "vitest";
import { classifyUnknownIp, POLICY_PRIORITY } from "./policy";

describe("default V1 policy", () => {
  it("lets a parent allow rule override a subscription", () => {
    expect(POLICY_PRIORITY.parentAllow).toBeLessThan(POLICY_PRIORITY.subscription);
  });

  it("does not let a normal parent allow override a security rule", () => {
    expect(POLICY_PRIORITY.security).toBeLessThan(POLICY_PRIORITY.parentAllow);
  });

  it("marks direct IP access without a domain as a warning", () => {
    expect(classifyUnknownIp({ targetIp: "203.0.113.8", matchedIpRule: false })).toBe("warning");
  });
});
