// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";

describe("browser preview persistence", () => {
  beforeEach(() => {
    const storage = new Map<string, string>();
    const sessionStorage = new Map<string, string>();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        clear: () => storage.clear(),
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
      },
    });
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      value: {
        clear: () => sessionStorage.clear(),
        getItem: (key: string) => sessionStorage.get(key) ?? null,
        setItem: (key: string, value: string) => sessionStorage.set(key, value),
        removeItem: (key: string) => sessionStorage.delete(key),
      },
    });
    window.localStorage.clear();
    window.sessionStorage.clear();
    delete (window as typeof window & { __CLEANWEB_TARGET__?: string }).__CLEANWEB_TARGET__;
    clearMocks();
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("keeps protection enabled after a page reload", async () => {
    let backend = await import("./backend");
    await backend.startProtection("browser-preview");
    await backend.updateSetting("browser-preview", "protection_enabled", "true");

    vi.resetModules();
    backend = await import("./backend");

    await expect(backend.getSettings()).resolves.toMatchObject({ protectionEnabled: true });
    await expect(backend.getCoreStatus()).resolves.toMatchObject({ running: true });
  });

  it("persists strict mode setting in browser preview", async () => {
    let backend = await import("./backend");
    await backend.updateSetting("browser-preview", "strict_mode_enabled", "true");

    vi.resetModules();
    backend = await import("./backend");

    await expect(backend.getSettings()).resolves.toMatchObject({ strictModeEnabled: true });
  });

  it("persists entertainment category setting in browser preview", async () => {
    let backend = await import("./backend");
    await backend.updateSetting("browser-preview", "category.entertainment", "true");

    vi.resetModules();
    backend = await import("./backend");

    await expect(backend.getSettings()).resolves.toMatchObject({
      categories: expect.objectContaining({ entertainment: true }),
    });
  });

  it("exposes recommended ad rule sources in browser preview", async () => {
    const backend = await import("./backend");

    await expect(backend.getRecommendedSources()).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "EasyList · Ads",
          format: "adblock",
          category: "ads",
        }),
      ]),
    );
  });

  it("uses mobile commands when the mobile shell marks the target even if the user agent is generic", async () => {
    (window as typeof window & { __CLEANWEB_TARGET__?: string }).__CLEANWEB_TARGET__ = "mobile";
    const invoked: string[] = [];
    mockIPC((command) => {
      invoked.push(command);
      if (command === "mobile_vpn_status") {
        return {
          supported: true,
          prepared: true,
          running: true,
          stage: "running",
          dataPlaneReady: true,
          dataPlaneMode: "dns_only",
          lastError: null,
          lastPolicyUpdatedAt: Date.now(),
          lastStartedAt: Date.now(),
          lastDnsActivityAt: null,
          dnsQueryCount: 3,
          blockedDnsQueryCount: 1,
          upstreamFailureCount: 0,
        };
      }
      throw new Error(`unexpected command: ${command}`);
    });

    const backend = await import("./backend");

    await expect(backend.getCoreStatus()).resolves.toMatchObject({
      running: true,
      controller: "android-vpn:running",
    });
    expect(invoked).toEqual(["mobile_vpn_status"]);
  });

  it("loads imported proxy nodes through mobile commands", async () => {
    (window as typeof window & { __CLEANWEB_TARGET__?: string }).__CLEANWEB_TARGET__ = "mobile";
    const calls: string[] = [];
    mockIPC((command, args) => {
      calls.push(command);
      if (command === "mobile_import_proxy_payload") {
        expect(args).toMatchObject({ payload: { content: expect.stringContaining("node-a") } });
        return {
          detectedFormat: "clash",
          importedCount: 0,
          ignoredCount: 0,
          proxyCount: 1,
          groupCount: 1,
          updated: true,
        };
      }
      if (command === "mobile_get_subscription_proxies") {
        expect(args).toMatchObject({ subscriptionId: expect.any(String) });
        return {
          proxies: [{ name: "node-a", nodeType: "ss" }],
          groups: [{ name: "auto", groupType: "url-test", members: ["node-a"] }],
          payloadReady: true,
        };
      }
      throw new Error(`unexpected command: ${command}`);
    });

    const backend = await import("./backend");
    const subscription = await backend.importProxyPayload("browser-preview", {
      name: "mobile proxy",
      content: "proxies:\n  - {name: node-a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\nproxy-groups:\n  - {name: auto, type: url-test, proxies: [node-a]}\n",
    });

    await expect(backend.getSubscriptionProxies("browser-preview", subscription.id)).resolves.toEqual({
      proxies: [{ name: "node-a", nodeType: "ss" }],
      groups: [{ name: "auto", groupType: "url-test", members: ["node-a"] }],
      payloadReady: true,
    });
    expect(subscription.importedRuleCount).toBe(1);
    expect(calls).toEqual(["mobile_import_proxy_payload", "mobile_get_subscription_proxies"]);
  });

  it("tests mobile proxy connectivity through the Mihomo controller in full tunnel mode", async () => {
    (window as typeof window & { __CLEANWEB_TARGET__?: string }).__CLEANWEB_TARGET__ = "mobile";
    mockIPC((command) => {
      if (command === "mobile_vpn_status") {
        return {
          supported: true,
          prepared: true,
          running: true,
          stage: "running",
          dataPlaneReady: true,
          dataPlaneMode: "full_tunnel",
          lastError: null,
          lastPolicyUpdatedAt: Date.now(),
          lastStartedAt: Date.now(),
          lastDnsActivityAt: null,
          dnsQueryCount: 0,
          blockedDnsQueryCount: 0,
          upstreamFailureCount: 0,
        };
      }
      throw new Error(`unexpected command: ${command}`);
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toContain("http://127.0.0.1:19090/proxies/CleanWeb/delay?");
      expect(init?.headers).toMatchObject({ Authorization: "Bearer cleanweb-mobile" });
      return new Response(JSON.stringify({ delay: 123 }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const backend = await import("./backend");

    await expect(backend.testProxyConnectivity("browser-preview", "www.gstatic.com/generate_204")).resolves.toEqual({
      url: "https://www.gstatic.com/generate_204",
      group: "CleanWeb",
      delay: 123,
    });
  });

  it("keeps the unlocked backend session across a page reload", async () => {
    let backend = await import("./backend");
    await backend.unlock("parent123");

    vi.resetModules();
    backend = await import("./backend");

    expect(backend.getStoredSessionToken()).toBe("browser-preview");
    await expect(backend.validateSession("browser-preview")).resolves.toMatchObject({
      sessionToken: "browser-preview",
    });
  });

  it("restores the unlocked backend session when session storage is cleared by webview reload", async () => {
    let backend = await import("./backend");
    await backend.unlock("parent123");
    window.sessionStorage.clear();

    vi.resetModules();
    backend = await import("./backend");

    expect(backend.getStoredSessionToken()).toBe("browser-preview");
  });

  it("keeps parent rules after a page reload", async () => {
    let backend = await import("./backend");
    await backend.createParentRule("browser-preview", {
      action: "block",
      kind: "suffix",
      pattern: "example.com",
      category: "custom",
    });

    vi.resetModules();
    backend = await import("./backend");

    await expect(backend.listParentRules("browser-preview")).resolves.toMatchObject([
      { action: "block", kind: "suffix", pattern: "example.com", category: "custom", enabled: true },
    ]);
  });

  it("keeps subscriptions after a page reload", async () => {
    let backend = await import("./backend");
    await backend.createSubscription("browser-preview", {
      kind: "rule",
      name: "Test rules",
      url: "https://example.com/rules.txt",
      format: "domain-list",
      category: "custom",
    });

    vi.resetModules();
    backend = await import("./backend");

    await expect(backend.listSubscriptions("browser-preview", "rule")).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "rule", name: "Test rules", url: "https://example.com/rules.txt", enabled: true }),
      ]),
    );
  });

  it("updates preview subscriptions", async () => {
    const backend = await import("./backend");
    const item = await backend.createSubscription("browser-preview", {
      kind: "rule",
      name: "Old rules",
      url: "https://example.com/old.txt",
      format: "hosts",
      category: "custom",
    });

    await backend.updateSubscription("browser-preview", item.id, {
      name: "New rules",
      url: "https://example.com/new.txt",
      format: "adblock",
      category: "ads",
      updateIntervalHours: 12,
    });

    await expect(backend.listSubscriptions("browser-preview", "rule")).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: item.id, name: "New rules", url: "https://example.com/new.txt", format: "adblock", category: "ads", updateIntervalHours: 12 }),
      ]),
    );
  });

  it("blocks preview edits and deletes for builtin URL subscriptions while allowing optional builtin toggles", async () => {
    const backend = await import("./backend");
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {
        id: "local:cleanweb:entertainment-short-video",
        kind: "rule",
        name: "CleanWeb · 短视频与直播",
        url: "https://example.test/cleanweb-entertainment-short-video.txt",
        format: "clash",
        category: "entertainment",
        enabled: true,
        uiGroup: "短视频与直播",
        uiOrder: 60,
        toggleable: true,
      },
    ]));

    await backend.listSubscriptions("browser-preview", "rule");

    await expect(backend.updateSubscription("browser-preview", "local:cleanweb:entertainment-short-video", {
      name: "Changed",
      url: "https://example.com/changed.txt",
      format: "hosts",
      category: "custom",
      updateIntervalHours: 24,
    })).rejects.toThrow("内置规则不能修改");
    await expect(backend.setSubscriptionEnabled("browser-preview", "local:cleanweb:entertainment-short-video", false)).resolves.toBeUndefined();
    await expect(backend.deleteSubscription("browser-preview", "local:cleanweb:entertainment-short-video")).rejects.toThrow("内置规则不能删除");

    await expect(backend.listSubscriptions("browser-preview", "rule")).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "local:cleanweb:entertainment-short-video", name: "CleanWeb · 短视频与直播", enabled: false }),
      ]),
    );
  });
});
