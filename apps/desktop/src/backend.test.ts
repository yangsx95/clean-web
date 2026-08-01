// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

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

    await expect(backend.listSubscriptions("browser-preview", "rule")).resolves.toMatchObject([
      { kind: "rule", name: "Test rules", url: "https://example.com/rules.txt", enabled: true },
    ]);
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

    await expect(backend.listSubscriptions("browser-preview", "rule")).resolves.toMatchObject([
      { id: item.id, name: "New rules", url: "https://example.com/new.txt", format: "adblock", category: "ads", updateIntervalHours: 12 },
    ]);
  });

  it("blocks preview edits, disables, and deletes for builtin URL subscriptions", async () => {
    const backend = await import("./backend");
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {
        id: "local:cleanweb:entertainment-cdn",
        kind: "rule",
        name: "内置规则 · 娱乐内容补充",
        url: "https://example.test/cleanweb-entertainment-cdn.txt",
        format: "clash",
        category: "entertainment",
        enabled: true,
      },
    ]));

    await backend.listSubscriptions("browser-preview", "rule");

    await expect(backend.updateSubscription("browser-preview", "local:cleanweb:entertainment-cdn", {
      name: "Changed",
      url: "https://example.com/changed.txt",
      format: "hosts",
      category: "custom",
      updateIntervalHours: 24,
    })).rejects.toThrow("内置规则不能修改");
    await expect(backend.setSubscriptionEnabled("browser-preview", "local:cleanweb:entertainment-cdn", false)).rejects.toThrow("内置规则必须保持启用");
    await expect(backend.deleteSubscription("browser-preview", "local:cleanweb:entertainment-cdn")).rejects.toThrow("内置规则不能删除");

    await expect(backend.listSubscriptions("browser-preview", "rule")).resolves.toMatchObject([
      { id: "local:cleanweb:entertainment-cdn", name: "内置规则 · 娱乐内容补充", enabled: true },
    ]);
  });
});
