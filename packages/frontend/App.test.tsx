// @vitest-environment jsdom
import React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import * as backend from "./backend";

beforeEach(() => {
  const values = new Map<string,string>();
  Object.defineProperty(window, "localStorage", { configurable:true, value:{
    getItem:(key:string)=>values.get(key)??null,
    setItem:(key:string,value:string)=>values.set(key,value),
    removeItem:(key:string)=>values.delete(key),
    clear:()=>values.clear(),
  }});
  window.sessionStorage.clear();
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("management actions", () => {
  async function unlockManagement() {
    await userEvent.click(await screen.findByRole("button", { name: "点击解锁" }));
    await userEvent.type(screen.getByLabelText("管理密码"), "parent123");
    await userEvent.click(screen.getByRole("button", { name: "确认解锁" }));
    await screen.findByRole("button", { name: "点击锁定" });
  }

  it("starts locked and unlocks with the parent password", async () => {
    render(<App />);
    expect(await screen.findByRole("button", { name: "点击解锁" })).toBeTruthy();
    expect(screen.getByLabelText("CleanWeb 锁定状态")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "规则管理" })).toBeNull();
    expect(screen.queryByRole("switch", { name: "总保护" })).toBeNull();
    await unlockManagement();
  });

  it("sets the initial parent password with matching confirmation", async () => {
    const bootstrap = vi.spyOn(backend, "getBootstrapState").mockResolvedValueOnce({ passwordConfigured: false });
    const initialize = vi.spyOn(backend, "initializePassword").mockResolvedValueOnce(undefined);

    render(<App />);
    await userEvent.type(await screen.findByLabelText("管理密码"), "parent123");
    await userEvent.type(screen.getByLabelText("确认密码"), "parent123");
    await userEvent.click(screen.getByRole("button", { name: "保存管理密码" }));

    expect(initialize).toHaveBeenCalledWith("parent123");
    expect(screen.queryByText("两次输入的密码不一致")).toBeNull();
    bootstrap.mockRestore();
    initialize.mockRestore();
  });

  it("navigates to rules and opens subscription form after unlocking", async () => {
    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    expect(screen.getByRole("tab", { name: /访问拦截/ })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /路由设置/ })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /内置规则/ })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /外部订阅/ })).toBeTruthy();
    await userEvent.click(screen.getByRole("tab", { name: /外部订阅/ }));
    expect(screen.getByRole("heading", { name: "外部订阅" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "添加订阅" }));
    expect(screen.getByRole("dialog", { name: "添加规则订阅" })).toBeTruthy();
  });

  it("keeps the native context menu available in editable fields and app content", async () => {
    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("button", { name: "添加拦截" }));

    expect(fireEvent.contextMenu(screen.getByLabelText("规则内容"))).toBe(true);
    expect(fireEvent.contextMenu(screen.getByRole("dialog", { name: "添加拦截规则" }))).toBe(true);
  });

  it("shows a strict mode switch on the overview", async () => {
    render(<App />);
    await unlockManagement();

    expect(screen.getByText("严格模式")).toBeTruthy();
    expect(screen.getByRole("switch", { name: "严格模式" })).toBeTruthy();
  });

  it("shows an entertainment category switch on the overview", async () => {
    render(<App />);
    await unlockManagement();

    expect(screen.getByText("短视频与游戏")).toBeTruthy();
    expect(screen.getByRole("switch", { name: "短视频与游戏" })).toBeTruthy();
  });

  it("applies browser enhancement policies from settings", async () => {
    const apply = vi.spyOn(backend, "applyBrowserPolicies").mockResolvedValueOnce({
      browsers: [
        {
          id: "edge",
          name: "Edge",
          installed: true,
          configured: true,
          needsRestart: true,
          details: [
            { label: "强制 Google SafeSearch", configured: true, currentValue: "true", expectedValue: "true" },
          ],
        },
      ],
    });

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "设置" }));
    expect(screen.queryByText("运行健康状态")).toBeNull();
    expect(screen.queryByRole("tab", { name: "管理会话" })).toBeNull();
    await userEvent.click(screen.getByRole("tab", { name: "浏览器保护" }));
    await userEvent.click(await screen.findByRole("button", { name: "应用浏览器保护" }));

    expect(apply).toHaveBeenCalledWith("browser-preview");
    expect(await screen.findByText("浏览器策略已写入，重启浏览器后完全生效")).toBeTruthy();
    apply.mockRestore();
  });

  it("keeps unrelated settings interactive while one setting is applying", async () => {
    const update = vi.spyOn(backend, "updateSetting")
      .mockImplementation(() => new Promise<backend.Settings>(() => {}));

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "设置" }));
    await userEvent.click(screen.getByRole("switch", { name: "安全搜索" }));

    await waitFor(() => expect((screen.getByRole("switch", { name: "安全搜索" }) as HTMLButtonElement).disabled).toBe(true));
    expect((screen.getByRole("switch", { name: "严格模式" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("switch", { name: "短视频与游戏" }) as HTMLButtonElement).disabled).toBe(false);
    update.mockRestore();
  });

  it("shows the protection switch as off when protection is configured but not running", async () => {
    const settings = { ...await backend.getSettings(), protectionEnabled: true };
    window.localStorage.setItem("cleanweb.preview.settings", JSON.stringify(settings));
    window.localStorage.setItem("cleanweb.preview.coreStatus", JSON.stringify({ running: false, controller: "127.0.0.1:19090", configPath: "preview" }));

    render(<App />);
    await unlockManagement();

    expect(screen.getByText("保护未运行")).toBeTruthy();
    expect(screen.getByText("配置要求保护开启，但服务当前未运行；点击开关重新启动保护")).toBeTruthy();
    expect(screen.getByRole("switch", { name: "总保护" }).getAttribute("aria-checked")).toBe("false");
  });

  it("does not auto start protection on app launch", async () => {
    const enabled = { ...await backend.getSettings(), protectionEnabled: true };
    const settings = vi.spyOn(backend, "getSettings")
      .mockResolvedValueOnce(enabled);
    const autoStart = vi.spyOn(backend, "autoStartProtection")
      .mockResolvedValue({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" });

    render(<App />);

    expect(await screen.findByLabelText("CleanWeb 锁定状态")).toBeTruthy();
    expect(screen.queryByRole("switch", { name: "总保护" })).toBeNull();
    expect(autoStart).not.toHaveBeenCalled();
    settings.mockRestore();
    autoStart.mockRestore();
  });

  it("subscribes to access log update events for overview counters", async () => {
    const subscribe = vi.spyOn(backend, "onAccessLogsUpdated").mockResolvedValue(() => {});

    render(<App />);
    await unlockManagement();

    expect(subscribe).toHaveBeenCalled();
    subscribe.mockRestore();
  });

  it("polls access logs when update events are missed", async () => {
    const interval = vi.spyOn(window, "setInterval");

    render(<App />);
    await unlockManagement();

    await waitFor(() => expect(interval).toHaveBeenCalledWith(expect.any(Function), 3000));
    interval.mockRestore();
  });

  it("does not refresh access logs when navigating between non-log pages", async () => {
    const syncLogs = vi.spyOn(backend, "syncAccessLogs").mockResolvedValue(0);
    const listLogs = vi.spyOn(backend, "listAccessLogs").mockResolvedValue([]);

    render(<App />);
    await unlockManagement();
    await waitFor(() => expect(syncLogs).toHaveBeenCalled());
    syncLogs.mockClear();
    listLogs.mockClear();

    await userEvent.click(screen.getByRole("button", { name: "设置" }));

    await new Promise((resolve) => window.setTimeout(resolve, 0));
    expect(syncLogs).not.toHaveBeenCalled();
    expect(listLogs).not.toHaveBeenCalled();
  });

  it("debounces access log searches before querying the backend", async () => {
    const listLogs = vi.spyOn(backend, "listAccessLogs").mockResolvedValue([]);

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "访问日志" }));
    listLogs.mockClear();

    fireEvent.change(screen.getByLabelText("搜索访问日志"), { target: { value: "baidu.com" } });

    expect(listLogs).not.toHaveBeenCalled();

    await waitFor(() => {
      expect(listLogs).toHaveBeenCalledWith("browser-preview", undefined, "baidu.com", 500);
    });
  });

  it("shows an error when exporting access logs fails", async () => {
    vi.spyOn(backend, "saveAccessLogsCsv").mockRejectedValueOnce(new Error("dialog save not allowed"));

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "访问日志" }));
    await userEvent.click(screen.getByRole("button", { name: "导出 CSV" }));

    expect((await screen.findAllByText("访问日志导出失败，请稍后重试")).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/dialog save not allowed/).length).toBeGreaterThan(0);
  });

  it("keeps polling access logs after a refresh failure", async () => {
    let pollLogs: (() => void) | undefined;
    const interval = vi.spyOn(window, "setInterval").mockImplementation((handler: TimerHandler, timeout?: number) => {
      if (timeout === 3000 && typeof handler === "function") pollLogs = handler as () => void;
      return 1;
    });
    vi.spyOn(backend, "listAccessLogs")
      .mockResolvedValueOnce([])
      .mockRejectedValueOnce(new Error("temporary log read failure"))
      .mockResolvedValueOnce([{
        id: "fresh-log",
        observedAt: "2026-07-26T11:03:32Z",
        domain: "fresh.example",
        targetPort: 443,
        decision: "allow",
        operatingSystem: "test",
        systemUser: "test",
      }]);

    render(<App />);
    await unlockManagement();
    await waitFor(() => expect(pollLogs).toBeTruthy());

    act(() => pollLogs?.());
    await waitFor(() => expect(backend.listAccessLogs).toHaveBeenCalledTimes(2));
    act(() => pollLogs?.());

    expect(await screen.findByText("fresh.example:443")).toBeTruthy();
    interval.mockRestore();
  });

  it("shows seconds in overview and access log timestamps", async () => {
    vi.spyOn(backend, "listAccessLogs").mockResolvedValue([{
      id: "timed-log",
      observedAt: "2026-07-26T11:03:32Z",
      domain: "timed.example",
      targetPort: 443,
      decision: "allow",
      operatingSystem: "test",
      systemUser: "test",
    }]);

    render(<App />);
    await unlockManagement();

    expect(await screen.findByText("timed.example:443")).toBeTruthy();
    expect(screen.getAllByText(/\d{2}:\d{2}:\d{2}/).length).toBeGreaterThan(0);

    await userEvent.click(screen.getByRole("button", { name: "访问日志" }));
    expect(await screen.findByText("timed.example:443")).toBeTruthy();
    expect(screen.getAllByText(/\d{2}:\d{2}:\d{2}/).length).toBeGreaterThan(0);
  });

  it("shows ports with log targets in overview and access log rows", async () => {
    vi.spyOn(backend, "listAccessLogs").mockResolvedValue([
      {
        id: "domain-port-log",
        observedAt: "2026-07-26T11:03:32Z",
        domain: "port.example",
        targetIp: "203.0.113.8",
        targetPort: 9443,
        decision: "allow",
        operatingSystem: "test",
        systemUser: "test",
      },
      {
        id: "ip-port-log",
        observedAt: "2026-07-26T11:03:31Z",
        targetIp: "198.51.100.42",
        targetPort: 8443,
        decision: "warning",
        operatingSystem: "test",
        systemUser: "test",
      },
    ]);

    render(<App />);
    await unlockManagement();

    expect(await screen.findByText("port.example:9443")).toBeTruthy();
    expect(screen.getByText("198.51.100.42:8443")).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "访问日志" }));
    expect(await screen.findByText("port.example:9443")).toBeTruthy();
    expect(screen.getAllByText("203.0.113.8:9443").length).toBeGreaterThan(0);
    expect(screen.getByText("198.51.100.42:8443")).toBeTruthy();
    expect(screen.queryByText("端口 8443")).toBeNull();
  });

  it("refreshes overview recent logs without stale log-page search filters", async () => {
    vi.spyOn(backend, "listAccessLogs").mockImplementation(async (_token, _decision, search) => {
      if (search === "baidu.com") return [];
      return [{
        id: "overview-live-log",
        observedAt: "2026-07-26T11:03:32Z",
        domain: "overview-live.example",
        targetPort: 443,
        decision: "allow",
        operatingSystem: "test",
        systemUser: "test",
      }];
    });

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "访问日志" }));
    fireEvent.change(screen.getByLabelText("搜索访问日志"), { target: { value: "baidu.com" } });

    await waitFor(() => expect(screen.getByText("没有匹配的访问记录")).toBeTruthy());
    await userEvent.click(screen.getByRole("button", { name: "概览" }));

    expect(await screen.findByText("overview-live.example:443")).toBeTruthy();
    await waitFor(() => {
      expect(backend.listAccessLogs).toHaveBeenLastCalledWith("browser-preview", undefined, undefined, 500);
    });
  });

  it("confirms app quit requests and explains that protection will stop first", async () => {
    let requestQuit = () => {};
    const coreStatus = vi.spyOn(backend, "getCoreStatus")
      .mockResolvedValue({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" });
    const subscribe = vi.spyOn(backend, "onQuitRequested")
      .mockImplementation(async (callback) => { requestQuit = callback; return () => {}; });

    render(<App />);
    expect(await screen.findByLabelText("CleanWeb 锁定状态")).toBeTruthy();
    act(() => requestQuit());

    expect(await screen.findByRole("dialog", { name: "退出前将关闭保护" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("保护运行中");
    expect(screen.getByText("输入管理密码后将先停止保护，再退出应用。")).toBeTruthy();
    subscribe.mockRestore();
    coreStatus.mockRestore();
  });

  it("opens the quit password dialog from a pending native quit request", async () => {
    const pendingQuit = vi.spyOn(backend, "takePendingQuitRequest").mockResolvedValueOnce(true);

    render(<App />);

    expect(await screen.findByRole("dialog", { name: "确认关闭 CleanWeb" })).toBeTruthy();
    expect(screen.getByLabelText("管理密码")).toBeTruthy();
    pendingQuit.mockRestore();
  });

  it("requires the management password before quitting", async () => {
    let requestQuit = () => {};
    const subscribe = vi.spyOn(backend, "onQuitRequested")
      .mockImplementation(async (callback) => { requestQuit = callback; return () => {}; });
    const quit = vi.spyOn(backend, "confirmedQuit").mockRejectedValueOnce(new Error("管理密码错误")).mockResolvedValueOnce(undefined);

    render(<App />);
    await screen.findByLabelText("CleanWeb 锁定状态");
    act(() => requestQuit());

    await userEvent.type(await screen.findByLabelText("管理密码"), "wrongpass");
    await userEvent.click(screen.getByRole("button", { name: "退出" }));
    expect(await screen.findByText("Error: 管理密码错误")).toBeTruthy();
    expect(quit).toHaveBeenCalledWith("wrongpass");

    await userEvent.clear(screen.getByLabelText("管理密码"));
    await userEvent.type(screen.getByLabelText("管理密码"), "parent123");
    await userEvent.click(screen.getByRole("button", { name: "退出" }));
    expect(quit).toHaveBeenLastCalledWith("parent123");
    subscribe.mockRestore();
  });

  it("allows the default browser context menu for copying app content", async () => {
    render(<App />);
    await screen.findByLabelText("CleanWeb 锁定状态");

    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    const allowed = window.dispatchEvent(event);

    expect(allowed).toBe(true);
    expect(event.defaultPrevented).toBe(false);
  });

  it("uses access log stats instead of the recent log list for counters", async () => {
    const logs = Array.from({ length: 2 }, (_, index) => ({
      id: `recent-${index}`,
      observedAt: "2026-01-01T00:00:00Z",
      decision: "allow" as const,
      operatingSystem: "test",
      systemUser: "test",
    }));
    const listLogs = vi.spyOn(backend, "listAccessLogs").mockResolvedValue(logs);
    const stats = vi.spyOn(backend, "getAccessLogStats").mockResolvedValue({
      block: 2,
      allow: 150,
      warning: 0,
      total: 152,
      todayBlock: 1,
      todayAllow: 10,
      todayWarning: 0,
      todayTotal: 11,
    });

    render(<App />);
    await unlockManagement();

    expect(await screen.findByText("10")).toBeTruthy();
    expect(screen.getByText("11")).toBeTruthy();
    expect(screen.getByText("1")).toBeTruthy();
    expect(screen.getByText("累计 150 次")).toBeTruthy();
    expect(screen.getByText("累计 152 条")).toBeTruthy();
    expect(screen.getByText("累计 2 次")).toBeTruthy();
  });

  it("opens both subscription forms when unlocked", async () => {
    render(<App />);
    await unlockManagement();

    await userEvent.click(screen.getByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("tab", { name: /外部订阅/ }));
    await userEvent.click(screen.getByRole("button", { name: "添加订阅" }));
    expect(screen.getByRole("dialog", { name: "添加规则订阅" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "取消" }));

    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    expect(screen.getByRole("heading", { name: "代理订阅" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "导入代理" }));
    expect(screen.getByRole("dialog", { name: "导入代理订阅" })).toBeTruthy();
  });

  it("imports a manual proxy node from the proxy import menu", async () => {
    const importProxy = vi.spyOn(backend, "importProxyPayload").mockResolvedValue({
      id: "manual-proxy",
      kind: "proxy",
      name: "手动节点",
      url: "manual://preview",
      format: "clash",
      enabled: true,
    });

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(screen.getByRole("button", { name: "选择代理导入方式" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "单节点链接" }));
    await userEvent.type(screen.getByLabelText("名称"), "手动节点");
    await userEvent.type(screen.getByLabelText("代理内容"), "ss://YWVzLTEyOC1nY206dGVzdA==@example.com:8388#my-ss");
    await userEvent.click(screen.getByRole("button", { name: "验证并添加" }));

    expect(importProxy).toHaveBeenCalledWith("browser-preview", {
      name: "手动节点",
      content: "ss://YWVzLTEyOC1nY206dGVzdA==@example.com:8388#my-ss",
    });
    importProxy.mockRestore();
  });

  it("uses a file drop area for QR proxy import", async () => {
    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(screen.getByRole("button", { name: "选择代理导入方式" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "二维码导入" }));

    expect(screen.getByRole("dialog", { name: "导入二维码" })).toBeTruthy();
    expect(screen.getByLabelText("二维码图片")).toBeTruthy();
    expect(screen.queryByLabelText("代理内容")).toBeNull();
  });

  it("imports a proxy config file from the proxy import menu", async () => {
    const importProxy = vi.spyOn(backend, "importProxyPayload").mockResolvedValue({
      id: "file-proxy",
      kind: "proxy",
      name: "proxy-config",
      url: "manual://preview",
      format: "clash",
      enabled: true,
    });

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(screen.getByRole("button", { name: "选择代理导入方式" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "配置文件" }));

    expect(screen.getByRole("dialog", { name: "导入配置文件" })).toBeTruthy();
    await userEvent.upload(
      screen.getByLabelText("配置文件"),
      new File(["proxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\n"], "proxy-config.yaml", { type: "application/yaml" })
    );
    await userEvent.click(screen.getByRole("button", { name: "验证并添加" }));

    expect(importProxy).toHaveBeenCalledWith("browser-preview", {
      name: "proxy-config",
      content: "proxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\n",
    });
    importProxy.mockRestore();
  });

  it("handles dropped files in QR proxy import", async () => {
    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(screen.getByRole("button", { name: "选择代理导入方式" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "二维码导入" }));

    const dropzone = screen.getByText("拖入二维码图片").closest(".qr-dropzone");
    expect(dropzone).toBeTruthy();
    fireEvent.drop(dropzone!, {
      dataTransfer: {
        files: [new File(["not-image"], "proxy.txt", { type: "text/plain" })],
      },
    });

    await waitFor(() => expect(screen.getByText("Error: 请选择图片文件")).toBeTruthy());
  });

  it("selects proxy nodes from an expanded subscription", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"proxy-source",kind:"proxy",name:"我的代理",url:"https://example.test/proxy",format:"clash",enabled:true},
    ]));
    const proxies = vi.spyOn(backend, "getSubscriptionProxies").mockResolvedValue({
      proxies: [{ name: "node-a", nodeType: "ss" }],
      groups: [],
    });
    const select = vi.spyOn(backend, "selectProxy").mockResolvedValue({ requiresReload: false });

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(await screen.findByText("我的代理"));
    await userEvent.click(await screen.findByRole("button", { name: /node-a/ }));

    expect(select).toHaveBeenCalledWith("browser-preview", "CleanWeb", "node-a");
    proxies.mockRestore();
    select.mockRestore();
  });

  it("tests proxy node delays with the Mihomo group delay endpoint", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"proxy-source",kind:"proxy",name:"我的代理",url:"https://example.test/proxy",format:"clash",enabled:true},
    ]));
    window.localStorage.setItem("cleanweb.preview.coreStatus", JSON.stringify({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" }));
    vi.spyOn(backend, "getCoreStatus")
      .mockResolvedValue({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" });
    vi.spyOn(backend, "getSubscriptionProxies").mockResolvedValue({
      proxies: [{ name: "node-a", nodeType: "ss" }, { name: "node-b", nodeType: "vmess" }],
      groups: [],
    });
    const groupDelay = vi.spyOn(backend, "testAllProxyDelays").mockResolvedValue({
      delays: { "node-a": 126 },
    });
    const singleDelay = vi.spyOn(backend, "testProxyGroup").mockResolvedValue(999);

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(await screen.findByText("我的代理"));
    await screen.findByRole("button", { name: /node-a/ });
    await waitFor(() => expect((screen.getByRole("button", { name: "节点延迟检测" }) as HTMLButtonElement).disabled).toBe(false));
    await userEvent.click(screen.getByRole("button", { name: "节点延迟检测" }));

    await waitFor(() => expect(groupDelay).toHaveBeenCalledWith("browser-preview", "CleanWeb"));
    expect(singleDelay).not.toHaveBeenCalled();
    expect(await screen.findByText("126ms")).toBeTruthy();
    expect(screen.getByText("不可达")).toBeTruthy();
    expect(screen.getByText("部分节点检测失败：1/2")).toBeTruthy();
  });

  it("keeps proxy node selection available while delay testing is running", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"proxy-source",kind:"proxy",name:"我的代理",url:"https://example.test/proxy",format:"clash",enabled:true},
    ]));
    window.localStorage.setItem("cleanweb.preview.coreStatus", JSON.stringify({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" }));
    vi.spyOn(backend, "getCoreStatus")
      .mockResolvedValue({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" });
    vi.spyOn(backend, "getSubscriptionProxies").mockResolvedValue({
      proxies: [{ name: "node-a", nodeType: "ss" }, { name: "node-b", nodeType: "vmess" }],
      groups: [],
    });
    let resolveDelay: (value: backend.ProxyDelayResult) => void = () => {};
    vi.spyOn(backend, "testAllProxyDelays")
      .mockImplementation(() => new Promise<backend.ProxyDelayResult>((resolve) => { resolveDelay = resolve; }));
    const select = vi.spyOn(backend, "selectProxy").mockResolvedValue({ requiresReload: false });

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(await screen.findByText("我的代理"));
    await screen.findByRole("button", { name: /node-a/ });
    await waitFor(() => expect((screen.getByRole("button", { name: "节点延迟检测" }) as HTMLButtonElement).disabled).toBe(false));
    await userEvent.click(screen.getByRole("button", { name: "节点延迟检测" }));

    expect(await screen.findByRole("button", { name: /检测中/ })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: /node-b/ }));

    expect(select).toHaveBeenCalledWith("browser-preview", "CleanWeb", "node-b");
    resolveDelay({ delays: { "node-a": 120, "node-b": 180 } });
  });

  it("keeps other proxy nodes interactive while one node is switching", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"proxy-source",kind:"proxy",name:"我的代理",url:"https://example.test/proxy",format:"clash",enabled:true},
    ]));
    vi.spyOn(backend, "getSubscriptionProxies").mockResolvedValue({
      proxies: [{ name: "node-a", nodeType: "ss" }, { name: "node-b", nodeType: "vmess" }],
      groups: [],
    });
    const select = vi.spyOn(backend, "selectProxy").mockReturnValue(new Promise(() => {}));

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(await screen.findByText("我的代理"));
    await userEvent.click(await screen.findByRole("button", { name: /node-a/ }));

    expect(await screen.findByText("切换中")).toBeTruthy();
    expect((screen.getByRole("button", { name: /node-b/ }) as HTMLButtonElement).disabled).toBe(false);
    select.mockRestore();
  });

  it("keeps other subscription rows interactive while one subscription is updating", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"source-a",kind:"rule",name:"规则源 A",url:"https://example.test/a",format:"hosts",enabled:true},
      {id:"source-b",kind:"rule",name:"规则源 B",url:"https://example.test/b",format:"hosts",enabled:true},
    ]));
    const toggle = vi.spyOn(backend, "setSubscriptionEnabled")
      .mockImplementation(() => new Promise<void>(() => {}));

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("tab", { name: /外部订阅/ }));
    await userEvent.click(await screen.findByRole("switch", { name: "规则源 A订阅" }));

    await waitFor(() => expect((screen.getByRole("switch", { name: "规则源 A订阅" }) as HTMLButtonElement).disabled).toBe(true));
    expect((screen.getByRole("switch", { name: "规则源 B订阅" }) as HTMLButtonElement).disabled).toBe(false);
    toggle.mockRestore();
  });

  it("does not allow default rule sources to be disabled or deleted", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"default:stevenblack:porn",kind:"rule",name:"内置规则 · StevenBlack porn-only",url:"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",format:"hosts",category:"pornography",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:00:00",importedRuleCount:128},
      {id:"default:blocklistproject:porn",kind:"rule",name:"内置规则 · BlocklistProject porn-nl",url:"https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt",format:"domain-list",category:"pornography",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:02:00",importedRuleCount:953393},
      {id:"local:cleanweb:entertainment-cdn",kind:"rule",name:"内置规则 · CleanWeb entertainment-cdn",url:"https://example.test/cleanweb-entertainment-cdn.txt",format:"clash",category:"entertainment",enabled:true},
      {id:"custom-source",kind:"rule",name:"我的规则",url:"https://example.test/custom",format:"hosts",category:"custom",enabled:true},
    ]));
    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));

    await userEvent.click(screen.getByRole("tab", { name: /内置规则/ }));
    expect(screen.getByRole("heading", { name: "内置规则" })).toBeTruthy();
    expect(screen.queryByText("上次更新")).toBeNull();
    expect(screen.getByText("已生效")).toBeTruthy();
    expect(screen.getByText("953521/953521 条规则生效")).toBeTruthy();
    expect(screen.getByText("待同步")).toBeTruthy();
    expect(screen.queryByRole("progressbar", { name: /下载应用进度/ })).toBeNull();
    expect(screen.getByText("娱乐内容")).toBeTruthy();
    expect(screen.queryByText("StevenBlack porn-only")).toBeNull();
    expect(screen.queryByText("BlocklistProject porn-nl")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /来源 2/ }));
    expect(await screen.findByText("上次更新")).toBeTruthy();
    expect(screen.getByText("BlocklistProject porn-nl")).toBeTruthy();
    expect(screen.getByText("StevenBlack porn-only")).toBeTruthy();
    expect(screen.queryByText("https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt")).toBeNull();
    expect(screen.getByRole("button", { name: "更新StevenBlack porn-only" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "更新BlocklistProject porn-nl" })).toBeTruthy();
    expect(screen.queryByRole("switch", { name: "内置规则 · StevenBlack porn-only订阅" })).toBeNull();
    expect(screen.queryByRole("button", { name: "删除内置规则 · StevenBlack porn-only" })).toBeNull();
    expect(screen.queryByRole("button", { name: "编辑内置规则 · CleanWeb entertainment-cdn" })).toBeNull();
    expect(screen.queryByRole("button", { name: "删除内置规则 · CleanWeb entertainment-cdn" })).toBeNull();
    await userEvent.click(screen.getByRole("tab", { name: /外部订阅/ }));
    expect(screen.getByRole("heading", { name: "外部订阅" })).toBeTruthy();
    expect(screen.queryByText("内置规则 · CleanWeb entertainment-cdn")).toBeNull();
    expect(screen.getByRole("switch", { name: "我的规则订阅" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "删除我的规则" })).toBeTruthy();
  });

  it("checks due builtin rule updates without applying when nothing is due", async () => {
    const refreshDue = vi.spyOn(backend, "refreshDueSubscriptions").mockResolvedValue(0);
    const reload = vi.spyOn(backend, "reloadProtection").mockResolvedValue({ running:true,pid:1234,controller:"127.0.0.1:19090",configPath:"preview" });

    render(<App />);
    await unlockManagement();
    await userEvent.click(screen.getByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("tab", { name: /内置规则/ }));
    await userEvent.click(screen.getByRole("button", { name: "检查更新" }));

    await screen.findByText("规则来源已是最新");
    expect(refreshDue).toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
    refreshDue.mockRestore();
    reload.mockRestore();
  });

  it("keeps external subscriptions in rule management focused on external rule sources", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"default:stevenblack:porn",kind:"rule",name:"内置规则 · 色情内容",url:"https://example.test/default",format:"hosts",category:"pornography",enabled:true},
      {id:"custom-source",kind:"rule",name:"我的规则",url:"https://example.test/custom",format:"hosts",category:"custom",enabled:true},
      {id:"proxy-source",kind:"proxy",name:"我的代理",url:"https://example.test/proxy",format:"clash",enabled:true},
    ]));

    render(<App />);
    await unlockManagement();
    expect(screen.queryByRole("button", { name: "规则导入" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("tab", { name: /外部订阅/ }));

    expect(screen.getByRole("heading", { name: "外部订阅" })).toBeTruthy();
    expect(screen.getByText("我的规则")).toBeTruthy();
    expect(screen.queryByText("内置规则 · 色情内容")).toBeNull();
    expect(screen.queryByText("我的代理")).toBeNull();
    expect(screen.queryByRole("heading", { name: "代理来源" })).toBeNull();
    expect(screen.queryByRole("button", { name: "添加代理源" })).toBeNull();
  });

  it("edits an external rule subscription", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"custom-source",kind:"rule",name:"旧规则源",url:"https://example.test/old",format:"hosts",category:"custom",updateIntervalHours:24,enabled:true},
    ]));

    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("tab", { name: /外部订阅/ }));
    await userEvent.click(screen.getByRole("button", { name: "编辑旧规则源" }));

    expect(screen.getByRole("dialog", { name: "修改规则订阅" })).toBeTruthy();
    const name = screen.getByLabelText("订阅名称");
    const url = screen.getByLabelText("订阅地址");
    await userEvent.clear(name);
    await userEvent.type(name, "新规则源");
    await userEvent.clear(url);
    await userEvent.type(url, "https://example.test/new");
    await userEvent.selectOptions(screen.getByLabelText("格式"), "adblock");
    await userEvent.selectOptions(screen.getByLabelText("分类"), "ads");
    await userEvent.selectOptions(screen.getByLabelText("更新周期"), "12");
    await userEvent.click(screen.getByRole("button", { name: "保存修改" }));

    expect(await screen.findByText("新规则源")).toBeTruthy();
    expect(screen.getByText("https://example.test/new")).toBeTruthy();
    expect(screen.getByText("adblock")).toBeTruthy();
    expect(screen.queryByText("旧规则源")).toBeNull();
  });

  it("closes the custom rule dialog after saving even when runtime reload fails", async () => {
    const coreStatus = vi.spyOn(backend, "getCoreStatus")
      .mockResolvedValue({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" });
    const reload = vi.spyOn(backend, "reloadProtection")
      .mockRejectedValue(new Error("reload failed"));

    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("button", { name: "添加拦截" }));
    await userEvent.type(screen.getByLabelText("规则内容"), "blocked.example");
    await userEvent.click(screen.getByRole("button", { name: "验证并保存" }));

    expect(screen.queryByRole("dialog", { name: "添加拦截规则" })).toBeNull();
    expect(await screen.findByText("blocked.example")).toBeTruthy();
    expect(await screen.findByText(/规则已添加，但保护配置重载失败/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "关闭错误信息" }));
    expect(screen.queryByText(/规则已添加，但保护配置重载失败/)).toBeNull();
    reload.mockRestore();
    coreStatus.mockRestore();
  });

  it("adds routing rules separately from blocking rules", async () => {
    const create = vi.spyOn(backend, "createParentRule").mockResolvedValueOnce({
      id: "route-1",
      action: "proxy",
      kind: "suffix",
      pattern: "chatgpt.com",
      category: "routing",
      enabled: true,
    });

    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    expect(screen.getByRole("heading", { name: "访问拦截" })).toBeTruthy();

    await userEvent.click(screen.getByRole("tab", { name: /路由设置/ }));
    expect(screen.getByRole("heading", { name: "路由设置" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "添加路由" }));
    expect(screen.getByRole("dialog", { name: "添加路由规则" })).toBeTruthy();
    await userEvent.selectOptions(screen.getByLabelText("出口"), "proxy");
    await userEvent.type(screen.getByLabelText("规则内容"), "chatgpt.com");
    await userEvent.click(screen.getByRole("button", { name: "验证并保存" }));

    expect(create).toHaveBeenCalledWith("browser-preview", {
      action: "proxy",
      kind: "suffix",
      pattern: "chatgpt.com",
      category: "routing",
    });
    create.mockRestore();
  });

  it("adds system route rules from the routing dialog", async () => {
    const create = vi.spyOn(backend, "createParentRule").mockResolvedValueOnce({
      id: "route-system",
      action: "system_route",
      kind: "cidr",
      pattern: "10.8.0.0/24",
      category: "routing",
      enabled: true,
    });

    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("tab", { name: /路由设置/ }));
    await userEvent.click(screen.getByRole("button", { name: "添加路由" }));
    await userEvent.selectOptions(screen.getByLabelText("出口"), "system_route");
    await userEvent.selectOptions(screen.getByLabelText("匹配方式"), "cidr");
    await userEvent.type(screen.getByLabelText("规则内容"), "10.8.0.0/24");
    await userEvent.click(screen.getByRole("button", { name: "验证并保存" }));

    expect(create).toHaveBeenCalledWith("browser-preview", {
      action: "system_route",
      kind: "cidr",
      pattern: "10.8.0.0/24",
      category: "routing",
    });
    create.mockRestore();
  });

  it("shows an applying state while runtime policy reload is pending", async () => {
    const coreStatus = vi.spyOn(backend, "getCoreStatus")
      .mockResolvedValue({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" });
    let resolveReload: (value: backend.CoreStatus) => void = () => {};
    const reload = vi.spyOn(backend, "reloadProtection")
      .mockImplementation(() => new Promise<backend.CoreStatus>((resolve) => { resolveReload = resolve; }));

    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("button", { name: "添加拦截" }));
    await userEvent.type(screen.getByLabelText("规则内容"), "pending.example");
    await userEvent.click(screen.getByRole("button", { name: "验证并保存" }));

    const status = await screen.findByRole("status");
    expect(status.textContent).toContain("应用中");
    expect(status.textContent).toContain("正在应用网络策略");

    resolveReload({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" });
    expect(await screen.findByText("网络策略已生效")).toBeTruthy();
    reload.mockRestore();
    coreStatus.mockRestore();
  });
});
