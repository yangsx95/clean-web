// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

afterEach(cleanup);

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

  it("shows a strict mode switch on the overview", async () => {
    render(<App />);
    await unlockManagement();

    expect(screen.getByText("严格模式")).toBeTruthy();
    expect(screen.getByRole("switch", { name: "严格模式" })).toBeTruthy();
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

  it("keeps protection enabled when auto start is cancelled on app launch", async () => {
    const enabled = { ...await backend.getSettings(), protectionEnabled: true };
    const settings = vi.spyOn(backend, "getSettings")
      .mockResolvedValueOnce(enabled)
      .mockResolvedValueOnce(enabled);
    const autoStart = vi.spyOn(backend, "autoStartProtection")
      .mockRejectedValueOnce(new Error("已取消管理员授权，CleanWeb 未开启保护"));

    render(<App />);

    expect((await screen.findByRole("alert")).textContent).toContain("已取消管理员授权");
    expect(screen.getByLabelText("CleanWeb 锁定状态")).toBeTruthy();
    expect(screen.queryByRole("switch", { name: "总保护" })).toBeNull();
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

  it("uses access log stats instead of the recent log list for counters", async () => {
    const logs = Array.from({ length: 100 }, (_, index) => ({
      id: `allow-${index}`,
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
    });

    render(<App />);
    await unlockManagement();

    expect(await screen.findByText("150")).toBeTruthy();
    expect(screen.getByText("152")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
    listLogs.mockRestore();
    stats.mockRestore();
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

  it("does not allow default rule sources to be disabled or deleted", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"default:stevenblack:porn",kind:"rule",name:"内置规则 · 色情内容",url:"https://example.test/default",format:"hosts",category:"pornography",updateIntervalHours:24,enabled:true},
      {id:"custom-source",kind:"rule",name:"我的规则",url:"https://example.test/custom",format:"hosts",category:"custom",enabled:true},
    ]));
    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));

    await userEvent.click(screen.getByRole("tab", { name: /内置规则/ }));
    expect(screen.getByRole("heading", { name: "内置规则" })).toBeTruthy();
    expect(screen.getByText("内置启用")).toBeTruthy();
    expect(screen.queryByText("https://example.test/default")).toBeNull();
    expect(screen.queryByRole("switch", { name: "内置规则 · 色情内容订阅" })).toBeNull();
    expect(screen.queryByRole("button", { name: "删除内置规则 · 色情内容" })).toBeNull();
    await userEvent.click(screen.getByRole("tab", { name: /外部订阅/ }));
    expect(screen.getByRole("heading", { name: "外部订阅" })).toBeTruthy();
    expect(screen.getByRole("switch", { name: "我的规则订阅" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "删除我的规则" })).toBeTruthy();
  });

  it("closes the custom rule dialog after saving even when runtime reload fails", async () => {
    const coreStatus = vi.spyOn(backend, "getCoreStatus")
      .mockResolvedValue({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" });
    const reload = vi.spyOn(backend, "reloadProtection")
      .mockResolvedValueOnce({ running: true, pid: 1234, controller: "127.0.0.1:19090", configPath: "preview" })
      .mockRejectedValueOnce(new Error("reload failed"));

    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("button", { name: "添加拦截" }));
    await userEvent.type(screen.getByLabelText("规则内容"), "blocked.example");
    await userEvent.click(screen.getByRole("button", { name: "验证并保存" }));

    expect(screen.queryByRole("dialog", { name: "添加拦截规则" })).toBeNull();
    expect(await screen.findByText("blocked.example")).toBeTruthy();
    expect(await screen.findByText(/规则已添加，但保护配置重载失败/)).toBeTruthy();
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
