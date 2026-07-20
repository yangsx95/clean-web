// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
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
    expect(screen.getByRole("heading", { name: "规则来源" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "添加订阅" }));
    expect(screen.getByRole("dialog", { name: "添加规则订阅" })).toBeTruthy();
  });

  it("opens both subscription forms when unlocked", async () => {
    render(<App />);
    await unlockManagement();

    await userEvent.click(screen.getByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("button", { name: "添加订阅" }));
    expect(screen.getByRole("dialog", { name: "添加规则订阅" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "取消" }));

    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(screen.getByRole("button", { name: "导入订阅" }));
    expect(screen.getByRole("dialog", { name: "添加代理订阅" })).toBeTruthy();
  });

  it("does not allow default rule sources to be disabled or deleted", async () => {
    window.localStorage.setItem("cleanweb.preview.subscriptions", JSON.stringify([
      {id:"default:stevenblack:porn",kind:"rule",name:"默认源 · 色情内容",url:"https://example.test/default",format:"hosts",category:"pornography",enabled:true},
      {id:"custom-source",kind:"rule",name:"我的规则",url:"https://example.test/custom",format:"hosts",category:"custom",enabled:true},
    ]));
    render(<App />);
    await unlockManagement();
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));

    expect(screen.getByText("强制启用")).toBeTruthy();
    expect(screen.queryByRole("switch", { name: "默认源 · 色情内容订阅" })).toBeNull();
    expect(screen.queryByRole("button", { name: "删除默认源 · 色情内容" })).toBeNull();
    expect(screen.getByRole("switch", { name: "我的规则订阅" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "删除我的规则" })).toBeTruthy();
  });
});
