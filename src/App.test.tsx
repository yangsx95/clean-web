// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { App } from "./App";

beforeEach(() => {
  window.sessionStorage.clear();
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
});
