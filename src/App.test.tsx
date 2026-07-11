// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App";

afterEach(cleanup);

describe("management actions", () => {
  it("opens an unlock dialog when the unlock button is clicked", async () => {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "解锁管理台" }));
    expect(screen.getByRole("dialog", { name: "家长身份验证" })).toBeTruthy();
  });

  it("navigates to rules and asks for unlock before adding a subscription", async () => {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "规则管理" }));
    expect(screen.getByRole("heading", { name: "规则来源" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "添加订阅" }));
    expect(screen.getByRole("dialog", { name: "家长身份验证" })).toBeTruthy();
  });

  it("unlocks and opens both subscription forms", async () => {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "解锁管理台" }));
    await userEvent.type(screen.getByLabelText("管理密码"), "parent-password");
    await userEvent.click(screen.getByRole("button", { name: "确认解锁" }));
    expect(screen.getByRole("button", { name: "锁定管理台" })).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "规则管理" }));
    await userEvent.click(screen.getByRole("button", { name: "添加订阅" }));
    expect(screen.getByRole("dialog", { name: "添加规则订阅" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "取消" }));

    await userEvent.click(screen.getByRole("button", { name: "代理节点" }));
    await userEvent.click(screen.getByRole("button", { name: "导入订阅" }));
    expect(screen.getByRole("dialog", { name: "添加代理订阅" })).toBeTruthy();
  });
});
