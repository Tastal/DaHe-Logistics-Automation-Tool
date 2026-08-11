import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AppServices } from "../../app/contracts";
import { CredentialSettings } from "./CredentialSettings";

describe("Credential settings", () => {
  it("saves and deletes Chengfeng credentials without echoing the password", async () => {
    const load = vi.fn(async () => ({
      configured: false,
      maskedUsername: null,
      recordVersion: 0,
    }));
    const save = vi.fn(async () => ({
      configured: true,
      maskedUsername: "13*******88",
      recordVersion: 1,
    }));
    const remove = vi.fn(async () => ({
      configured: false,
      maskedUsername: null,
      recordVersion: 2,
    }));
    const services = {
      loadPlatformCredentials: load,
      savePlatformCredentials: save,
      deletePlatformCredentials: remove,
    } as unknown as AppServices;

    render(<CredentialSettings services={services} />);
    const user = userEvent.setup();

    expect(await screen.findByLabelText("成丰账号")).toHaveValue("");
    await user.type(screen.getByLabelText("成丰账号"), "13800138088");
    await user.type(screen.getByLabelText("成丰密码"), "secret-value");
    await user.click(screen.getByRole("button", { name: "保存登录信息" }));

    expect(save).toHaveBeenCalledWith({
      username: "13800138088",
      password: "secret-value",
      expectedRecordVersion: 0,
    });
    expect(screen.queryByDisplayValue("secret-value")).not.toBeInTheDocument();
    expect(await screen.findByDisplayValue("13*******88")).toBeVisible();

    await user.click(screen.getByRole("button", { name: "删除登录信息" }));
    expect(remove).toHaveBeenCalledWith(1);
    await waitFor(() => expect(screen.getByLabelText("成丰账号")).toHaveValue(""));
    expect(screen.queryByRole("button", { name: "删除登录信息" })).not.toBeInTheDocument();
  });

  it("does not render a password when loading configured metadata", async () => {
    const services = {
      loadPlatformCredentials: vi.fn(async () => ({
        configured: true,
        maskedUsername: "fi********er",
        recordVersion: 4,
      })),
    } as unknown as AppServices;

    render(<CredentialSettings services={services} />);

    expect(await screen.findByDisplayValue("fi********er")).toBeVisible();
    expect(screen.getByLabelText("成丰密码")).toHaveValue("");
  });
});
