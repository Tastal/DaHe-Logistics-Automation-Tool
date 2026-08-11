import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AppServices } from "../../app/contracts";
import type { RuntimeLogEvent } from "../../api/auditContracts";
import { SystemWorkspace } from "./SystemWorkspace";

function services(): AppServices {
  return {
    loadDiagnostics: vi.fn(async () => ({
      generatedAt: "2026-07-28T00:00:00+00:00",
      health: [],
      recentIssues: [],
    })),
    loadRuntimeLogs: vi.fn(async () => ({
      events: [
        {
          eventId: "1",
          createdAt: "2026-07-28T00:00:00+00:00",
          level: "info",
          source: "application",
          eventCode: "application_started",
          stream: "application",
          message: "<script>alert(1)</script>",
          diagnosticCode: null,
          jobId: null,
          workItemId: null,
        },
      ],
      earliestCursor: "1",
      latestCursor: "1",
      hasMoreOlder: false,
    })),
    subscribeRuntimeLogs: vi.fn(() => () => undefined),
  } as unknown as AppServices;
}

describe("System runtime diagnostics", () => {
  it("renders sanitized log text as text with terminal controls", async () => {
    const api = services();
    const { container } = render(
      <SystemWorkspace
        services={api}
        jobs={[]}
        resources={[]}
        section="diagnostics"
        onSectionChange={vi.fn()}
        onOpenTemplates={vi.fn()}
      />,
    );

    expect(await screen.findByText("<script>alert(1)</script>")).toBeVisible();
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByRole("button", { name: "暂停" })).toBeVisible();
    expect(screen.getByRole("button", { name: "复制可见日志" })).toBeVisible();
    expect(screen.getByRole("link", { name: "导出全部日志" })).toHaveAttribute(
      "href",
      "/api/v1/diagnostics/logs/export",
    );
    await waitFor(() => expect(api.subscribeRuntimeLogs).toHaveBeenCalled());
  });

  it("buffers live events while paused and releases them on continue", async () => {
    let listener: (event: RuntimeLogEvent) => void = () => undefined;
    const api = services();
    api.subscribeRuntimeLogs = vi.fn((_cursor, next) => {
      listener = next;
      return () => undefined;
    });
    const user = userEvent.setup();
    render(
      <SystemWorkspace
        services={api}
        jobs={[]}
        resources={[]}
        section="diagnostics"
        onSectionChange={vi.fn()}
        onOpenTemplates={vi.fn()}
      />,
    );
    await screen.findByText("<script>alert(1)</script>");
    await user.click(screen.getByRole("button", { name: "暂停" }));
    listener({
      eventId: "2",
      createdAt: "2026-07-28T00:00:01+00:00",
      level: "error",
      source: "worker",
      eventCode: "worker_failed",
      stream: "stderr",
      message: "worker stopped",
      diagnosticCode: "D-1",
      jobId: null,
      workItemId: null,
    });
    expect(await screen.findByText("1 条新日志")).toBeVisible();
    expect(screen.queryByText("worker stopped")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "继续" }));
    expect(await screen.findByText("worker stopped")).toBeVisible();
  });
});
