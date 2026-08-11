import { describe, expect, it, vi } from "vitest";

import {
  applyLocalApiOriginHeader,
  LOCAL_API_ORIGIN,
} from "../../vite.config";

describe("Vite local API proxy", () => {
  it("rewrites Origin to the fixed local backend origin", () => {
    const setHeader = vi.fn();

    applyLocalApiOriginHeader({ setHeader });

    expect(setHeader).toHaveBeenCalledWith("Origin", LOCAL_API_ORIGIN);
    expect(LOCAL_API_ORIGIN).toBe("http://127.0.0.1:8877");
  });
});
