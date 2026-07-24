import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useVisibilityPolling } from "@/hooks/use-visibility-polling";

function Harness({
  callback,
  intervalMs,
  enabled,
}: {
  callback: () => void;
  intervalMs: number;
  enabled?: boolean;
}) {
  useVisibilityPolling(callback, intervalMs, enabled);
  return null;
}

/** Force `document.visibilityState` and dispatch the matching event. */
function setVisibility(state: "visible" | "hidden") {
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    get: () => state,
  });
  document.dispatchEvent(new Event("visibilitychange"));
}

afterEach(() => {
  vi.useRealTimers();
  setVisibility("visible");
});

describe("useVisibilityPolling", () => {
  it("invokes the callback once per interval while visible", () => {
    vi.useFakeTimers();
    setVisibility("visible");
    const callback = vi.fn();

    render(<Harness callback={callback} intervalMs={1000} />);
    expect(callback).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1000);
    expect(callback).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(2000);
    expect(callback).toHaveBeenCalledTimes(3);
  });

  it("pauses while the tab is hidden and resumes when visible again", () => {
    vi.useFakeTimers();
    setVisibility("visible");
    const callback = vi.fn();

    render(<Harness callback={callback} intervalMs={1000} />);
    vi.advanceTimersByTime(1000);
    expect(callback).toHaveBeenCalledTimes(1);

    // Backgrounded: the interval is cleared, so no ticks accrue.
    setVisibility("hidden");
    vi.advanceTimersByTime(5000);
    expect(callback).toHaveBeenCalledTimes(1);

    // Foregrounded again: polling resumes on the same cadence.
    setVisibility("visible");
    vi.advanceTimersByTime(1000);
    expect(callback).toHaveBeenCalledTimes(2);
  });

  it("does not start when disabled", () => {
    vi.useFakeTimers();
    setVisibility("visible");
    const callback = vi.fn();

    render(<Harness callback={callback} intervalMs={1000} enabled={false} />);
    vi.advanceTimersByTime(5000);
    expect(callback).not.toHaveBeenCalled();
  });

  it("clears the interval and listener on unmount (no leaked polling)", () => {
    vi.useFakeTimers();
    setVisibility("visible");
    const callback = vi.fn();
    const removeSpy = vi.spyOn(document, "removeEventListener");

    const { unmount } = render(<Harness callback={callback} intervalMs={1000} />);
    vi.advanceTimersByTime(1000);
    expect(callback).toHaveBeenCalledTimes(1);

    unmount();
    expect(removeSpy).toHaveBeenCalledWith("visibilitychange", expect.any(Function));

    // After teardown the timer must be gone: advancing fires nothing more.
    vi.advanceTimersByTime(10_000);
    expect(callback).toHaveBeenCalledTimes(1);
    removeSpy.mockRestore();
  });
});
