// Bounded, visibility-aware polling (issue #343).
//
// The cockpit refreshes the control-plane overview on an interval, but a
// background tab must NOT keep polling: it wastes the operator's quota and the
// gateway's aggregate budget for a view nobody is looking at. This hook drives a
// single `setInterval` that ticks only while the document is visible, PAUSES
// (clears the interval outright) when the tab is hidden, RESUMES on return, and
// tears both the interval and the `visibilitychange` listener down on unmount —
// so an unmounted cockpit never fires another poll.
import { useEffect, useRef } from "react";

/**
 * Invoke `callback` every `intervalMs` while the document is visible.
 *
 * - Pauses when the tab is hidden and resumes when it is shown again, so a
 *   backgrounded cockpit stops polling instead of throttling silently.
 * - `enabled` gates the whole loop (e.g. off while the first load is in flight).
 * - The latest `callback` is always used without restarting the interval, so a
 *   changing closure never resets the cadence.
 */
export function useVisibilityPolling(
  callback: () => void,
  intervalMs: number,
  enabled = true,
): void {
  const savedCallback = useRef(callback);
  savedCallback.current = callback;

  useEffect(() => {
    if (!enabled || intervalMs <= 0) return;

    let timer: ReturnType<typeof setInterval> | undefined;

    const isHidden = (): boolean =>
      typeof document !== "undefined" && document.visibilityState === "hidden";

    const start = (): void => {
      if (timer !== undefined) return;
      timer = setInterval(() => {
        // Belt-and-suspenders: never fire a tick that raced the hidden state.
        if (!isHidden()) savedCallback.current();
      }, intervalMs);
    };

    const stop = (): void => {
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
    };

    const onVisibilityChange = (): void => {
      if (isHidden()) stop();
      else start();
    };

    if (!isHidden()) start();
    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [intervalMs, enabled]);
}
