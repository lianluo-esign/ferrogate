import { expect, it } from "vitest";
import worker from "../src/worker.js";
it("keeps HTTP and maintenance cron but retires the schedule queue handler", () => {
  expect(typeof worker.fetch).toBe("function");
  expect(typeof worker.scheduled).toBe("function");
  expect(worker.queue).toBeUndefined();
});
