import type { BillingReportPublisher, MeteredCharge } from "./ports.js";

/** Settlement is already authoritative in the owning DO. No downstream copy. */
export class SettledBillingReportPublisher implements BillingReportPublisher {
  deliver(_charge: MeteredCharge): Promise<void> {
    return Promise.resolve();
  }
}

/** Explicit test collector; never selected by the production sink. */
export class InMemoryBillingReportPublisher implements BillingReportPublisher {
  readonly #delivered: MeteredCharge[] = [];
  #failure: Error | undefined;

  // eslint-disable-next-line @typescript-eslint/require-await -- the port is async.
  async deliver(charge: MeteredCharge): Promise<void> {
    if (this.#failure !== undefined) {
      throw this.#failure;
    }
    this.#delivered.push(charge);
  }

  /** Every charge accepted downstream, in order. */
  get delivered(): readonly MeteredCharge[] {
    return this.#delivered;
  }

  /** Simulate an unavailable downstream: every `deliver` rejects. */
  fail(reason = "billing downstream unavailable"): void {
    this.#failure = new Error(reason);
  }

  /** Downstream recovered. */
  recover(): void {
    this.#failure = undefined;
  }
}
