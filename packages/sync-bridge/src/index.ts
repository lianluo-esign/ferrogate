/**
 * `@ferrogate/sync-bridge` — async fan-out / service-binding bridge.
 *
 * Replaces the Rust crate `ferrogate-sync-bridge`. The Rust crate existed only
 * to run async work from synchronous Pingora hooks; on Cloudflare everything is
 * already async, so this narrows to a thin Queues / Service-Bindings dispatch
 * helper.
 */
import type { Scope } from "@ferrogate/core";

/** An envelope forwarded across a Queue or Service Binding. */
export interface BridgeMessage<T = unknown> {
  scope: Scope;
  kind: string;
  payload: T;
}

/** Dispatches a message onward (Queue producer / Service Binding fetch). */
export interface BridgeDispatcher {
  send<T>(message: BridgeMessage<T>): Promise<void>;
}
