/**
 * The workerd-only surface of `@ferrogate/storage`: the Durable Object
 * classes and everything a Worker entry module re-exports.
 *
 * This barrel exists so `@ferrogate/storage/durable-objects` can name every
 * data-plane object class (`TenantDataObject`, one per tenant; `ControlDataObject`,
 * exactly one — Zero-D1 S1, #877; and `PlatformDataObject`, exactly one — Zero-D1
 * Plan B, the home for platform/unattributed evidence) without the package
 * export map pointing at one implementation file. Everything here imports
 * `cloudflare:workers` and resolves only under workerd; node-safe consumers
 * import from the package root instead.
 */
export * from "./tenant-data-object.js";
export * from "./control-data-object.js";
export * from "./platform-data-object.js";
