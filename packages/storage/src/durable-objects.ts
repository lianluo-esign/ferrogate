/**
 * The workerd-only surface of `@ferrogate/storage`: the Durable Object
 * classes and everything a Worker entry module re-exports.
 *
 * This barrel exists so `@ferrogate/storage/durable-objects` can name BOTH
 * data-plane object classes (`TenantDataObject`, one per tenant, and
 * `ControlDataObject`, exactly one — Zero-D1 S1, #877) without the package
 * export map pointing at one implementation file. Everything here imports
 * `cloudflare:workers` and resolves only under workerd; node-safe consumers
 * import from the package root instead.
 */
export * from "./tenant-data-object.js";
export * from "./control-data-object.js";
