/**
 * Platform announcement CRUD. Notices are stored and read once in the platform
 * configuration authority, CONTROL_DATA. No tenant database participates in
 * announcement reads or writes. The operator-only authorization fence applies
 * to every operation; tenant-facing publication is a separate API concern.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope } from "../ports.js";
import { adminDeleted, adminItem, listResponse, parseListQuery } from "../responses.js";
import {
  type AnnouncementInput,
  type AnnouncementPatch,
  PlatformAnnouncementStore,
} from "../store/platform-announcement.js";
import { isMissingPlatformCatalogError } from "../store/platform-model-catalog.js";
import { matchesSearch } from "../store/query.js";
import {
  TenantCatalogConflictError,
  TenantCatalogNotFoundError,
  TenantCatalogValidationError,
} from "../store/tenant-model-catalog.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

const unixTimestamp = z.number().int().nonnegative().nullable();

const announcementCreateSchema = z
  .object({
    id: z.string().trim().min(1).optional(),
    title: z.string().trim().min(1),
    body: z.string().trim().min(1),
    level: z.string().trim().min(1).optional(),
    enabled: z.boolean().optional(),
    starts_at_unix: unixTimestamp.optional(),
    ends_at_unix: unixTimestamp.optional(),
  })
  .strict();

const announcementPatchSchema = z
  .object({
    title: z.string().trim().min(1).optional(),
    body: z.string().trim().min(1).optional(),
    level: z.string().trim().min(1).optional(),
    enabled: z.boolean().optional(),
    starts_at_unix: unixTimestamp.optional(),
    ends_at_unix: unixTimestamp.optional(),
  })
  .strict();

/** The platform configuration singleton is the sole announcement authority. */
function announcementStore(c: Parameters<Handler>[0]): PlatformAnnouncementStore {
  const deps = depsOf(c);
  if (deps.controlDatabase === null) {
    throw new HttpError(
      503,
      "control_database_unavailable",
      "control database is required for platform announcements",
    );
  }
  return new PlatformAnnouncementStore({
    db: deps.controlDatabase,
    requestId: c.get("requestId") ?? null,
  });
}

/**
 * The leak-proof platform fence: a tenant-scoped caller gets `404`, not `403`,
 * so a probe cannot distinguish "you may not" from "there is no such notice".
 */
function platformScope(c: Parameters<Handler>[0]): CallerScope {
  const scope = scopeOf(c);
  if (scope.kind === "tenant") {
    throw new HttpError(404, "not_found", "announcement not found");
  }
  return scope;
}

/** Map the store's typed errors onto HTTP, exactly as the billing-group handler does. */
function announcementHandler(handler: Handler): Handler {
  return async (c) => {
    try {
      return await handler(c);
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) {
        throw new HttpError(
          503,
          "control_database_unavailable",
          "the platform announcement schema is not applied to the control database yet",
        );
      }
      if (error instanceof TenantCatalogNotFoundError) {
        throw new HttpError(404, "not_found", error.message);
      }
      if (error instanceof TenantCatalogConflictError) {
        throw new HttpError(409, "announcement_conflict", error.message);
      }
      if (error instanceof TenantCatalogValidationError) {
        throw new HttpError(400, "invalid_request_body", error.message);
      }
      throw error;
    }
  };
}

async function listAnnouncements(c: Parameters<Handler>[0]): Promise<Response> {
  platformScope(c);
  const deps = depsOf(c);
  const announcements = await announcementStore(c).listAnnouncements();
  const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
  // Same `?search=`/`?q=` contract every `pageOf`-backed collection honors; the
  // total is post-filter so the page count matches what the caller sees.
  const matched = announcements.filter((announcement) => matchesSearch(announcement, query.search));
  const page = query.paginate ? matched.slice(query.offset, query.offset + query.limit) : matched;
  return json(c, 200, listResponse({ items: page, total: matched.length }, query));
}

async function createAnnouncement(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = platformScope(c);
  const body = await readJson(c, announcementCreateSchema);
  const input: AnnouncementInput = {
    id: body.id ?? crypto.randomUUID(),
    title: body.title,
    body: body.body,
    level: body.level,
    enabled: body.enabled,
    startsAtUnix: body.starts_at_unix ?? null,
    endsAtUnix: body.ends_at_unix ?? null,
  };
  const record = await announcementStore(c).createAnnouncement(scope, input);
  return json(c, 201, adminItem("announcement", record));
}

async function getAnnouncement(c: Parameters<Handler>[0]): Promise<Response> {
  platformScope(c);
  const id = pathParam(c, "id");
  const record = await announcementStore(c).getAnnouncement(id);
  if (record === null) throw new HttpError(404, "not_found", `announcement ${id} not found`);
  return json(c, 200, adminItem("announcement", record));
}

async function patchAnnouncement(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = platformScope(c);
  const id = pathParam(c, "id");
  const body = await readJson(c, announcementPatchSchema);
  // Translate the wire snake_case timestamps onto the store's camelCase patch,
  // touching only the keys the caller actually sent (a `hasOwn` contract): a
  // spread of `undefined` would still create the key, so each is conditional.
  const patch: AnnouncementPatch = {
    ...("title" in body ? { title: body.title } : {}),
    ...("body" in body ? { body: body.body } : {}),
    ...("level" in body ? { level: body.level } : {}),
    ...("enabled" in body ? { enabled: body.enabled } : {}),
    ...("starts_at_unix" in body ? { startsAtUnix: body.starts_at_unix ?? null } : {}),
    ...("ends_at_unix" in body ? { endsAtUnix: body.ends_at_unix ?? null } : {}),
  };
  const record = await announcementStore(c).updateAnnouncement(scope, id, patch);
  return json(c, 200, adminItem("announcement", record));
}

async function deleteAnnouncement(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = platformScope(c);
  const id = pathParam(c, "id");
  const deleted = await announcementStore(c).deleteAnnouncement(scope, id);
  if (!deleted) throw new HttpError(404, "not_found", `announcement ${id} not found`);
  return json(c, 200, adminDeleted("announcement", id));
}

export const adminAnnouncementRoutes: GroupModule = crudGroup("admin_announcement", [], {
  listAnnouncements: announcementHandler(listAnnouncements),
  createAnnouncement: announcementHandler(createAnnouncement),
  getAnnouncement: announcementHandler(getAnnouncement),
  patchAnnouncement: announcementHandler(patchAnnouncement),
  deleteAnnouncement: announcementHandler(deleteAnnouncement),
});
