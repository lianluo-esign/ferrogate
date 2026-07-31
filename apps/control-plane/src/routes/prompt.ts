/**
 * Contract group `prompt` (6 operations) — CRUD over
 * `/admin/v1/prompt-templates`.
 *
 * The DELETE operation is `archiveAdminPromptTemplate`, and the name is the
 * behaviour: Rust ARCHIVES a template rather than removing the row
 * (`state.rs::archive_prompt_template` sets `PromptTemplateStatus::Archived`;
 * `local.rs::handle_admin_prompt_template_archive` answers `200`). Rendered
 * requests reference the template version they used, so a hard delete would
 * orphan every one of them — and a template id that becomes free to re-mint is
 * a template id whose historical renders can be silently re-attributed to a
 * different document.
 *
 * Two details taken straight off the Rust handler that the generic delete
 * handler got wrong:
 *
 *  - **the response is `deleted: FALSE`.** Rust builds
 *    `AdminDeleteResponse { object: "prompt_template", id, deleted: false }`.
 *    The generic `adminDeleted` helper hard-codes `true`, which is right for
 *    every other collection in the app and wrong for exactly this one: a client
 *    that trusts `deleted: true` believes the row is gone, and it is not.
 *  - **the row survives the call**, carrying `status: "archived"` — the
 *    `PromptTemplateStatus` value from `@ferrogate/config`, not a string spelled
 *    afresh here.
 *
 * An already-archived template is a `409 prompt_template_reload_rejected`,
 * matching Rust's rejected fork: re-archiving is not a no-op success, because
 * "this call archived it" and "it was already archived" are different facts and
 * the second usually means the caller is acting on stale state.
 *
 * Archived templates leave the DEFAULT listing — they are no longer active
 * configuration — but stay addressable by id and reachable with
 * `?status=archived`, so the audit trail a render references is never
 * unreadable. Same shape as the lifecycle statuses elsewhere in the app: the row
 * is filtered, never destroyed.
 */
import { promptTemplateStatusSchema } from "@ferrogate/config";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { listResponse, parseListQuery } from "../responses.js";
import {
  type GroupModule,
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  scopeOf,
} from "./resource.js";

const PROMPT_TEMPLATES = "prompt-templates";

/** `PromptTemplateStatus::Archived`. */
export const PROMPT_TEMPLATE_ARCHIVED = "archived";

export const promptTemplateSchema = adminRecordSchema.extend({
  template: z.string().optional(),
  version: z.number().int().min(0).optional(),
  status: promptTemplateStatusSchema.optional(),
});

export const promptRoutes: GroupModule = crudGroup(
  "prompt",
  [{ segment: PROMPT_TEMPLATES, object: "prompt_template", body: promptTemplateSchema }],
  {
    /**
     * The default listing hides archived templates. A request that names a
     * status explicitly (`?status=archived`, `?status=active`) gets exactly what
     * it asked for — the caller's own filter always wins, so no row this app
     * stores is unreachable through its own API.
     */
    listAdminPromptTemplates: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
      if (query.filters.status !== undefined) {
        const asked = await deps.store.list(PROMPT_TEMPLATES, scope, query);
        return json(c, 200, listResponse(asked, query));
      }
      // The archived exclusion is applied BEFORE the page window, so `total`
      // counts what the caller can actually see and a page is never short.
      const page = await deps.store.list(PROMPT_TEMPLATES, scope, {
        ...query,
        paginate: false,
        offset: 0,
      });
      const active = page.items.filter((record) => record.status !== PROMPT_TEMPLATE_ARCHIVED);
      const items = query.paginate
        ? active.slice(query.offset, query.offset + query.limit)
        : active;
      return json(c, 200, listResponse({ items, total: active.length }, query));
    },

    archiveAdminPromptTemplate: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const id = pathParam(c, "id");

      const existing = await deps.store.get(PROMPT_TEMPLATES, scope, id);
      if (existing === null) {
        throw new HttpError(404, "not_found", `prompt template ${id} not found`);
      }
      if (existing.status === PROMPT_TEMPLATE_ARCHIVED) {
        throw new HttpError(
          409,
          "prompt_template_reload_rejected",
          `prompt template ${id} is already archived`,
        );
      }

      const stored = await deps.store.merge(PROMPT_TEMPLATES, scope, id, {
        status: PROMPT_TEMPLATE_ARCHIVED,
        archived_at: Math.floor(Date.now() / 1000),
      });
      if (stored === null) {
        throw new HttpError(404, "not_found", `prompt template ${id} not found`);
      }
      // Rust `AdminDeleteResponse { object, id, deleted: false }` — see the
      // module docblock for why `false` is load-bearing.
      return json(c, 200, { object: "prompt_template", id, deleted: false });
    },
  },
);
