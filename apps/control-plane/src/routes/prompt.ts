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
import {
  PromptLabelError,
  type PromptLabelPointer,
  normalizePromptLabel,
  promptLabelPointerKey,
  promptTemplateStatusSchema,
} from "@ferrogate/config";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope, StoreRecord } from "../ports.js";
import { adminDeleted, adminList, listResponse, parseListQuery } from "../responses.js";
import {
  type GroupModule,
  adminRecordSchema,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

/**
 * PORT-TODO(P: inventory-edge-control §4 config-backed collections) — the templates
 * stored here are not the templates rendered.
 * `apps/gateway/src/routes/prompts.ts` resolves `renderPromptTemplate` from the
 * deploy-time `GATEWAY_PROMPT_TEMPLATES` var, not from these documents. See the
 * full statement of the split (and the two ways to close it) on
 * `routes/admin_agent_upstream.ts`.
 */
const PROMPT_TEMPLATES = "prompt-templates";

/** `PromptTemplateStatus::Archived`. */
export const PROMPT_TEMPLATE_ARCHIVED = "archived";

export const promptTemplateSchema = adminRecordSchema.extend({
  template: z.string().optional(),
  version: z.number().int().min(0).optional(),
  status: promptTemplateStatusSchema.optional(),
});

// ---------------------------------------------------------------------------
// Deployment labels (#694)
// ---------------------------------------------------------------------------

/**
 * The label RECORD collection.
 *
 * A label is stored TWICE and the two copies are not redundant:
 *
 *  - here, as a normal admin document, so it is listable, tenant-fenced by the
 *    store, and survives a KV namespace being re-provisioned;
 *  - in KV, as the pointer `apps/gateway` reads on the inference hot path.
 *
 * The document is the record of intent; the pointer is the thing that takes
 * effect. Keeping only the pointer would make the label invisible to the admin
 * surface, and keeping only the document would put a D1 query in front of every
 * inference request that names a prompt.
 */
const PROMPT_TEMPLATE_LABELS = "prompt-template-labels";

/** `{ revision }` — the only field a label carries. */
const promptLabelBodySchema = z
  .object({
    revision: z
      .number()
      .int("revision must be a whole number")
      .positive("revision must be 1 or greater"),
  })
  .strict();

/**
 * The store id for one label.
 *
 * `::` rather than a single separator character because a template id may
 * legitimately contain `:` — the pair is not a security boundary (the STORE
 * enforces the tenant fence, and the KV key derivation escapes its components),
 * only a collision-avoidance convention within one tenant's namespace.
 */
function labelRecordId(templateId: string, label: string): string {
  return `${templateId}::${label}`;
}

/**
 * The label key space a template's labels live in.
 *
 * Taken from the TEMPLATE, not from the caller. For a tenant-scoped caller the
 * two are always the same value — the store fence guarantees a tenant can only
 * resolve its own rows — so this changes nothing about the fence. It decides
 * the one case where they differ: a PLATFORM OPERATOR acting on a tenant's
 * template writes into THAT TENANT's space, which is what makes the change
 * visible to the tenant's traffic. Keying on the caller instead would let an
 * operator "move production" and have the tenant's requests never see it.
 *
 * `null` — an un-attributed platform template — is its own space, reached only
 * by requests that carry no tenant.
 */
function labelTenantId(template: StoreRecord): string | null {
  const tenantId = template.tenant_id;
  return typeof tenantId === "string" && tenantId !== "" ? tenantId : null;
}

/**
 * Normalize a `{label}` path segment, or refuse.
 *
 * `400 invalid_prompt_label` rather than the generic `404 not_found`
 * {@link pathParam} gives a malformed segment: an operator who typed
 * `Production!` needs to be told the name is illegal, not that the label does
 * not exist — the second reading sends them looking for a missing resource.
 */
function labelParam(c: Parameters<typeof scopeOf>[0]): string {
  try {
    return normalizePromptLabel(decodeURIComponent(pathParam(c, "label")));
  } catch (error) {
    if (error instanceof PromptLabelError) {
      throw new HttpError(400, "invalid_prompt_label", error.message);
    }
    throw error;
  }
}

/**
 * Resolve the template a label belongs to, for THIS caller — the tenant fence.
 *
 * The lookup goes through the store, which is where the fence lives, so a
 * template owned by another tenant is a 404 and NOTHING downstream runs. That
 * ordering is the whole reason a label cannot be pointed into another tenant's
 * key space: the pointer write below is only ever reached with a template the
 * caller can already see, under a key derived from the caller's own scope.
 */
async function visibleTemplate(
  c: Parameters<typeof scopeOf>[0],
  scope: CallerScope,
  templateId: string,
): Promise<StoreRecord> {
  const existing = await depsOf(c).store.get(PROMPT_TEMPLATES, scope, templateId);
  if (existing === null) {
    throw new HttpError(404, "not_found", `prompt template ${templateId} not found`);
  }
  return existing;
}

/** The KV namespace, or a 503 that names the missing binding. */
function labelStore(
  c: Parameters<typeof scopeOf>[0],
): NonNullable<ReturnType<typeof depsOf>["promptLabels"]> {
  const kv = depsOf(c).promptLabels;
  if (kv === null) {
    // Deliberately NOT "write the document and report success": a label the
    // operator believes moved, that the gateway will never see, is a silent
    // failure of exactly the kind this feature exists to remove.
    throw new HttpError(
      503,
      "prompt_labels_unavailable",
      "prompt label storage is not configured (no PROMPT_LABELS KV binding)",
    );
  }
  return kv;
}

function pointerFor(
  tenantId: string | null,
  templateId: string,
  label: string,
  revision: number,
  subject: string | null,
  nowUnix: number,
): PromptLabelPointer {
  return {
    tenant_id: tenantId,
    template_id: templateId,
    label,
    revision,
    updated_at_unix: nowUnix,
    updated_by: subject,
  };
}

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

    // -----------------------------------------------------------------------
    // Deployment labels
    // -----------------------------------------------------------------------

    /**
     * `GET /admin/v1/prompt-templates/{id}/labels` — every label on ONE
     * template, in this caller's scope.
     *
     * Read from the DOCUMENT store, not from KV: a `list({prefix})` over KV is
     * eventually consistent and would show an operator a stale view of a change
     * they just made. The pointer is the hot-path read; the document is the
     * operator's read.
     */
    listAdminPromptTemplateLabels: async (c) => {
      const deps = depsOf(c);
      const scope = scopeOf(c);
      const templateId = pathParam(c, "id");
      await visibleTemplate(c, scope, templateId);

      const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
      const page = await deps.store.list(PROMPT_TEMPLATE_LABELS, scope, {
        ...query,
        paginate: false,
        offset: 0,
        // Forced regardless of what the client asked for — a label listing is
        // always about the template in the path.
        filters: { ...query.filters, template_id: templateId },
      });
      const labels = [...page.items].sort((a, b) =>
        String(a.label ?? "").localeCompare(String(b.label ?? "")),
      );
      return json(c, 200, adminList(labels));
    },

    /**
     * `PUT /admin/v1/prompt-templates/{id}/labels/{label}` — point a label at a
     * revision. THIS is the call that replaces a deploy.
     *
     * ## The write order, and why it is this way round
     *
     * Document FIRST, pointer SECOND. A crash between the two legs leaves a
     * label the operator can see whose pointer the edge has not adopted yet —
     * traffic keeps running the previous revision, and the next PUT heals it.
     * The reverse order would let traffic move to a revision no admin record
     * explains, which is the failure that is hard to even notice.
     *
     * ## What is deliberately NOT validated here
     *
     * That the revision EXISTS. This Worker stores admin documents; the
     * renderable revisions live in the gateway's operator table
     * (see the PORT-TODO at the top of this module), so a check here would be a
     * guess. The gateway refuses a pointer it cannot resolve with
     * `404 prompt_template_version_not_found` — loudly, at the edge, rather
     * than by rendering something else.
     */
    putAdminPromptTemplateLabel: async (c) => {
      const deps = depsOf(c);
      const scope = scopeOf(c);
      const templateId = pathParam(c, "id");
      const label = labelParam(c);
      const { revision } = await readJson(c, promptLabelBodySchema);

      const template = await visibleTemplate(c, scope, templateId);
      if (template.status === PROMPT_TEMPLATE_ARCHIVED) {
        // A retired prompt must not be re-deployable by label — otherwise
        // archiving is not a lifecycle state, it is a suggestion.
        throw new HttpError(
          409,
          "prompt_template_inactive",
          `prompt template ${templateId} is archived`,
        );
      }

      // Resolved BEFORE the document write so an unconfigured deployment
      // refuses cleanly instead of leaving a record with no pointer.
      const kv = labelStore(c);

      const tenantId = labelTenantId(template);
      const nowUnix = Math.floor(Date.now() / 1000);
      const subject = c.get("auth")?.subject ?? null;
      const id = labelRecordId(templateId, label);
      const document: StoreRecord = {
        id,
        template_id: templateId,
        label,
        revision,
        updated_at_unix: nowUnix,
        updated_by: subject,
      };

      // Upsert. `replace` answers `null` for a row that does not exist OR is
      // not visible to `scope`; the template fence above already established
      // visibility, so `null` here means "first time this label is set".
      const stored =
        (await deps.store.replace(PROMPT_TEMPLATE_LABELS, scope, id, document)) ??
        (await deps.store.create(PROMPT_TEMPLATE_LABELS, scope, document));

      await kv.put(
        promptLabelPointerKey({ tenantId, templateId, label }),
        JSON.stringify(pointerFor(tenantId, templateId, label, revision, subject, nowUnix)),
      );

      return json(c, 200, {
        object: "prompt_template_label",
        prompt_template_label: { ...stored, tenant_id: tenantId },
      });
    },

    /**
     * `DELETE /admin/v1/prompt-templates/{id}/labels/{label}` — retire a label.
     *
     * Pointer FIRST, document SECOND: the mirror image of the PUT ordering, and
     * for the mirror-image reason. A crash between the legs leaves a recorded
     * label that no longer resolves at the edge, which fails LOUDLY on the next
     * request that names it. Removing the document first would leave a pointer
     * still steering traffic that no admin surface can see or withdraw.
     */
    deleteAdminPromptTemplateLabel: async (c) => {
      const deps = depsOf(c);
      const scope = scopeOf(c);
      const templateId = pathParam(c, "id");
      const label = labelParam(c);
      const template = await visibleTemplate(c, scope, templateId);

      const id = labelRecordId(templateId, label);
      // Resolved for THIS caller's scope before anything is removed, so a
      // label belonging to another tenant is a 404 and no key is touched.
      const existing = await deps.store.get(PROMPT_TEMPLATE_LABELS, scope, id);
      if (existing === null) {
        throw new HttpError(
          404,
          "not_found",
          `prompt label ${label} is not defined for prompt template ${templateId}`,
        );
      }

      const kv = labelStore(c);
      await kv.delete(
        promptLabelPointerKey({ tenantId: labelTenantId(template), templateId, label }),
      );
      await deps.store.remove(PROMPT_TEMPLATE_LABELS, scope, id);

      return json(c, 200, adminDeleted("prompt_template_label", label));
    },
  },
);
