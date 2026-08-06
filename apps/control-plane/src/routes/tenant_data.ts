import type { TenantDataExportPageResult } from "@ferrogate/storage";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import {
  type GroupModule,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

const operatorQueryRequestSchema = z
  .object({
    sql: z.string().min(1).max(100_000),
    params: z
      .array(z.union([z.string(), z.number(), z.null()]))
      .max(100)
      .optional(),
  })
  .strict();

const exportRequestSchema = z
  .object({
    export_id: z.string().trim().min(1).max(200).optional(),
    cursor: z.string().nullable().optional(),
    page_size: z.number().int().min(1).max(32).optional(),
    part: z.number().int().min(0).max(1_000_000).optional(),
  })
  .strict();

const restoreRequestSchema = z
  .object({
    bookmark: z.string().trim().min(1).optional(),
    timestamp_unix: z.number().int().nonnegative().optional(),
  })
  .strict()
  .refine(
    (body) => (body.bookmark === undefined) !== (body.timestamp_unix === undefined),
    "provide exactly one of bookmark or timestamp_unix",
  );

function requirePlatformOperator(c: Parameters<typeof scopeOf>[0]): void {
  if (scopeOf(c).kind !== "platform_operator") {
    throw new HttpError(
      403,
      "platform_operator_required",
      "this tenant-data operation requires a platform operator",
    );
  }
}

function requireTenantExportScope(c: Parameters<typeof scopeOf>[0], tenantId: string): void {
  const scope = scopeOf(c);
  if (scope.kind !== "platform_operator" && scope.tenantId !== tenantId) {
    throw new HttpError(403, "tenant_scope_denied", "API key cannot export another tenant's data");
  }
}

function objectOperator(c: Parameters<typeof depsOf>[0]) {
  const operator = depsOf(c).tenantObjectOperator;
  if (operator === undefined || operator === null) {
    throw new HttpError(
      503,
      "tenant_data_unavailable",
      "TENANT_DATA is not bound on this control-plane deployment",
    );
  }
  return operator;
}

function reclassifyObjectError(error: unknown): never {
  const detail = error instanceof Error ? error.message : String(error);
  if (/operator query .*read-only SELECT|parse level|exactly one SQL statement/i.test(detail)) {
    throw new HttpError(400, "invalid_read_statement", "statement must be one read-only SELECT");
  }
  if (/operator export .*cursor|page size|export requires/i.test(detail)) {
    throw new HttpError(400, "invalid_export_request", "export page request is invalid");
  }
  if (/no usable bookmark/i.test(detail)) {
    throw new HttpError(
      409,
      "pitr_bookmark_unavailable",
      "no usable bookmark is retained for this tenant",
    );
  }
  throw error;
}

const queryTenantData = async (c: Parameters<typeof scopeOf>[0]) => {
  requirePlatformOperator(c);
  const tenantId = pathParam(c, "tenant_id");
  const body = await readJson(c, operatorQueryRequestSchema);
  const auth = c.get("auth");
  try {
    const result = await objectOperator(c).operatorQuery(tenantId, {
      ...body,
      auditId: `operator-query:${c.get("requestId")}`,
      requestId: c.get("requestId"),
      operator: auth?.subject ?? "platform_operator",
      occurredAtUnix: Math.floor(Date.now() / 1000),
    });
    return json(c, 200, {
      object: "tenant_data_query",
      tenant_id: tenantId,
      data: result.results,
      row_count: result.rowCount,
      audit_id: result.auditId,
    });
  } catch (error) {
    return reclassifyObjectError(error);
  }
};

const exportTenantData = async (c: Parameters<typeof scopeOf>[0]) => {
  const tenantId = pathParam(c, "tenant_id");
  requireTenantExportScope(c, tenantId);
  const body = await readJson(c, exportRequestSchema);
  const bucket = c.env.SIEM_EXPORTS;
  if (bucket === undefined) {
    throw new HttpError(503, "tenant_export_unavailable", "SIEM_EXPORTS is not bound");
  }
  const exportId = body.export_id ?? crypto.randomUUID();
  const part = body.part ?? 0;
  const auth = c.get("auth");
  let result: TenantDataExportPageResult;
  try {
    result = await objectOperator(c).operatorExportPage(tenantId, {
      exportId,
      cursor: body.cursor ?? null,
      pageSize: body.page_size ?? 32,
      auditId: `operator-export:${c.get("requestId")}:${exportId}:${part}`,
      requestId: c.get("requestId"),
      operator: auth?.subject ?? "tenant_export",
      occurredAtUnix: Math.floor(Date.now() / 1000),
    });
  } catch (error) {
    return reclassifyObjectError(error);
  }

  const prefix = `tenant-data-exports/${encodeURIComponent(tenantId)}/${encodeURIComponent(exportId)}`;
  const objectKey = `${prefix}/part-${String(part).padStart(8, "0")}.jsonl`;
  await bucket.put(objectKey, result.jsonl, {
    httpMetadata: { contentType: "application/x-ndjson; charset=utf-8" },
    customMetadata: { tenant_id: tenantId, export_id: exportId, format: "jsonl" },
  });

  let manifestKey: string | null = null;
  if (result.done) {
    manifestKey = `${prefix}/manifest.json`;
    await bucket.put(
      manifestKey,
      JSON.stringify({
        object: "tenant_data_export",
        tenant_id: tenantId,
        export_id: exportId,
        format: "jsonl",
        last_part: part,
        done: true,
      }),
      { httpMetadata: { contentType: "application/json; charset=utf-8" } },
    );
  }

  return json(c, 200, {
    object: "tenant_data_export_page",
    tenant_id: tenantId,
    export_id: exportId,
    format: "jsonl",
    rows: result.rowCount,
    next_cursor: result.nextCursor,
    done: result.done,
    object_key: objectKey,
    manifest_key: manifestKey,
    audit_id: result.auditId,
  });
};

const restoreTenantData = async (c: Parameters<typeof scopeOf>[0]) => {
  requirePlatformOperator(c);
  const tenantId = pathParam(c, "tenant_id");
  const body = await readJson(c, restoreRequestSchema);
  const auth = c.get("auth");
  try {
    const result = await objectOperator(c).operatorRestore(tenantId, {
      bookmark: body.bookmark,
      timestampUnix: body.timestamp_unix,
      auditId: `operator-restore:${c.get("requestId")}`,
      requestId: c.get("requestId"),
      operator: auth?.subject ?? "platform_operator",
      occurredAtUnix: Math.floor(Date.now() / 1000),
    });
    return json(c, 200, {
      object: "tenant_data_restore",
      tenant_id: tenantId,
      bookmark: result.bookmark,
      scheduled: result.scheduled,
      audit_id: result.auditId,
    });
  } catch (error) {
    return reclassifyObjectError(error);
  }
};

export const tenantDataRoutes: GroupModule = crudGroup("tenant_data", [], {
  queryTenantData,
  exportTenantData,
  restoreTenantData,
});
