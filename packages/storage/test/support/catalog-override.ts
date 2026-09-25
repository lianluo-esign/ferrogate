/** Explicit tenant configuration, independent of the platform catalog. */
export async function seedCatalogOverride(db: D1Database, tenantId: string): Promise<void> {
  await db.batch([
    db
      .prepare(
        "INSERT INTO provider_channels (id, tenant_id, name, kind, base_url) VALUES (?, ?, 'tenant-provider', 'openai', 'https://tenant.example.test')",
      )
      .bind(`${tenantId}:provider`, tenantId),
    ...["gpt-4o", "gpt-5", "claude-opus-4"].flatMap((model) => [
      db
        .prepare("INSERT INTO catalog_models (id, tenant_id, name) VALUES (?, ?, ?)")
        .bind(`${tenantId}:model:${model}`, tenantId, model),
      db
        .prepare(
          "INSERT INTO catalog_model_offerings (id, tenant_id, model_id, provider_id, upstream_model_id, role, input_price_per_1m, source) VALUES (?, ?, ?, ?, ?, 'primary', 2.5, 'admin')",
        )
        .bind(
          `${tenantId}:offering:${model}`,
          tenantId,
          `${tenantId}:model:${model}`,
          `${tenantId}:provider`,
          model,
        ),
    ]),
    db
      .prepare(
        "INSERT INTO catalog_revisions (tenant_id, id, revision, updated_at_unix) VALUES (?, 1, 1, 1)",
      )
      .bind(tenantId),
  ]);
}
