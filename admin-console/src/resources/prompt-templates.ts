import type { ResourceConfig } from "@/lib/resource-config";

export interface AdminPromptTemplate extends Record<string, unknown> {
  id: string;
  name: string;
  status: "draft" | "active" | "archived";
  target: "chat_completions" | "responses";
  model: string;
  active_revision: number | null;
  versions: unknown[];
}

// Per-resource operator copy migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey`/
// `descriptionKey`, and select-option `labelKey` resolve under the active
// locale. Resource IDs, field `name`s, option `value`s, and the JSON example
// placeholders (protected code/config values) stay data-driven. The
// description keeps the literal `/v1/prompts/{id}/render` API path; `{id}` is
// never interpolated (title/description are resolved with no values).
export const promptTemplatesConfig: ResourceConfig<AdminPromptTemplate> = {
  key: "prompt-templates",
  titleKey: "resource.promptTemplates.title",
  descriptionKey: "resource.promptTemplates.description",
  basePath: "/admin/v1/prompt-templates",
  idField: "id",
  columns: [
    { key: "name", headerKey: "resource.promptTemplates.col.name" },
    { key: "model", headerKey: "resource.promptTemplates.col.model" },
    { key: "status", headerKey: "resource.promptTemplates.col.status" },
    { key: "active_revision", headerKey: "resource.promptTemplates.col.activeRevision" },
  ],
  fields: [
    {
      name: "id",
      labelKey: "resource.promptTemplates.field.id",
      type: "text",
      required: true,
      createOnly: true,
    },
    { name: "name", labelKey: "resource.promptTemplates.field.name", type: "text", required: true },
    {
      name: "status",
      labelKey: "resource.promptTemplates.field.status",
      type: "select",
      options: [
        { labelKey: "resource.promptTemplates.option.status.draft", value: "draft" },
        { labelKey: "resource.promptTemplates.option.status.active", value: "active" },
        { labelKey: "resource.promptTemplates.option.status.archived", value: "archived" },
      ],
    },
    {
      name: "target",
      labelKey: "resource.promptTemplates.field.target",
      type: "select",
      options: [
        {
          labelKey: "resource.promptTemplates.option.target.chatCompletions",
          value: "chat_completions",
        },
        { labelKey: "resource.promptTemplates.option.target.responses", value: "responses" },
      ],
    },
    {
      name: "model",
      labelKey: "resource.promptTemplates.field.model",
      type: "entity",
      reference: {
        target: "models",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["provider", "provider_model"],
      },
    },
    {
      name: "variables",
      labelKey: "resource.promptTemplates.field.variables",
      type: "json",
      placeholder: '[{"name":"topic","required":true}]',
    },
    {
      name: "version",
      labelKey: "resource.promptTemplates.field.version",
      type: "json",
      placeholder: '{"messages":[{"role":"system","content":"You are..."}],"temperature":0.7}',
      descriptionKey: "resource.promptTemplates.field.version.desc",
    },
  ],
};
