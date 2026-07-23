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

export const promptTemplatesConfig: ResourceConfig<AdminPromptTemplate> = {
  key: "prompt-templates",
  title: "Prompt templates",
  description: "Versioned, reusable prompts served through /v1/prompts/{id}/render.",
  basePath: "/admin/v1/prompt-templates",
  idField: "id",
  columns: [
    { key: "name", header: "Name" },
    { key: "model", header: "Model" },
    { key: "status", header: "Status" },
    { key: "active_revision", header: "Active revision" },
  ],
  fields: [
    { name: "id", label: "ID", type: "text", required: true, createOnly: true },
    { name: "name", label: "Name", type: "text", required: true },
    {
      name: "status",
      label: "Status",
      type: "select",
      options: [
        { label: "Draft", value: "draft" },
        { label: "Active", value: "active" },
        { label: "Archived", value: "archived" },
      ],
    },
    {
      name: "target",
      label: "Target",
      type: "select",
      options: [
        { label: "Chat completions", value: "chat_completions" },
        { label: "Responses", value: "responses" },
      ],
    },
    {
      name: "model",
      label: "Model",
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
      label: "Variables (JSON array)",
      type: "json",
      placeholder: '[{"name":"topic","required":true}]',
    },
    {
      name: "version",
      label: "New version (JSON)",
      type: "json",
      placeholder:
        '{"messages":[{"role":"system","content":"You are..."}],"temperature":0.7}',
      description: "Appends a new revision; omit to leave versions unchanged.",
    },
  ],
};
