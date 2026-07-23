import { describe, expect, it } from "vitest";
import {
  clearDependentReferenceValues,
  resolveActiveReference,
  type EntityReferenceFieldConfig,
  type FieldConfig,
} from "@/lib/resource-config";

// #341: unit coverage for the scope-kind-driven reference mechanics that back
// the quota/policy scope pickers — target selection by a sibling field, and the
// dependent-value clearing that guarantees a stale (wrong-scope) selection can
// never survive a scope change or a parent (provider/tenant) change.

const scopeIdField: EntityReferenceFieldConfig = {
  name: "scope_id",
  label: "Scope ID",
  type: "entity",
  scopedReference: {
    field: "scope_type",
    byValue: {
      tenant: { target: "tenant-accounts", valueKey: "id", primaryLabelKey: "name" },
      project: { target: "projects", valueKey: "id", primaryLabelKey: "name" },
      workspace: { target: "workspaces", valueKey: "id", primaryLabelKey: "name" },
      key: { target: "virtual-keys", valueKey: "id", primaryLabelKey: "name" },
    },
  },
};

describe("resolveActiveReference (scope-kind switching)", () => {
  it("selects the target entity kind from the sibling scope field", () => {
    expect(resolveActiveReference(scopeIdField, { scope_type: "tenant" })?.target).toBe(
      "tenant-accounts",
    );
    expect(resolveActiveReference(scopeIdField, { scope_type: "project" })?.target).toBe(
      "projects",
    );
    expect(resolveActiveReference(scopeIdField, { scope_type: "workspace" })?.target).toBe(
      "workspaces",
    );
    expect(resolveActiveReference(scopeIdField, { scope_type: "key" })?.target).toBe(
      "virtual-keys",
    );
  });

  it("returns undefined (picker disabled) when the scope kind is unset or unknown", () => {
    expect(resolveActiveReference(scopeIdField, {})).toBeUndefined();
    expect(resolveActiveReference(scopeIdField, { scope_type: "" })).toBeUndefined();
    expect(resolveActiveReference(scopeIdField, { scope_type: "nonsense" })).toBeUndefined();
  });

  it("returns the fixed reference for a non-scoped entity field", () => {
    const fixed: EntityReferenceFieldConfig = {
      name: "model",
      label: "Model",
      type: "entity",
      reference: { target: "models", valueKey: "name", primaryLabelKey: "name" },
    };
    expect(resolveActiveReference(fixed, {})?.target).toBe("models");
  });
});

describe("clearDependentReferenceValues", () => {
  it("clears a scoped selection when its scope kind changes", () => {
    const fields: FieldConfig[] = [
      { name: "scope_type", label: "Scope type", type: "select" },
      scopeIdField,
    ];
    const next = clearDependentReferenceValues(
      fields,
      { scope_type: "tenant", scope_id: "tenant-1" },
      "scope_type",
    );
    // The tenant ID cannot linger once the scope kind moves to another entity.
    expect(next.scope_id).toBe("");
  });

  it("clears a provider-dependent multi model allowlist to an empty array and cascades", () => {
    const fields: FieldConfig[] = [
      { name: "provider", label: "Provider", type: "text" },
      {
        name: "models",
        label: "Models",
        type: "entities",
        reference: {
          target: "models",
          valueKey: "name",
          primaryLabelKey: "name",
          dependencies: [{ field: "provider", queryKey: "provider" }],
        },
      },
      {
        name: "fallback",
        label: "Fallback",
        type: "entity",
        reference: {
          target: "models",
          valueKey: "name",
          primaryLabelKey: "name",
          dependencies: [{ field: "models", queryKey: "model" }],
        },
      },
    ];
    const next = clearDependentReferenceValues(
      fields,
      { provider: "anthropic", models: ["a", "b"], fallback: "a" },
      "provider",
    );
    // Multi allowlist resets to [] (not ""), and the transitive dependent clears too.
    expect(next.models).toEqual([]);
    expect(next.fallback).toBe("");
  });

  it("leaves unrelated fields untouched", () => {
    const fields: FieldConfig[] = [
      { name: "scope_type", label: "Scope type", type: "select" },
      scopeIdField,
      { name: "rpm_limit", label: "RPM", type: "number" },
    ];
    const next = clearDependentReferenceValues(
      fields,
      { scope_type: "tenant", scope_id: "tenant-1", rpm_limit: 60 },
      "scope_type",
    );
    expect(next.rpm_limit).toBe(60);
  });
});
