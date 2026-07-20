import { describe, expect, it } from "vitest";

import { projectsConfig } from "@/resources/projects";
import { workspacesConfig } from "@/resources/workspaces";

// #326 shipped the project/workspace update+delete admin handlers, so the
// console completes their CRUD (previously create-only). The parent identifier
// is immutable server-side (400 on re-attribution), so it must be create-only.
describe("projects/workspaces CRUD config", () => {
  it("projects support edit and delete with an immutable tenant_id", () => {
    expect(projectsConfig.noEditDelete).toBeUndefined();
    expect(projectsConfig.noUpdate).toBeUndefined();
    expect(projectsConfig.noDelete).toBeUndefined();
    const tenantField = projectsConfig.fields.find((f) => f.name === "tenant_id");
    expect(tenantField?.createOnly).toBe(true);
  });

  it("workspaces support edit and delete with an immutable project_id", () => {
    expect(workspacesConfig.noEditDelete).toBeUndefined();
    expect(workspacesConfig.noUpdate).toBeUndefined();
    expect(workspacesConfig.noDelete).toBeUndefined();
    const projectField = workspacesConfig.fields.find((f) => f.name === "project_id");
    expect(projectField?.createOnly).toBe(true);
  });
});
