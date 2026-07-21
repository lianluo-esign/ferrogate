import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ResourceForm } from "@/components/resource/resource-form";
import { defaultFieldValues, type FieldConfig } from "@/lib/resource-config";

const fields: FieldConfig[] = [
  { name: "name", label: "Name", type: "text", required: true },
  { name: "size", label: "Size", type: "number" },
  { name: "tags", label: "Tags", type: "csv" },
  { name: "settings", label: "Settings", type: "json" },
  { name: "slug", label: "Slug", type: "text", createOnly: true },
];

function renderForm(overrides: Partial<Parameters<typeof ResourceForm>[0]> = {}) {
  const onSubmit = vi.fn().mockResolvedValue(undefined);
  const onCancel = vi.fn();
  render(
    <ResourceForm
      fields={fields}
      initialValues={defaultFieldValues(fields)}
      submitLabel="Create"
      onSubmit={onSubmit}
      onCancel={onCancel}
      {...overrides}
    />,
  );
  return { onSubmit, onCancel };
}

describe("ResourceForm", () => {
  it("submits typed payload: numbers coerced, csv split, json parsed, empties dropped", async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText("Name *"), "Sprocket");
    await user.type(screen.getByLabelText("Size"), "12");
    await user.type(screen.getByLabelText("Tags"), "a, b ,c");
    await user.type(screen.getByLabelText("Settings"), '{{"active": true}');
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(onSubmit).toHaveBeenCalledWith({
      name: "Sprocket",
      size: 12,
      tags: ["a", "b", "c"],
      settings: { active: true },
      // slug omitted: empty values are not sent
    });
    expect(screen.getByLabelText("Name *")).toHaveAttribute("name", "name");
    expect(screen.getByLabelText("Name *")).toHaveAttribute("autocomplete", "off");
    expect(screen.getByLabelText("Size")).toHaveAttribute("inputmode", "decimal");
  });

  it("shows a validation error (and does not submit) when a JSON field is invalid", async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText("Name *"), "Sprocket");
    await user.type(screen.getByLabelText("Settings"), "not-json");
    await user.click(screen.getByRole("button", { name: "Create" }));

    const error = await screen.findByRole("alert");
    expect(error).toHaveTextContent("Settings must be valid JSON");
    expect(error).toHaveFocus();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("surfaces onSubmit rejection (e.g. an ApiError from the gateway) as the form error", async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn().mockRejectedValue(new Error("slug already exists"));
    renderForm({ onSubmit });

    await user.type(screen.getByLabelText("Name *"), "Sprocket");
    await user.click(screen.getByRole("button", { name: "Create" }));

    const error = await screen.findByRole("alert");
    expect(error).toHaveTextContent("slug already exists");
    expect(error).toHaveFocus();
  });

  it("hides createOnly fields in edit mode and calls onCancel from the Cancel button", async () => {
    const user = userEvent.setup();
    const { onCancel } = renderForm({ isEdit: true, submitLabel: "Save changes" });

    expect(screen.queryByLabelText("Slug")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalled();
  });
});
