/**
 * OpenAI Files lifecycle through the official SDK.
 *
 * The SDK owns multipart encoding, pagination response parsing, binary response
 * handling, and the delete/retrieve request shapes in this test. A hand-written
 * fetch would not prove those client-facing compatibility guarantees.
 */
import { describe, expect, it } from "vitest";

import { openaiClient } from "./harness.js";

describe("openai SDK - files", () => {
  it("uploads, lists, retrieves, reads, and deletes a file", async () => {
    const client = openaiClient();
    const contents = "hello from the official SDK";

    const created = await client.files.create({
      file: new File([contents], "notes.txt", { type: "text/plain" }),
      purpose: "assistants",
    });

    expect(created).toMatchObject({
      object: "file",
      filename: "notes.txt",
      purpose: "assistants",
      status: "processed",
    });
    expect(created.bytes).toBe(new TextEncoder().encode(contents).byteLength);

    const listed = await client.files.list({ purpose: "assistants" });
    expect(listed.data).toEqual(expect.arrayContaining([expect.objectContaining({ id: created.id })]));

    const retrieved = await client.files.retrieve(created.id);
    expect(retrieved).toEqual(created);

    const content = await client.files.content(created.id);
    expect(content.status).toBe(200);
    expect(content.headers.get("content-type")).toBe("text/plain");
    expect(await content.text()).toBe(contents);

    const deleted = await client.files.delete(created.id);
    expect(deleted).toEqual({ id: created.id, object: "file", deleted: true });
  });
});
