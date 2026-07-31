// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, constants shared by the two
// halves of the #424 PoC harness. Deliberately free of `node:` imports: the Node
// globalSetup serves these values and the workerd suite asserts them, so a
// proxied response that did not come from the stub upstream cannot pass.

/** The completion the stub upstream serves, verbatim. */
export const UPSTREAM_COMPLETION = {
  id: "chatcmpl_ferrogate_poc",
  object: "chat.completion",
  created: 1_700_000_000,
  model: "gpt-4o-mini",
  choices: [
    {
      index: 0,
      message: { role: "assistant", content: "pong from the PoC upstream" },
      finish_reason: "stop",
    },
  ],
  usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
};

/** Virtual key the harness config seeds. */
export const POC_VIRTUAL_KEY = "poc-virtual-key";

/** Model the harness config registers. */
export const POC_MODEL = "poc-chat";
