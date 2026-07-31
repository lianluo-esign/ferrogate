/**
 * Incremental tool-call / function-call accumulation across streamed deltas.
 *
 * Clean-room port of the Rust `ToolCallAccumulator` (`messages_stream.rs`) and
 * `FunctionCallState` (`responses_stream.rs`). Both keep an index-keyed
 * `BTreeMap` — the map ordering matters, because the accumulated calls are
 * replayed in index order at end-of-stream — and both concatenate the
 * `function.arguments` string fragments the provider dribbles out one JSON
 * substring at a time.
 *
 * The two Rust sites differ in exactly one respect: the fallback index used
 * when a `tool_calls[]` element omits `index`. `messages_stream.rs` uses the
 * element's position within the array; `responses_stream.rs` uses
 * `choice_index + tool_index`. That is modelled here by `baseIndex`.
 */
import { asArray, asString, asUint, get, getString } from "./values.js";

/** Accumulated state for one tool call. */
export interface ToolCallState {
  /** Provider-assigned slot (the `index` field, or the positional fallback). */
  readonly index: number;
  /** `id` — absent until the provider sends the frame that carries it. */
  readonly id?: string | undefined;
  /** `function.name` — likewise arrives once, usually on the opening frame. */
  readonly name?: string | undefined;
  /** Concatenation of every `function.arguments` fragment seen so far. */
  readonly arguments: string;
}

/** One tool-call element observed in a single delta frame. */
export interface ToolCallUpdate {
  /** Slot this element addressed. */
  readonly index: number;
  /** State of the slot *after* applying this element. */
  readonly state: ToolCallState;
  /**
   * The `function.arguments` fragment carried by this element — `""` when the
   * element only introduced `id`/`name`. Both Rust normalizers emit an
   * argument delta event only for a non-empty fragment.
   */
  readonly argumentsDelta: string;
  /** True the first time this slot is seen (the normalizers open a block). */
  readonly opened: boolean;
}

interface MutableState {
  index: number;
  id: string | undefined;
  name: string | undefined;
  arguments: string;
}

/**
 * Index-keyed tool-call accumulator.
 *
 * Insertion-ordered `Map` plus an explicit numeric sort in {@link snapshot}
 * reproduces the Rust `BTreeMap` ordering (providers may open slot 1 before
 * slot 0 when parallel tool calls interleave).
 */
export class ToolCallAccumulator {
  readonly #calls = new Map<number, MutableState>();

  /** Number of distinct tool-call slots seen. */
  get size(): number {
    return this.#calls.size;
  }

  /** True when no tool call has been observed (Rust `is_empty`). */
  get isEmpty(): boolean {
    return this.#calls.size === 0;
  }

  /** State for one slot. */
  get(index: number): ToolCallState | undefined {
    const state = this.#calls.get(index);
    return state === undefined ? undefined : { ...state };
  }

  /**
   * Apply one OpenAI `delta.tool_calls[]` array.
   *
   * `baseIndex` is added to the element position when the element omits an
   * explicit `index` (0 for the messages normalizer, the choice index for the
   * responses normalizer).
   */
  applyToolCallDeltas(toolCalls: unknown, baseIndex = 0): ToolCallUpdate[] {
    const elements = asArray(toolCalls);
    if (elements === undefined) {
      return [];
    }
    const updates: ToolCallUpdate[] = [];
    for (let position = 0; position < elements.length; position += 1) {
      const element = elements[position];
      const index = asUint(get(element, "index")) ?? baseIndex + position;
      const opened = !this.#calls.has(index);
      const state = this.#entry(index);

      const id = getString(element, "id");
      if (id !== undefined) {
        state.id = id;
      }
      const fn = get(element, "function");
      let argumentsDelta = "";
      if (fn !== undefined) {
        const name = getString(fn, "name");
        if (name !== undefined) {
          state.name = name;
        }
        const fragment = asString(get(fn, "arguments"));
        if (fragment !== undefined && fragment.length > 0) {
          state.arguments += fragment;
          argumentsDelta = fragment;
        }
      }
      updates.push({ index, state: { ...state }, argumentsDelta, opened });
    }
    return updates;
  }

  /**
   * Apply the deprecated single-slot OpenAI `delta.function_call` object.
   * `responses_stream.rs` keys it by the choice index.
   */
  applyFunctionCallDelta(functionCall: unknown, index: number): ToolCallUpdate | undefined {
    if (functionCall === undefined || functionCall === null) {
      return undefined;
    }
    const opened = !this.#calls.has(index);
    const state = this.#entry(index);
    const id = getString(functionCall, "id");
    if (id !== undefined) {
      state.id = id;
    }
    const name = getString(functionCall, "name");
    if (name !== undefined) {
      state.name = name;
    }
    let argumentsDelta = "";
    const fragment = asString(get(functionCall, "arguments"));
    if (fragment !== undefined && fragment.length > 0) {
      state.arguments += fragment;
      argumentsDelta = fragment;
    }
    return { index, state: { ...state }, argumentsDelta, opened };
  }

  /**
   * Apply an already-decomposed fragment (used by the Anthropic and Gemini
   * branches of `extract_function_call_deltas`, which dig the pieces out of
   * provider-specific shapes before folding them into the same map).
   */
  applyFragment(input: {
    index: number;
    id?: string | undefined;
    name?: string | undefined;
    argumentsDelta?: string | undefined;
  }): ToolCallUpdate {
    const opened = !this.#calls.has(input.index);
    const state = this.#entry(input.index);
    if (input.id !== undefined) {
      state.id = input.id;
    }
    if (input.name !== undefined) {
      state.name = input.name;
    }
    let argumentsDelta = "";
    if (input.argumentsDelta !== undefined && input.argumentsDelta.length > 0) {
      state.arguments += input.argumentsDelta;
      argumentsDelta = input.argumentsDelta;
    }
    return { index: input.index, state: { ...state }, argumentsDelta, opened };
  }

  /** All accumulated calls in ascending index order (Rust `BTreeMap` order). */
  snapshot(): ToolCallState[] {
    return [...this.#calls.values()]
      .sort((left, right) => left.index - right.index)
      .map((state) => ({ ...state }));
  }

  /**
   * Render as the OpenAI `message.tool_calls` array the buffered
   * `chat_sse_to_completion` path produces (`id`/`name` default to `""`,
   * matching Rust `String::default`).
   */
  toOpenAiToolCalls(): {
    id: string;
    type: "function";
    function: { name: string; arguments: string };
  }[] {
    return this.snapshot().map((call) => ({
      id: call.id ?? "",
      type: "function" as const,
      function: { name: call.name ?? "", arguments: call.arguments },
    }));
  }

  #entry(index: number): MutableState {
    let state = this.#calls.get(index);
    if (state === undefined) {
      state = { index, id: undefined, name: undefined, arguments: "" };
      this.#calls.set(index, state);
    }
    return state;
  }
}
