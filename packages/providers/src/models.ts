/**
 * Logical→physical model registry — port of `ferrogate-providers/src/models.rs`.
 *
 * `ModelRegistry.resolve` sorts fallback routes by priority → weight (desc) →
 * provider → provider_model, matching the Rust `resolve` tiebreak exactly.
 */

export type RoutingStrategy = "Priority" | "LowestCost" | "LowestLatency" | "Balanced";
export const DEFAULT_ROUTING_STRATEGY: RoutingStrategy = "Priority";

/** Closed vocabulary for capabilities declared by one physical model route. */
export type ModelCapability =
  | "Chat"
  | "Streaming"
  | "Vision"
  | "Images"
  | "Embeddings"
  | "Tools"
  | "StructuredOutput";

const CAPABILITY_STRINGS: Record<ModelCapability, string> = {
  Chat: "chat",
  Streaming: "streaming",
  Vision: "vision",
  Images: "images",
  Embeddings: "embeddings",
  Tools: "tools",
  StructuredOutput: "structured_output",
};

export const modelCapabilityAsStr = (capability: ModelCapability): string =>
  CAPABILITY_STRINGS[capability];

/** `FromStr` for `ModelCapability`; throws on an unknown capability name. */
export function modelCapabilityFromStr(value: string): ModelCapability {
  const entry = (Object.entries(CAPABILITY_STRINGS) as [ModelCapability, string][]).find(
    ([, name]) => name === value,
  );
  if (!entry) {
    throw new Error(
      `unknown model capability ${JSON.stringify(value)}; expected one of chat, streaming, vision, images, embeddings, tools, structured_output`,
    );
  }
  return entry[0];
}

export interface ModelRoute {
  provider: string;
  providerModel: string;
  inputPricePer1m?: number;
  outputPricePer1m?: number;
  priority: number;
  weight: number;
  capabilities: ModelCapability[];
  contextWindow?: number;
  region?: string;
}

/** `ModelRoute::new(provider, provider_model)` — priority 0, weight 1, no prices. */
export function newModelRoute(provider: string, providerModel: string): ModelRoute {
  return {
    provider,
    providerModel,
    inputPricePer1m: undefined,
    outputPricePer1m: undefined,
    priority: 0,
    weight: 1,
    capabilities: [],
    contextWindow: undefined,
    region: undefined,
  };
}

/** `ModelRoute::with_routing`. */
export function modelRouteWithRouting(
  provider: string,
  providerModel: string,
  inputPricePer1m: number | undefined,
  outputPricePer1m: number | undefined,
  priority: number,
  weight: number,
): ModelRoute {
  return {
    provider,
    providerModel,
    inputPricePer1m,
    outputPricePer1m,
    priority,
    weight,
    capabilities: [],
    contextWindow: undefined,
    region: undefined,
  };
}

export interface ModelRegistryEntry {
  name: string;
  primary: ModelRoute;
  fallbacks: ModelRoute[];
  capabilities: ModelCapability[];
  contextWindow?: number;
  inputPricePer1m?: number;
  outputPricePer1m?: number;
  routingStrategy: RoutingStrategy;
  enabled: boolean;
}

/** `ModelRegistryEntry::new` — a single enabled primary route. */
export function newModelRegistryEntry(
  name: string,
  provider: string,
  providerModel: string,
): ModelRegistryEntry {
  return {
    name,
    primary: newModelRoute(provider, providerModel),
    fallbacks: [],
    capabilities: [],
    contextWindow: undefined,
    inputPricePer1m: undefined,
    outputPricePer1m: undefined,
    routingStrategy: "Priority",
    enabled: true,
  };
}

export interface ResolvedModelRoute {
  logicalModel: string;
  routingStrategy: RoutingStrategy;
  primary: ModelRoute;
  fallbacks: ModelRoute[];
}

export type ModelRegistryErrorKind =
  | "EmptyModelName"
  | "DuplicateModel"
  | "ModelNotFound"
  | "ModelDisabled";

/** Port of the Rust `ModelRegistryError` enum. */
export class ModelRegistryError extends Error {
  override readonly name = "ModelRegistryError";
  readonly kind: ModelRegistryErrorKind;
  readonly modelName?: string;

  private constructor(kind: ModelRegistryErrorKind, modelName?: string) {
    super(kind === "EmptyModelName" ? "empty model name" : `${kind}: ${modelName}`);
    this.kind = kind;
    this.modelName = modelName;
  }

  static emptyModelName(): ModelRegistryError {
    return new ModelRegistryError("EmptyModelName");
  }
  static duplicateModel(name: string): ModelRegistryError {
    return new ModelRegistryError("DuplicateModel", name);
  }
  static modelNotFound(name: string): ModelRegistryError {
    return new ModelRegistryError("ModelNotFound", name);
  }
  static modelDisabled(name: string): ModelRegistryError {
    return new ModelRegistryError("ModelDisabled", name);
  }

  equals(other: ModelRegistryError): boolean {
    return this.kind === other.kind && this.modelName === other.modelName;
  }
}

/** Logical→physical registry. Construct via {@link ModelRegistry.create}. */
export class ModelRegistry {
  readonly #entries: Map<string, ModelRegistryEntry>;

  private constructor(entries: Map<string, ModelRegistryEntry>) {
    this.#entries = entries;
  }

  /** `ModelRegistry::new` — rejects empty and duplicate names (fail-closed). */
  static create(entries: Iterable<ModelRegistryEntry>): ModelRegistry {
    const map = new Map<string, ModelRegistryEntry>();
    for (const entry of entries) {
      if (entry.name.trim().length === 0) throw ModelRegistryError.emptyModelName();
      if (map.has(entry.name)) throw ModelRegistryError.duplicateModel(entry.name);
      map.set(entry.name, entry);
    }
    return new ModelRegistry(map);
  }

  /** Resolve a logical model, sorting fallbacks by priority→weight→provider→model. */
  resolve(logicalModel: string): ResolvedModelRoute {
    const entry = this.#entries.get(logicalModel);
    if (!entry) throw ModelRegistryError.modelNotFound(logicalModel);
    if (!entry.enabled) throw ModelRegistryError.modelDisabled(logicalModel);

    const fallbacks = [...entry.fallbacks].sort(
      (left, right) =>
        left.priority - right.priority ||
        right.weight - left.weight ||
        (left.provider < right.provider ? -1 : left.provider > right.provider ? 1 : 0) ||
        (left.providerModel < right.providerModel
          ? -1
          : left.providerModel > right.providerModel
            ? 1
            : 0),
    );

    return {
      logicalModel: entry.name,
      routingStrategy: entry.routingStrategy,
      primary: entry.primary,
      fallbacks,
    };
  }

  /** Enabled entries, sorted by name for a stable listing. */
  enabledModels(): ModelRegistryEntry[] {
    return [...this.#entries.values()]
      .filter((entry) => entry.enabled)
      .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  }

  get length(): number {
    return this.#entries.size;
  }

  isEmpty(): boolean {
    return this.#entries.size === 0;
  }
}
