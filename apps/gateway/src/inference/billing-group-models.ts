import { resolveCandidates } from "./defaults.js";
import type { ModelResolver, PhysicalRoute } from "./ports.js";

/**
 * Restrict a model catalog to the exact provider row ids bound to one billing
 * group. Provider names and provider family/type ids are deliberately ignored:
 * neither is the foreign key stored by `platform_billing_group_providers`.
 */
export class BillingGroupModelResolver implements ModelResolver {
  readonly #source: ModelResolver;
  readonly #providerIds: ReadonlySet<string>;

  constructor(source: ModelResolver, providerIds: readonly string[]) {
    this.#source = source;
    this.#providerIds = new Set(providerIds);
  }

  #allows(route: PhysicalRoute): boolean {
    return route.providerId !== undefined && this.#providerIds.has(route.providerId);
  }

  resolve(model: string): PhysicalRoute | null {
    return this.candidates(model)[0] ?? null;
  }

  candidates(model: string): readonly PhysicalRoute[] {
    return resolveCandidates(this.#source, model).filter((route) => this.#allows(route));
  }

  catalog(): readonly PhysicalRoute[] {
    const visible: PhysicalRoute[] = [];
    for (const descriptor of this.#source.catalog()) {
      const candidate = this.candidates(descriptor.logicalModel)[0];
      if (candidate !== undefined) {
        visible.push(candidate);
      } else if (this.#allows(descriptor)) {
        // Preserve disabled descriptors so handlers can retain the existing
        // `model_disabled` distinction without exposing another provider.
        visible.push(descriptor);
      }
    }
    return visible;
  }
}
