/**
 * Which experiment a request belongs to, and which arm served it.
 *
 * PURE, and deliberately tiny: it reads the candidate list the resolver already
 * produced and answers two questions the rest of the slice is built on. All the
 * split *semantics* live in `@ferrogate/routing` (`experimentIdFor`), because
 * the reader in `apps/control-plane` has to compute the same id from the same
 * inputs and a second implementation here would eventually disagree with it.
 *
 * ## The control arm is the route that would have served with no split at all
 *
 * `resolveCandidates` returns the model's routes priority→weight ordered, with
 * the canary and the mirror in the list; `applyCanary` may then promote the
 * canary to the head and `servableCandidates` strips the mirror. So the control
 * is the first candidate that is NEITHER of those, taken from the list BEFORE
 * `applyCanary` runs — which is why {@link experimentAssignmentFor} is called on
 * `resolved` and not on the rolled list.
 *
 * A model with several fallbacks has exactly one control by this reading: the
 * primary. That is right — a failover leg is not an experiment arm, it is the
 * same arm having a bad minute, and counting it as a third population would
 * make the control's numbers depend on the provider's uptime.
 */
import { type ExperimentArm, experimentIdFor } from "@ferrogate/routing";
import type { PhysicalRoute } from "../inference/ports.js";

/** The split one logical model declares, with its id already computed. */
export interface ExperimentAssignment {
  readonly experimentId: string;
  readonly logicalModel: string;
  readonly control: PhysicalRoute;
  readonly canary?: PhysicalRoute | undefined;
  readonly shadow?: PhysicalRoute | undefined;
}

function identityOf(route: PhysicalRoute): { provider: string; providerModel: string } {
  return { provider: route.provider, providerModel: route.providerModel };
}

/**
 * The experiment this model's candidate list describes, or `null` when it
 * describes none.
 *
 * `null` is the overwhelmingly common answer — a model with no canary and no
 * shadow is not an experiment, and labelling its requests would put a
 * single-arm entry on the reporting surface for every model in the catalogue.
 */
export function experimentAssignmentFor(
  candidates: readonly PhysicalRoute[],
  logicalModel: string,
): ExperimentAssignment | null {
  const canary = candidates.find((route) => route.canaryPercent !== undefined);
  const shadow = candidates.find((route) => route.shadowPercent !== undefined);
  if (canary === undefined && shadow === undefined) return null;

  const control = candidates.find(
    (route) => route.canaryPercent === undefined && route.shadowPercent === undefined,
  );
  // A split with no primary is a misconfiguration the resolver would already
  // have refused, but a `null` here is still the honest answer: there is
  // nothing to compare the variant AGAINST, so there is no experiment.
  if (control === undefined) return null;

  const experimentId = experimentIdFor({
    logicalModel,
    control: identityOf(control),
    ...(canary === undefined ? {} : { canary: identityOf(canary) }),
    ...(shadow === undefined ? {} : { shadow: identityOf(shadow) }),
  });
  if (experimentId === null) return null;

  return {
    experimentId,
    logicalModel,
    control,
    ...(canary === undefined ? {} : { canary }),
    ...(shadow === undefined ? {} : { shadow }),
  };
}

/**
 * Which arm the route that actually answered belongs to.
 *
 * Compared by IDENTITY (`===`) rather than by provider/model equality: the
 * routes come out of one resolver call, so the served route is the same object
 * the assignment captured, and an equality comparison would mislabel a
 * deployment that declared the canary as the same provider/model pair as the
 * primary — a degenerate split, but one whose two arms must still not be
 * conflated.
 *
 * `shadow` is never returned here. A mirror is not servable
 * (`servableCandidates` strips it before eligibility), so no served response can
 * come from it; the shadow arm is recorded by its own writer in `./shadow.ts`'s
 * observer. Returning it from this function would mean the mirror had reached a
 * client, which is the one thing the whole shadow design forbids.
 */
export function servedArmFor(
  assignment: ExperimentAssignment,
  servedRoute: PhysicalRoute,
): Extract<ExperimentArm, "control" | "canary"> {
  return assignment.canary !== undefined && servedRoute === assignment.canary
    ? "canary"
    : "control";
}
