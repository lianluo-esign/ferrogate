import { HttpError } from "../middleware/errors.js";
import type { GroupModule, Handler } from "./resource.js";

const retired: Handler = () => {
  throw new HttpError(410, "feature_retired", "Agent scheduling has been retired.");
};

export const adminAgentScheduleRoutes: GroupModule = {
  group: "admin_agent_schedule",
  build: (operations) => new Map(operations.map((operation) => [operation.operationId, retired])),
};
