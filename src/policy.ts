export const POLICY_PRIORITY = {
  integrity: 10,
  security: 20,
  parentBlock: 30,
  parentAllow: 40,
  coreContent: 50,
  optionalContent: 60,
  subscription: 70,
  proxyRouting: 80,
} as const;

export type AccessObservation = {
  domain?: string;
  targetIp: string;
  matchedIpRule: boolean;
};

export function classifyUnknownIp(observation: AccessObservation) {
  if (observation.domain || observation.matchedIpRule) return "normal";
  return "warning";
}
