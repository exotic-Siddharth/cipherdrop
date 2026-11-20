/**
 * GET /api/config: the operator switches the SPA needs before it sends anything (server-1, ops-3). Public, no
 * secrets: what this instance allows, never how full it is.
 */
import { z } from 'zod';

/** A feature an operator can switch off (`details.feature` of a 403 FEATURE_DISABLED). */
export const SwitchableFeatureSchema = z.enum(['anonymousUploads', 'registration']);
export type SwitchableFeature = z.infer<typeof SwitchableFeatureSchema>;

/** 403 FEATURE_DISABLED details. */
export const FeatureDisabledDetailsSchema = z.object({ feature: SwitchableFeatureSchema });
export type FeatureDisabledDetails = z.infer<typeof FeatureDisabledDetailsSchema>;

export const PublicConfigSchema = z.object({
  /** ALLOW_ANONYMOUS_UPLOADS: senders without an account may create drops. */
  anonymousUploads: z.boolean(),
  /** ALLOW_REGISTRATION: new accounts may be created. */
  registration: z.boolean(),
});
export type PublicConfig = z.infer<typeof PublicConfigSchema>;
