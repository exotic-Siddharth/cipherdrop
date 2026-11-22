/**
 * The operator switches from GET /api/config (server-1, ops-3), loaded once at boot (main.tsx). Until it
 * answers, or when it fails, `config` is null and pages assume everything is allowed: the API enforces every
 * switch anyway (403 FEATURE_DISABLED), and a page that gets that answer marks the feature off here, so the
 * explanation shows from then on.
 */
import {
  FeatureDisabledDetailsSchema,
  PublicConfigSchema,
  type PublicConfig,
  type SwitchableFeature,
} from '@cipherdrop/shared';
import { create } from 'zustand';
import { api, isApiError } from '../lib/api';

interface ServerConfigState {
  config: PublicConfig | null;
  load(): Promise<void>;
  markDisabled(feature: SwitchableFeature): void;
}

export const useServerConfig = create<ServerConfigState>()((set, get) => ({
  config: null,
  async load() {
    try {
      // `anonymous`: public, so it does not wait for the boot refresh.
      const config = await api.get('/config', { schema: PublicConfigSchema, anonymous: true });
      set({ config });
    } catch {
      // Keep null: the pages fall back to the server's 403 FEATURE_DISABLED.
    }
  },
  markDisabled(feature) {
    const current = get().config ?? { anonymousUploads: true, registration: true };
    set({ config: { ...current, [feature]: false } });
  },
}));

/** The feature a 403 FEATURE_DISABLED names, or null for any other error. */
export function disabledFeature(err: unknown): SwitchableFeature | null {
  if (!isApiError(err) || err.code !== 'FEATURE_DISABLED') return null;
  const details = FeatureDisabledDetailsSchema.safeParse(err.details);
  return details.success ? details.data.feature : null;
}

/** Record the switch a 403 FEATURE_DISABLED reports; returns whether `err` was one. */
export function noteDisabledFeature(err: unknown): boolean {
  const feature = disabledFeature(err);
  if (feature) useServerConfig.getState().markDisabled(feature);
  return feature !== null;
}
