import { EXPECTED_API_ORIGIN } from '../../../webflow-app-review-runtime-template/src/production-origin';
import { launchRuntimeObservationInE2B } from '../src/e2b-runtime-launcher';
import type { Env } from '../src/types';

interface ProbeEnv extends Env {
  PROBE_OBSERVATION_JOB_ID: string;
  PROBE_CAPABILITY: string;
  /** `boot_test` probes the Designer Extension boot test launch; absent probes an observation. */
  PROBE_JOB_KIND?: string;
}

export default {
  async fetch(_request: Request, env: ProbeEnv): Promise<Response> {
    const result = await launchRuntimeObservationInE2B(
      {
        observationJobId: env.PROBE_OBSERVATION_JOB_ID,
        apiBaseUrl: EXPECTED_API_ORIGIN,
        capability: env.PROBE_CAPABILITY,
        ...(env.PROBE_JOB_KIND === 'boot_test' ? { jobKind: 'boot_test' as const } : {})
      },
      env
    );
    return Response.json({ sandboxId: result.sandboxId });
  }
};
