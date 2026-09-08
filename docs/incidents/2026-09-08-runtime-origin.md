# Runtime sandbox startup after Webflow hosting migration

Tracked in CRE-1961. Reports: Zendesk 1186580 (Lead Source) and 1187574 (Stroke Infotech, reported September 11 submission deadline).

The runtime template still required the retired CREATE SOMETHING coordinator origin after the Worker migrated to Webflow. A live probe of the repository-pinned old template returned HTTP 400 for the Webflow origin and HTTP 202 for the retired origin. The Worker translates this rejection into the reported runner_start HTTP 503. The old smoke probe also used the retired origin.

The template and Worker smoke probe now share a production origin constant. A regression checks that the Webflow origin starts the runner while the retired origin cannot reserve a launch. Authentication, one-shot execution, and evidence trust remain enforced.

Replacement template: `app-review-companion-runtime:25557986-745c-4bd9-80bd-ffbd665239fa`. The workerd launcher probe accepted launch, read back the sandbox with HTTP 200, deleted it with HTTP 204, and verified HTTP 404 afterward. This proves startup, not completion of a customer observation.

## Production promotion

The live Worker stores `E2B_RUNTIME_TEMPLATE_ID` as a secret binding. Updating the repository variable alone is insufficient: activate the exact reviewed template through that binding and verify a new production observation. Preserve unrelated Worker configuration and credentials. Previous Worker version: `68572f7c-b1b4-4892-b44c-30e40606d561`. Roll back to that version if the new template causes a regression; it retains the known startup issue, so rollback is containment rather than resolution.

## Support guidance

This is a Preflight runtime service failure, not evidence that either app failed review. Reauthorizing the site or changing Chrome profiles does not repair the coordinator mismatch. After activation, retry Run Webflow test using the saved settings; expired settings may need renewal. Keep the existing submission receipt and failed-run details.

No submission waiver or deadline extension is established by these reports. If runtime testing remains unavailable, the Marketplace team must decide an exception or alternate evidence path. A receipt is not approval and must not be presented as a completed browser test.
