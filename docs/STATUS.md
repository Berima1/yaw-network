# Status

This file records only what has actually been checked. Update it every time something changes. Dates are 2026-10-03 unless stated.

## Verified (by running a command or reading the real system)

| Item | Result |
|---|---|
| GitHub repo `Berima1/yaw-network`, `main` | Old `backend/server.js` cannot start: it uses `redis` without importing it, requires `./yaw-blockchain-core` (file is `src/blockchain/core.js`), and `elliptic` is missing from `package.json`. |
| Render (account "My Workspace") | The service `yaw-network-1` from the original dashboard is **not** in this account. `yaw-network-api` (repo `yaw-network2`) exited with code 1 repeatedly in April-May 2026. Three Docker services never produced a deploy. |
| Old `Dockerfile` | Line 1 (`BLOCKCHAIN DOCKERFILE`) is not a valid instruction, so the build fails. |
| Vercel | No YAW frontend in recent deployments (only `okada-online`). |
| Google Cloud project | `yaw-network-prod` created (project number 169601424993). The account has no organisation. |
| Google Cloud billing | **Not linked** to `yaw-network-prod`. Enabling Cloud Run, Cloud Build, Artifact Registry and Secret Manager failed with a billing error. |
| Firestore location | `africa-south1` (Johannesburg) is a valid Firestore location in `gcloud firestore locations list`. |

## NOT verified yet (do not assume these work)

| Item | Why |
|---|---|
| **Any test in `backend/test`** | No test has been executed. The code was written without a runtime. A first run will probably find mistakes. |
| Install of the npm dependencies and their versions | `package-lock.json` does not exist yet. |
| Firestore transaction behaviour under the emulator and in production | Not run. |
| Docker image build | Not run. |
| Cloud Run deploy, Cloud Scheduler, Secret Manager wiring | Blocked on billing; the RUNBOOK commands are unexecuted. |
| Latency from Ghana to `africa-south1` vs other regions | Not measured. |

## Attempts that failed (so nobody repeats them blindly)

- Pushing `.github/workflows/*` through the GitHub connector returns 403 ("Resource not accessible by integration"): the connector's token cannot write workflow files. The workflow is stored at `docs/ci/backend-ci.yml` instead; the repo owner must copy it to `.github/workflows/`.
- A Vercel sandbox was created to run the tests, but command execution then returned "No approval received", so no tests ran there. The sandbox was non-persistent and expires on its own.
- Commit `b225600` accidentally added a junk file (`backend/test/__placeholder__`). It was removed in `c462dca`. The history is kept on purpose.

## Next steps, in order

1. Link billing to `yaw-network-prod` (console, one click).
2. Run the tests for real (GitHub Actions via `docs/ci/backend-ci.yml`, or Cloud Build), fix whatever fails, record the real result here.
3. Commit `package-lock.json`.
4. Create the Firestore database, service account, secrets, Artifact Registry repo (RUNBOOK sections 2-6).
5. Build, deploy to Cloud Run, run the smoke test (RUNBOOK section 8) against the real URL, record the result here.
6. Cloud Scheduler for block production (or keep `INSTANT_BLOCKS=true`).
7. Migrate the frontend to the new API (separate change).
8. Only then: open the PR to `main`.
