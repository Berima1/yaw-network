# Status

This file records only what has actually been checked. Update it every time something changes.

## Verified (by running a command or reading the real system)

| Item | Result | Date |
|---|---|---|
| **Unit tests** (`npm run test:unit`) | **22 of 22 pass.** Node v24.21.0. | 2026-10-04 |
| **Emulator tests** (`npm run test:emulator`, `REQUIRE_EMULATOR=true`) | **19 of 19 pass, 0 skipped, 0 failed.** Real Firestore **emulator** (firebase-tools 14, OpenJDK 21), Ubuntu sandbox. Covers genesis, signed transfers, fees, replay and duplicate rejection, nonce ordering, block-time rejection, concurrent block producers, tamper detection, supply audit, HTTP API, CORS, rate limit, fail-closed operator endpoints. | 2026-10-04 |
| **Real entrypoint smoke test** (`node src/server.js` against the emulator) | `/ready` 200, `/health` 200, `/v1/chain` 200, `/internal/audit` 503 (disabled when no token is set), unknown route 404 JSON, SIGTERM exits with code 0, logs are JSON with `severity` and `message`. | 2026-10-04 |
| Dependency install | Installs cleanly. Exact versions that passed: firestore 7.11.6, @noble/curves 1.9.7, @noble/hashes 1.8.0, compression 1.8.2, cors 2.8.6, express 4.22.3, express-rate-limit 7.5.1, helmet 8.3.0, pino 9.14.0, zod 3.25.76. They are now pinned in `package.json`. | 2026-10-04 |
| GitHub repo `Berima1/yaw-network`, `main` | Old `backend/server.js` cannot start: it uses `redis` without importing it, requires `./yaw-blockchain-core` (file is `src/blockchain/core.js`), and `elliptic` is missing from `package.json`. | 2026-10-03 |
| Render (account "My Workspace") | The service `yaw-network-1` from the original dashboard is **not** in this account. `yaw-network-api` (repo `yaw-network2`) exited with code 1 repeatedly in April-May 2026. Three Docker services never produced a deploy. | 2026-10-03 |
| Old `Dockerfile` | Line 1 (`BLOCKCHAIN DOCKERFILE`) is not a valid instruction, so the build fails. | 2026-10-03 |
| Vercel | No YAW frontend in recent deployments (only `okada-online`). | 2026-10-03 |
| Google Cloud project | `yaw-network-prod` created (project number 169601424993). The account has no organisation. | 2026-10-03 |
| Google Cloud billing | **Not linked** to `yaw-network-prod`. Enabling Cloud Run, Cloud Build, Artifact Registry and Secret Manager failed with a billing error. | 2026-10-03 |
| Firestore location | `africa-south1` (Johannesburg) is a valid Firestore location in `gcloud firestore locations list`. | 2026-10-03 |

## NOT verified yet (do not assume these work)

| Item | Why |
|---|---|
| **Anything against real Firestore** | All tests ran against the emulator. Real Firestore can differ in latency, contention behaviour and quotas. No composite index is needed by design, but that is unconfirmed in production. |
| Docker image build | Not run (no Docker in the test sandbox). |
| Cloud Run deploy, Cloud Scheduler, Secret Manager wiring | Blocked on billing; the RUNBOOK commands are unexecuted. |
| `package-lock.json` | Not committed. Direct dependencies are pinned, transitive ones are not. |
| GitHub Actions workflow | The connector cannot write `.github/workflows/*` (403). The template is in `docs/ci/backend-ci.yml`; the repo owner must copy it. |
| Latency from Ghana to `africa-south1` vs other regions | Not measured. |
| Frontend against the new API | Not started. |

## Findings from testing (real, keep in mind)

- **Concurrent block producers are correct but slow.** With 4 producers racing over 20 transactions the emulator test took about 10.6 seconds (Firestore retries on contention). No transaction was applied twice and the chain verified. Consequence: in production run **one** producer (Cloud Scheduler), and keep `INSTANT_BLOCKS=true` only for low traffic.
- **Request logs showed the router-relative path** (`/chain` instead of `/v1/chain`). Fixed by logging `originalUrl` without the query string.
- **Legacy files still on this branch, not reviewed:** `.github/workflows/deploy.yml` (would run `npm ci`, which fails without a lockfile, and deploys to Render), `docker-compose.yml`, `ecosystem.config.js`, `railway.toml`, root `package.json`, `vercel.json`, `DEPLOYMENT.md`. Retire them before merging.

## Attempts that failed (so nobody repeats them blindly)

- Pushing `.github/workflows/*` through the GitHub connector returns 403 ("Resource not accessible by integration"). Workflow template lives at `docs/ci/backend-ci.yml`.
- The first Vercel sandbox attempt could not run commands ("No approval received"). A second attempt on 2026-10-04 worked and produced the test results above. Sandboxes are non-persistent.
- Commit `b225600` accidentally added a junk file (`backend/test/__placeholder__`). It was removed in `c462dca`. The history is kept on purpose.

## Next steps, in order

1. Link billing to `yaw-network-prod` (console, one click).
2. Create the Firestore database, service account, secrets, Artifact Registry repo (RUNBOOK sections 2-6).
3. Build the image (Cloud Build), deploy to Cloud Run, run the smoke test (RUNBOOK section 8) against the real URL, record the result here.
4. Cloud Scheduler for block production, then re-test block production against real Firestore.
5. Retire the legacy files listed above; add the CI workflow.
6. Migrate the frontend to the new API (separate change).
7. Only then: open the PR to `main`.
