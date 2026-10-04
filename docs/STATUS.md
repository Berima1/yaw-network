# Status

This file records only what has actually been checked. Update it every time something changes.
Last updated: 2026-10-04.

## Verified (by running a command or reading the real system)

| Item | Result | Date |
|---|---|---|
| **Live staging service** | Cloud Run service `yaw-ledger-api`, region africa-south1, revision `yaw-ledger-api-00002-cxj`, URL `https://yaw-ledger-api-169601424993.africa-south1.run.app`. Image `ledger-api:b071fb3`, runtime service account `yaw-ledger-api`, 0-3 instances, 512Mi, public (allUsers invoker) on purpose, secrets pinned to version 1. | 2026-10-04 |
| **Live smoke test against real Cloud Run + real Firestore** | `/health` 200, `/ready` 200, `/v1/chain` 200 (chain `yaw-staging-1`, supply 1000000000). A signed transfer of 5000000 was **confirmed in block 1** (HTTP 201, 685 ms from a US-East sandbox). Alice 1000000000 -> 995000000, Bob 0 -> 5000000, nonce 1. Replaying the same transaction -> 409 `duplicate_transaction`. Tampered amount -> 400 `bad_signature`. `/internal/audit` without token -> 401. Unknown route -> 404 JSON. | 2026-10-04 |
| **Independent chain verification from outside** | A separate script fetched the blocks over the public API and recomputed every hash, link, merkle root and the operator signature: **PASS** (2 blocks). | 2026-10-04 |
| **Cloud Run logs** | JSON logs with `severity`; full request paths; no secrets, no query strings; no WARNING or ERROR entries during the test. Revision 1 logged a clean `shutting down` on SIGTERM when revision 2 replaced it. | 2026-10-04 |
| IAM | Owner granted `roles/datastore.user` and `roles/secretmanager.secretAccessor` to `yaw-ledger-api` (read back from the project policy). The service works with exactly those. | 2026-10-04 |
| **Unit tests** | 22 of 22 pass on Node v24.21.0 (Vercel sandbox) and inside Cloud Build (Node 24). | 2026-10-04 |
| **Emulator tests** (`REQUIRE_EMULATOR=true`) | 19 of 19 pass, 0 skipped, 0 failed, in two environments: a Vercel sandbox (commit f9955bd) and GitHub Actions run 37183531361 (commit b071fb3, log read from the `ci-logs` branch). | 2026-10-04 |
| **Docker image** | Built and pushed by Cloud Build 842e04ea-93ab-4410-8304-6a4906bcf1e9. Digest `sha256:477fa345301f059f3ce1debc3cb7cc28e3c848b8cece81efa1dbd1cdbb08391f`. It started correctly on Cloud Run. | 2026-10-04 |
| Google Cloud | Project `yaw-network-prod` (169601424993), billing linked, no organisation. Firestore `(default)` Native mode in africa-south1, delete protection ON, point-in-time recovery OFF. Artifact Registry repo `yaw`. Secrets `operator-private-key` and `producer-token` (generated inside a build, never displayed). | 2026-10-04 |
| GitHub repo `main` | Old `backend/server.js` cannot start (missing `redis` import, wrong path to the core file, `elliptic` not in `package.json`). | 2026-10-03 |
| Render (account "My Workspace") | The original `yaw-network-1` service is not in this account. `yaw-network-api` exited with code 1 repeatedly in April-May 2026. Three Docker services never deployed. | 2026-10-03 |
| Vercel | No YAW frontend in recent deployments (only `okada-online`). | 2026-10-03 |

## NOT verified yet (do not assume these work)

| Item | Why |
|---|---|
| **Block production by Cloud Scheduler** | Not created. Staging uses `INSTANT_BLOCKS=true`, which is only suitable for low traffic. |
| **`/internal/audit` with a valid token, live** | Only the 401 path was tested live. The authorised path is covered by emulator tests, not yet by a live call. |
| **Latency from Ghana** | The test ran from a US-East sandbox. Region choice (africa-south1) is unmeasured from Ghana. |
| **Cold start time, load, cost** | Not measured. |
| `package-lock.json` | Not committed. Direct dependencies are pinned exactly, transitive ones are not. |
| Frontend against the new API | Not started. |
| Real chain (`yaw-testnet-1`) | Does not exist yet; its genesis is a product decision. |

## Findings (real, keep in mind)

- **Concurrent block producers are correct but their speed depends on the environment** (4 producers, 20 transactions: about 10.6 s in one sandbox, 3.4 s in GitHub Actions). Nothing was ever applied twice. In production run **one** producer (Cloud Scheduler).
- **The Vercel Hobby sandbox lives 45 minutes at most.** One sandbox expired while it held the only copy of the staging wallet key, so the staging chain was recreated under prefix `stg2_` with a new wallet. The old `staging_*` Firestore collections (genesis for the lost wallet) are orphaned and harmless; delete them when convenient.
- The Google Cloud tool used by the automation refuses IAM-changing commands and `iam service-accounts create`; the service accounts and secrets were created by `deploy/bootstrap.yaml` instead, and the owner ran the two IAM grants.
- A build-time guard works: the first Cloud Build failed at the clone step because the branch head had moved since the commit was named, exactly as designed.
- `yaw-builder` service account exists but is unused; delete it or give it a purpose.
- **Legacy files still on this branch, not reviewed:** `docker-compose.yml`, `ecosystem.config.js`, `railway.toml`, root `package.json`, `vercel.json`, `DEPLOYMENT.md`. Retire them before merging.

## Attempts that failed (so nobody repeats them blindly)

- Pushing `.github/workflows/*` through the GitHub connector returns 403. The owner added the workflow by hand (commit b071fb3).
- IAM-changing gcloud verbs are refused by the tool.
- `gcloud builds log` cannot stream ("Unable to load credentials"); use `gcloud builds describe` for step status and `gcloud logging read` with the `logName` filter for logs.
- Commit `b225600` accidentally added a junk file (`backend/test/__placeholder__`). It was removed in `c462dca`. The history is kept on purpose.

## Next steps, in order

1. Decide the real genesis (supply, who gets what) and the chain name; launch `yaw-testnet-1` as a second Cloud Run service or revision with its own collection prefix.
2. Cloud Scheduler for block production (needs a design decision: shared token in the job, or verify Google OIDC tokens in the app), then switch `INSTANT_BLOCKS` off for that chain.
3. Live-test `/internal/audit` with the token.
4. Measure latency from Ghana and compare regions before the real launch.
5. Retire the legacy files; migrate the frontend to the new API (separate change).
6. Only then open the PR to `main`.
