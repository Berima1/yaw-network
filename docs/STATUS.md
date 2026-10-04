# Status

This file records only what has actually been checked. Update it every time something changes.
Last updated: 2026-10-04.

## Verified (by running a command or reading the real system)

| Item | Result | Date |
|---|---|---|
| **Unit tests** | **22 of 22 pass** on Node v24.21.0 (Vercel sandbox) and again inside Cloud Build (Node 24). | 2026-10-04 |
| **Emulator tests** (`REQUIRE_EMULATOR=true`) | **19 of 19 pass, 0 skipped, 0 failed**, in two independent environments: a Vercel sandbox (commit f9955bd) and GitHub Actions run 37183531361 (commit b071fb3, log read from the `ci-logs` branch). They use the real Firestore **emulator** (firebase-tools 14, OpenJDK 21). | 2026-10-04 |
| **Real entrypoint smoke test** (`node src/server.js` against the emulator) | `/ready` 200, `/health` 200, `/v1/chain` 200, `/internal/audit` 503 (disabled when no token), unknown route 404 JSON, SIGTERM exits 0, JSON logs with `severity`, full request paths. | 2026-10-04 |
| **Docker image** | Built and pushed by Cloud Build 842e04ea-93ab-4410-8304-6a4906bcf1e9 (clone guard, unit tests, docker build, docker push all SUCCESS). `africa-south1-docker.pkg.dev/yaw-network-prod/yaw/ledger-api:b071fb3`, digest `sha256:477fa345301f059f3ce1debc3cb7cc28e3c848b8cece81efa1dbd1cdbb08391f`. The image has **not been started** yet. | 2026-10-04 |
| Google Cloud project | `yaw-network-prod` (number 169601424993), no organisation. **Billing is linked** (paid APIs enabled successfully). | 2026-10-04 |
| Firestore | Database `(default)`, Native mode, **africa-south1**, delete protection ON, point-in-time recovery OFF, free tier flag true. | 2026-10-04 |
| Artifact Registry | Docker repo `yaw` in africa-south1. | 2026-10-04 |
| Service accounts | `yaw-ledger-api` (runtime), `yaw-builder` (created, currently unused), both created by `deploy/bootstrap.yaml`. | 2026-10-04 |
| Secrets | `operator-private-key` and `producer-token` exist with one enabled version each. Values were generated inside Cloud Build from /dev/urandom and were never displayed. | 2026-10-04 |
| Cloud Run in africa-south1 | Listed as an available region. | 2026-10-04 |
| GitHub repo `main` | Old `backend/server.js` cannot start (missing `redis` import, wrong path to the core file, `elliptic` not in `package.json`). | 2026-10-03 |
| Render (account "My Workspace") | The original `yaw-network-1` service is not in this account. `yaw-network-api` exited with code 1 repeatedly in April-May 2026. Three Docker services never deployed. | 2026-10-03 |
| Vercel | No YAW frontend in recent deployments (only `okada-online`). | 2026-10-03 |

## NOT verified yet (do not assume these work)

| Item | Why |
|---|---|
| **Anything against real Firestore** | Tests ran against the emulator only. Real Firestore can differ in latency, contention and quotas. |
| **The container running on Cloud Run** | Deploy is blocked on two permission grants that the automation cannot make (see below). |
| Cloud Scheduler block production | Not created yet. |
| `package-lock.json` | Not committed. Direct dependencies are pinned exactly, transitive ones are not. |
| Latency Ghana -> africa-south1 | Not measured. |
| Frontend against the new API | Not started. |

## Blocked on the repo owner (the automation is not allowed to do these)

The Google Cloud tool used here blocks every IAM-changing command (`add-iam-policy-binding`, `set-iam-policy`) and `iam service-accounts create`. The service accounts were created through a build instead; the two grants below must be run by the owner, for example in Cloud Shell:

```bash
gcloud projects add-iam-policy-binding yaw-network-prod --member="serviceAccount:yaw-ledger-api@yaw-network-prod.iam.gserviceaccount.com" --role="roles/datastore.user"
gcloud projects add-iam-policy-binding yaw-network-prod --member="serviceAccount:yaw-ledger-api@yaw-network-prod.iam.gserviceaccount.com" --role="roles/secretmanager.secretAccessor"
```

The runtime account then has exactly two permissions: use Firestore, read the two secrets.

## Findings from testing (real, keep in mind)

- **Concurrent block producers are correct but their speed depends on the environment.** The 4-producer, 20-transaction test took about 10.6 s in the sandbox and 3.4 s in GitHub Actions. No transaction was ever applied twice and the chain verified every time. In production run **one** producer (Cloud Scheduler) and keep `INSTANT_BLOCKS=true` only for low traffic.
- Request logs used to show the router-relative path; fixed (full path, no query string).
- A build-time guard works: the first Cloud Build failed at the clone step because the branch head had moved since the commit was named, exactly as designed.
- **Legacy files still on this branch, not reviewed:** `docker-compose.yml`, `ecosystem.config.js`, `railway.toml`, root `package.json`, `vercel.json`, `DEPLOYMENT.md`. Retire them before merging.

## Attempts that failed (so nobody repeats them blindly)

- Pushing `.github/workflows/*` through the GitHub connector returns 403. The owner added the workflow by hand (commit b071fb3).
- IAM-changing gcloud verbs and `iam service-accounts create` are refused by the tool.
- `gcloud builds log` cannot stream ("Unable to load credentials"); use `gcloud builds describe` for step status.
- The first Vercel sandbox attempt could not run commands ("No approval received"); the next attempts worked. Sandboxes are non-persistent.
- Commit `b225600` accidentally added a junk file (`backend/test/__placeholder__`). It was removed in `c462dca`. The history is kept on purpose.

## Next steps, in order

1. Owner runs the two IAM grants above.
2. Deploy `yaw-ledger-api` to Cloud Run with `deploy/staging.env.yaml` (chain `yaw-staging-1`), then run a live smoke test with a signed transfer and the audit endpoint, and record the result here.
3. Create the Cloud Scheduler job, then re-test block production against real Firestore.
4. Decide the real genesis (supply, who gets what) and launch `yaw-testnet-1`.
5. Retire the legacy files; migrate the frontend to the new API (separate change).
6. Only then open the PR to `main`.
