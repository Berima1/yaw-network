# Runbook

Every command here is **unexecuted** unless STATUS.md says otherwise. Run them in order and record real results in STATUS.md.

Variables used below: `PROJECT=yaw-network-prod`, `REGION=africa-south1` (see DECISIONS D9), `SERVICE=yaw-ledger-api`.

## 1. Link billing (manual, console only)

Open https://console.cloud.google.com/billing/linkedaccount?project=yaw-network-prod, choose your billing account, link. Everything below needs this.

## 2. Enable APIs

```bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  secretmanager.googleapis.com firestore.googleapis.com cloudscheduler.googleapis.com --project=$PROJECT
```

## 3. Firestore database (location cannot be changed later)

```bash
gcloud firestore databases create --location=$REGION --type=firestore-native --project=$PROJECT
```

Deploy the deny-all rules in `backend/firestore.rules` if you ever enable the client SDK path (the backend uses IAM and does not need them).

## 4. Service account

```bash
gcloud iam service-accounts create yaw-ledger-api --display-name="YAW ledger API" --project=$PROJECT
SA=yaw-ledger-api@$PROJECT.iam.gserviceaccount.com
gcloud projects add-iam-policy-binding $PROJECT --member=serviceAccount:$SA --role=roles/datastore.user
```

Least privilege: it can use Firestore and read its own secrets, nothing else.

## 5. Secrets

```bash
cd backend && npm install && npm run gen-key        # prints privateKey / publicKey / address
# Put the privateKey in Secret Manager; keep it out of chat, git and logs.
printf '%s' '<privateKey>' | gcloud secrets create operator-private-key --data-file=- --project=$PROJECT
openssl rand -hex 32 | tr -d '\n' | gcloud secrets create producer-token --data-file=- --project=$PROJECT
for s in operator-private-key producer-token; do
  gcloud secrets add-iam-policy-binding $s --member=serviceAccount:$SA --role=roles/secretmanager.secretAccessor --project=$PROJECT
done
```

Record the operator **address** (not the key) in STATUS.md.

## 6. Artifact Registry and build

```bash
gcloud artifacts repositories create yaw --repository-format=docker --location=$REGION --project=$PROJECT
gcloud builds submit backend --tag=$REGION-docker.pkg.dev/$PROJECT/yaw/ledger-api:v2.0.0 --project=$PROJECT
```

## 7. Deploy

Put genesis allocations in a file (commas break `--set-env-vars`), e.g. `env.yaml`:

```yaml
CHAIN_ID: yaw-testnet-1
INSTANT_BLOCKS: "true"
GENESIS_ALLOCATIONS: '{"yaw...address...": 1000000000}'
CORS_ORIGINS: "https://your-frontend.example"
```

```bash
gcloud run deploy $SERVICE --image=$REGION-docker.pkg.dev/$PROJECT/yaw/ledger-api:v2.0.0 \
  --region=$REGION --service-account=$SA --allow-unauthenticated \
  --min-instances=0 --max-instances=3 --cpu=1 --memory=512Mi \
  --env-vars-file=env.yaml \
  --set-secrets=OPERATOR_PRIVATE_KEY=operator-private-key:latest,PRODUCER_TOKEN=producer-token:latest \
  --project=$PROJECT
```

`GENESIS_ALLOCATIONS` is read only when the chain is first created. Choose it deliberately.

## 8. Smoke test (record the output in STATUS.md)

```bash
URL=$(gcloud run services describe $SERVICE --region=$REGION --project=$PROJECT --format='value(status.url)')
curl -s $URL/health
curl -s $URL/ready
curl -s $URL/v1/chain
curl -s -H "Authorization: Bearer $(gcloud secrets versions access latest --secret=producer-token --project=$PROJECT)" $URL/internal/audit
```

Then submit a real signed transaction from a test key and confirm balance changes. The first deploy is not done until this has been run against the real URL.

## 9. Optional: scheduled blocks and audit

Only needed if `INSTANT_BLOCKS=false` (blocks) and recommended always (audit). Cloud Scheduler HTTP jobs with the bearer header call `/internal/produce-block` (every minute) and `/internal/audit` (hourly, alert on `ok:false`).

## Rollback

```bash
gcloud run revisions list --service=$SERVICE --region=$REGION --project=$PROJECT
gcloud run services update-traffic $SERVICE --to-revisions=<previous-revision>=100 --region=$REGION --project=$PROJECT
```

Data is not rolled back by a code rollback. Never delete the Firestore collections to "reset" production; create a new chain id instead.

## CI

GitHub connector tokens cannot write workflow files. Copy `docs/ci/backend-ci.yml` to `.github/workflows/backend-ci.yml` yourself (GitHub web UI: Add file, paste, commit to the branch). While the migration is in progress the workflow also publishes test logs to a `ci-logs` branch; remove that last step and the `contents: write` permission once logs are readable normally.

## Debugging

- Logs: Cloud Logging, resource `cloud_run_revision`, JSON with `severity` and `message`.
- Startup failure: usually configuration (the process prints which variable is invalid) or an operator-key / chain-id mismatch with the stored chain.
- `/ready` returning 503: Firestore unreachable or chain not initialised.

## Cost notes

Scale to zero means no cost when idle. Firestore is billed per read/write; `/internal/audit` scans every account and block, so schedule it sparingly.
