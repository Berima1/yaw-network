import { Firestore } from '@google-cloud/firestore';

// On Cloud Run, credentials and project id come from the attached service account (no key files).
// Locally and in CI, FIRESTORE_EMULATOR_HOST is honoured automatically by the client library.
export function createFirestore() {
  const projectId = process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
  return new Firestore({ ...(projectId ? { projectId } : {}), ignoreUndefinedProperties: true });
}
