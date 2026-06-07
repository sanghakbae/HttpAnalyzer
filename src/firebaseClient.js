import { initializeApp, getApps, getApp } from "firebase/app";
import {
  GoogleAuthProvider,
  browserLocalPersistence,
  getAuth,
  setPersistence,
  signInWithPopup,
  signOut
} from "firebase/auth";
import {
  Timestamp,
  collection,
  doc,
  getDocs,
  getFirestore,
  limit,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  where
} from "firebase/firestore";

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyC4oX_d-LAthyry9EbwdjZrvHt2Q3PXdgM",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "http-analyzer.firebaseapp.com",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "http-analyzer",
  storageBucket:
    import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "http-analyzer.firebasestorage.app",
  messagingSenderId:
    import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "893069295106",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:893069295106:web:dc96d6fe3ece51d52a711b",
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || "G-XL4QT15KSX"
};

const hasFirebaseClientConfig = Boolean(firebaseConfig.apiKey && firebaseConfig.projectId);
const firebaseApp = hasFirebaseClientConfig ? (getApps().length ? getApp() : initializeApp(firebaseConfig)) : null;
const firebaseAuth = firebaseApp ? getAuth(firebaseApp) : null;
const firebaseDb = firebaseApp ? getFirestore(firebaseApp) : null;
const googleProvider = firebaseApp ? new GoogleAuthProvider() : null;

if (googleProvider) {
  googleProvider.setCustomParameters({ prompt: "select_account" });
}

let authPersistencePromise = null;

function ensureObject(value) {
  return value && typeof value === "object" ? value : {};
}

function normalizeFirestoreValue(value) {
  if (value instanceof Timestamp) {
    return value.toDate().toISOString();
  }

  if (Array.isArray(value)) {
    return value.map(normalizeFirestoreValue);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [key, normalizeFirestoreValue(nestedValue)])
    );
  }

  return value;
}

function buildRecordId(prefix) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(value || "")
  );
}

function buildCaptureEventFingerprint(event) {
  return [
    event.capture_session_id || "",
    event.request_timestamp || "",
    event.request_method || "",
    event.request_url || "",
    event.response_status || "",
    event.error_text || ""
  ].join("::");
}

function hashString(value) {
  let hash = 5381;
  const text = String(value || "");

  for (let index = 0; index < text.length; index += 1) {
    hash = (hash * 33) ^ text.charCodeAt(index);
  }

  return (hash >>> 0).toString(16);
}

function buildCaptureEventDocumentId(event) {
  const explicitId = String(event?.id || "").trim();
  if (explicitId && !explicitId.includes("/")) {
    return explicitId;
  }

  return `capture-event-${hashString(buildCaptureEventFingerprint(event))}`;
}

async function ensureAuthPersistence() {
  if (!firebaseAuth) {
    return;
  }

  if (!authPersistencePromise) {
    authPersistencePromise = setPersistence(firebaseAuth, browserLocalPersistence).catch((error) => {
      authPersistencePromise = null;
      throw error;
    });
  }

  await authPersistencePromise;
}

async function getCollectionRows(collectionName, orderColumn, maxRows) {
  if (!firebaseDb) {
    return [];
  }

  const snapshot = await getDocs(
    query(collection(firebaseDb, collectionName), orderBy(orderColumn, "desc"), limit(maxRows))
  );

  return snapshot.docs.map((item) => normalizeFirestoreValue({ id: item.id, ...item.data() }));
}

export function isFirebaseClientReady() {
  return Boolean(firebaseApp && firebaseAuth && firebaseDb);
}

export async function signInWithGooglePopup() {
  if (!firebaseAuth || !googleProvider) {
    throw new Error("Firebase Auth is not configured.");
  }

  await ensureAuthPersistence();
  return signInWithPopup(firebaseAuth, googleProvider);
}

export async function signOutFirebaseUser() {
  if (!firebaseAuth) {
    return;
  }

  await signOut(firebaseAuth);
}

export function getFirebaseAuth() {
  return firebaseAuth;
}

export async function loadRecentFromFirebaseClient() {
  if (!firebaseDb) {
    return {
      harAnalyses: [],
      captureEvents: [],
      inspectionRuns: [],
      dbBacked: false
    };
  }

  const [harAnalyses, captureEvents, inspectionRuns] = await Promise.all([
    getCollectionRows("capture_har_analyses", "created_at", 20),
    getCollectionRows("capture_http_events", "created_at", 500),
    getCollectionRows("capture_inspection_runs", "created_at", 500)
  ]);

  return {
    harAnalyses,
    captureEvents,
    inspectionRuns,
    dbBacked: true
  };
}

export async function saveInspectionRunToFirebase(payload) {
  if (!firebaseDb) {
    return { saved: false, reason: "Firebase client Firestore is not configured." };
  }

  const runPayload = {
    ...payload,
    report_snapshot: ensureObject(payload.report_snapshot),
    created_at: payload.created_at || payload.ended_at || new Date().toISOString(),
    updated_at: new Date().toISOString()
  };

  const runsRef = collection(firebaseDb, "capture_inspection_runs");
  let documentId = payload.id || "";

  if (isUuid(payload.capture_session_id)) {
    const existingSnapshot = await getDocs(
      query(runsRef, where("capture_session_id", "==", payload.capture_session_id), limit(1))
    );

    if (!existingSnapshot.empty) {
      const existingDocument = existingSnapshot.docs[0];
      const existing = normalizeFirestoreValue(existingDocument.data());
      documentId = existingDocument.id;
      await setDoc(doc(firebaseDb, "capture_inspection_runs", documentId), {
        ...existing,
        ...runPayload,
        id: existing.id || existingDocument.id,
        report_snapshot: {
          ...ensureObject(existing.report_snapshot),
          ...ensureObject(runPayload.report_snapshot)
        }
      });
      return { saved: true, updated: true, id: existing.id || existingDocument.id };
    }
  }

  documentId = documentId || buildRecordId("inspection-run");
  await setDoc(doc(firebaseDb, "capture_inspection_runs", documentId), {
    id: documentId,
    ...runPayload
  });

  return { saved: true, id: documentId };
}

export async function saveInspectionSummaryToFirebase(payload) {
  if (!firebaseDb) {
    return { saved: false, reason: "Firebase client Firestore is not configured." };
  }

  if (!payload.summary) {
    return { saved: false, reason: "summary is required." };
  }

  const runsRef = collection(firebaseDb, "capture_inspection_runs");
  let runSnapshot = null;

  if (isUuid(payload.capture_session_id)) {
    runSnapshot = await getDocs(
      query(runsRef, where("capture_session_id", "==", payload.capture_session_id), limit(10))
    );
  } else if (payload.target_url) {
    runSnapshot = await getDocs(query(runsRef, where("target_url", "==", payload.target_url), limit(10)));
  } else {
    return { saved: false, reason: "capture_session_id or target_url is required." };
  }

  if (!runSnapshot || runSnapshot.empty) {
    return { saved: false, reason: "No matching inspection run was found." };
  }

  const sortedDocs = runSnapshot.docs
    .slice()
    .sort((left, right) => {
      const leftValue = Date.parse(String(left.data()?.ended_at || left.data()?.created_at || ""));
      const rightValue = Date.parse(String(right.data()?.ended_at || right.data()?.created_at || ""));
      return rightValue - leftValue;
    });

  const runDocument = sortedDocs[0];
  const run = normalizeFirestoreValue(runDocument.data());

  await setDoc(doc(firebaseDb, "capture_inspection_runs", runDocument.id), {
    ...run,
    report_snapshot: {
      ...ensureObject(run.report_snapshot),
      aiSummary: payload.summary,
      aiSummaryMeta: {
        ...ensureObject(payload.summary_meta),
        syncedAt: new Date().toISOString()
      }
    }
  });

  return { saved: true, id: run.id || runDocument.id };
}

export async function saveCaptureEventsToFirebase(events) {
  if (!firebaseDb) {
    return { saved: false, reason: "Firebase client Firestore is not configured." };
  }

  const validEvents = (Array.isArray(events) ? events : []).filter(
    (event) => event && event.request_url
  );

  if (validEvents.length === 0) {
    return { saved: true, count: 0, skipped: Array.isArray(events) ? events.length : 0 };
  }

  for (const event of validEvents) {
    const documentId = buildCaptureEventDocumentId(event);
    await setDoc(doc(firebaseDb, "capture_http_events", documentId), {
      id: documentId,
      created_at: event.created_at || new Date().toISOString(),
      updated_at: new Date().toISOString(),
      server_created_at: serverTimestamp(),
      ...event
    });
  }

  return {
    saved: true,
    count: validEvents.length,
    skipped: 0
  };
}
