import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import fs from "fs/promises";
import multer from "multer";
import path from "path";
import { createClient } from "@supabase/supabase-js";
import { chromium } from "playwright";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const proxyRulesPath = path.resolve(__dirname, "../proxy/rules.json");

app.use(cors());
app.use(express.json({ limit: "4mb" }));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase =
  supabaseUrl && supabaseServiceRoleKey
    ? createClient(supabaseUrl, supabaseServiceRoleKey, {
        auth: {
          persistSession: false
        }
      })
    : null;

const captureState = {
  browser: null,
  context: null,
  page: null,
  startedAt: null,
  targetUrl: null,
  excludePatterns: [],
  exchanges: [],
  errors: []
};

function resetCaptureCollections() {
  captureState.exchanges = [];
  captureState.errors = [];
}

function trimCollection(collection, max = 250) {
  if (collection.length > max) {
    collection.splice(0, collection.length - max);
  }
}

function normalizeUrl(input) {
  if (!input) {
    throw new Error("domain is required");
  }

  if (/^https?:\/\//i.test(input)) {
    return input;
  }

  return `https://${input}`;
}

async function closeCaptureBrowser() {
  if (captureState.page) {
    await captureState.page.close().catch(() => {});
  }

  if (captureState.context) {
    await captureState.context.close().catch(() => {});
  }

  if (captureState.browser) {
    await captureState.browser.close().catch(() => {});
  }

  captureState.browser = null;
  captureState.context = null;
  captureState.page = null;
  captureState.startedAt = null;
  captureState.targetUrl = null;
  captureState.excludePatterns = [];
}

function sanitizeHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers || {}).slice(0, 30).map(([key, value]) => [key, String(value)])
  );
}

function filterReplayHeaders(headers) {
  const blocked = new Set([
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "transfer-encoding"
  ]);

  return Object.fromEntries(
    Object.entries(headers || {}).filter(([key]) => !blocked.has(String(key).toLowerCase()))
  );
}

function attachCaptureListeners(page, targetHost) {
  const exchangeMap = new Map();

  function shouldExclude(url) {
    return captureState.excludePatterns.some((pattern) => pattern && url.includes(pattern));
  }

  page.on("request", async (request) => {
    const url = request.url();
    if (!url.includes(targetHost)) {
      return;
    }

    if (shouldExclude(url)) {
      return;
    }

    const id = request.url() + "-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
    const entry = {
      id,
      timestamp: new Date().toISOString(),
      request: {
        method: request.method(),
        url,
        resourceType: request.resourceType(),
        headers: sanitizeHeaders(request.headers()),
        postData: request.postData() || ""
      },
      response: null
    };

    exchangeMap.set(request, entry);
    captureState.exchanges.push(entry);
    trimCollection(captureState.exchanges);
  });

  page.on("response", async (response) => {
    const url = response.url();
    if (!url.includes(targetHost)) {
      return;
    }

    if (shouldExclude(url)) {
      return;
    }

    let bodyPreview = "";
    try {
      const contentType = response.headers()["content-type"] || "";
      if (
        contentType.includes("application/json") ||
        contentType.includes("text/") ||
        contentType.includes("javascript") ||
        contentType.includes("xml")
      ) {
        bodyPreview = (await response.text()).slice(0, 4000);
      }
    } catch {
      bodyPreview = "";
    }

    const pairedEntry = exchangeMap.get(response.request());
    const responsePayload = {
      timestamp: new Date().toISOString(),
      url,
      status: response.status(),
      statusText: response.statusText(),
      headers: sanitizeHeaders(response.headers()),
      bodyPreview
    };

    if (pairedEntry) {
      pairedEntry.response = responsePayload;
      return;
    }

    captureState.exchanges.push({
      id: response.url() + "-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8),
      timestamp: new Date().toISOString(),
      request: null,
      response: responsePayload
    });
    trimCollection(captureState.exchanges);
  });

  page.on("requestfailed", (request) => {
    const url = request.url();
    if (!url.includes(targetHost)) {
      return;
    }

    if (shouldExclude(url)) {
      return;
    }

    captureState.errors.push({
      id: url + "-" + Date.now(),
      timestamp: new Date().toISOString(),
      url,
      method: request.method(),
      errorText: request.failure()?.errorText || "Unknown error"
    });
    trimCollection(captureState.errors, 100);
  });
}

async function launchCaptureSession(domain, excludePatterns = []) {
  const targetUrl = normalizeUrl(domain);
  const parsedTargetUrl = new URL(targetUrl);
  const targetHost = parsedTargetUrl.host;
  const popupWidth = 1280;
  const popupHeight = 860;
  const screenWidth = 1728;
  const screenHeight = 1117;
  const windowX = Math.max(0, Math.floor((screenWidth - popupWidth) / 2));
  const windowY = Math.max(0, Math.floor((screenHeight - popupHeight) / 2));

  await closeCaptureBrowser();
  resetCaptureCollections();

  const browser = await chromium.launch({
    headless: false,
    args: [
      `--window-size=${popupWidth},${popupHeight}`,
      `--window-position=${windowX},${windowY}`
    ]
  });

  const context = await browser.newContext({
    viewport: {
      width: popupWidth,
      height: popupHeight - 96
    }
  });
  context.on("page", (newPage) => {
    attachCaptureListeners(newPage, targetHost);
  });

  const page = await context.newPage();
  attachCaptureListeners(page, targetHost);
  await page.goto(targetUrl, { waitUntil: "domcontentloaded" });

  captureState.browser = browser;
  captureState.context = context;
  captureState.page = page;
  captureState.startedAt = new Date().toISOString();
  captureState.targetUrl = targetUrl;
  captureState.excludePatterns = excludePatterns;
}

function analyzeHar(har) {
  const entries = har?.log?.entries ?? [];
  const methods = {};
  const hosts = new Map();
  const statusCodes = {};
  const contentTypes = {};
  const slowestEntries = [];
  const largestResponses = [];
  const failedRequests = [];

  let totalWait = 0;
  let slowestEntry = null;

  for (const entry of entries) {
    const method = entry?.request?.method ?? "UNKNOWN";
    const url = entry?.request?.url ?? "";
    const time = Number(entry?.time ?? 0);
    const status = entry?.response?.status ?? 0;
    const responseSize = Number(entry?.response?.bodySize ?? 0);
    const mimeType = entry?.response?.content?.mimeType ?? "unknown";

    methods[method] = (methods[method] ?? 0) + 1;
    statusCodes[status] = (statusCodes[status] ?? 0) + 1;
    contentTypes[mimeType] = (contentTypes[mimeType] ?? 0) + 1;
    totalWait += time;

    try {
      const { host } = new URL(url);
      hosts.set(host, (hosts.get(host) ?? 0) + 1);
    } catch {
      hosts.set("invalid-url", (hosts.get("invalid-url") ?? 0) + 1);
    }

    if (!slowestEntry || time > slowestEntry.time) {
      slowestEntry = {
        time,
        url,
        method,
        status
      };
    }

    slowestEntries.push({
      method,
      status,
      time,
      url
    });

    largestResponses.push({
      method,
      status,
      size: responseSize,
      url
    });

    if (status >= 400) {
      failedRequests.push({
        method,
        status,
        time,
        url
      });
    }
  }

  return {
    totalEntries: entries.length,
    averageWaitMs: entries.length ? Number((totalWait / entries.length).toFixed(2)) : 0,
    slowestEntry,
    slowestEntries: slowestEntries.sort((a, b) => b.time - a.time).slice(0, 5),
    largestResponses: largestResponses.sort((a, b) => b.size - a.size).slice(0, 5),
    failedRequests: failedRequests.sort((a, b) => b.time - a.time).slice(0, 10),
    methods,
    statusCodes,
    contentTypes: Object.entries(contentTypes)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    topHosts: [...hosts.entries()]
      .map(([host, count]) => ({ host, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
  };
}

async function readProxyRules() {
  try {
    const raw = await fs.readFile(proxyRulesPath, "utf-8");
    return JSON.parse(raw);
  } catch {
    return { rules: [] };
  }
}

async function writeProxyRules(rules) {
  const payload = JSON.stringify({ rules }, null, 2);
  await fs.writeFile(proxyRulesPath, payload, "utf-8");
}

async function saveAnalysisRecord(payload) {
  if (!supabase) {
    return { saved: false, reason: "Supabase credentials are not configured." };
  }

  const { error } = await supabase.from("har_analyses").insert(payload);

  if (error) {
    return { saved: false, reason: error.message };
  }

  return { saved: true };
}

app.get("/api/health", (_request, response) => {
  response.json({ ok: true });
});

app.get("/api/capture/status", (_request, response) => {
  response.json({
    active: Boolean(captureState.page),
    startedAt: captureState.startedAt,
    targetUrl: captureState.targetUrl,
    excludePatterns: captureState.excludePatterns,
    exchanges: captureState.exchanges,
    errors: captureState.errors
  });
});

app.post("/api/capture/start", async (request, response) => {
  const { domain, excludePatterns } = request.body ?? {};

  try {
    await launchCaptureSession(
      domain,
      Array.isArray(excludePatterns) ? excludePatterns.filter(Boolean) : []
    );
    response.json({
      ok: true,
      targetUrl: captureState.targetUrl,
      startedAt: captureState.startedAt,
      excludePatterns: captureState.excludePatterns
    });
  } catch (error) {
    response.status(400).json({
      error: error instanceof Error ? error.message : "Failed to start capture session"
    });
  }
});

app.post("/api/capture/stop", async (_request, response) => {
  await closeCaptureBrowser();
  response.json({ ok: true });
});

app.post("/api/replay-request", async (request, response) => {
  const { url, method, headers, body } = request.body ?? {};

  if (!url || !method) {
    response.status(400).json({ error: "url and method are required." });
    return;
  }

  try {
    const replayResponse = await fetch(url, {
      method,
      headers: filterReplayHeaders(headers),
      body:
        method === "GET" || method === "HEAD" || body === undefined || body === null || body === ""
          ? undefined
          : body
    });

    const contentType = replayResponse.headers.get("content-type") || "";
    let responseBody = "";

    if (
      contentType.includes("application/json") ||
      contentType.includes("text/") ||
      contentType.includes("javascript") ||
      contentType.includes("xml") ||
      contentType.includes("html")
    ) {
      responseBody = await replayResponse.text();
    } else {
      responseBody = "(binary response omitted)";
    }

    response.json({
      ok: true,
      response: {
        status: replayResponse.status,
        statusText: replayResponse.statusText,
        headers: Object.fromEntries(replayResponse.headers.entries()),
        body: responseBody.slice(0, 20000)
      }
    });
  } catch (error) {
    response.status(400).json({
      error: error instanceof Error ? error.message : "Failed to replay request"
    });
  }
});

app.get("/api/proxy-rules", async (_request, response) => {
  const data = await readProxyRules();
  response.json(data);
});

app.post("/api/proxy-rules", async (request, response) => {
  const rules = Array.isArray(request.body?.rules) ? request.body.rules : null;

  if (!rules) {
    response.status(400).json({ error: "rules array is required." });
    return;
  }

  await writeProxyRules(rules);
  response.json({ ok: true, rules });
});

app.post("/api/analyze-har", upload.single("har"), async (request, response) => {
  if (!request.file) {
    response.status(400).json({ error: "HAR file is required." });
    return;
  }

  try {
    const rawText = request.file.buffer.toString("utf-8");
    const har = JSON.parse(rawText);
    const summary = analyzeHar(har);

    const saved = await saveAnalysisRecord({
      file_name: request.file.originalname,
      file_size: request.file.size,
      total_entries: summary.totalEntries,
      average_wait_ms: summary.averageWaitMs,
      slowest_url: summary.slowestEntry?.url ?? null,
      methods: summary.methods,
      top_hosts: summary.topHosts,
      status_codes: summary.statusCodes,
      content_types: summary.contentTypes,
      failed_requests: summary.failedRequests
    });

    response.json({
      fileName: request.file.originalname,
      fileSize: request.file.size,
      summary,
      storage: saved
    });
  } catch (error) {
    response.status(400).json({
      error: "Invalid HAR file.",
      message: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, "127.0.0.1", () => {
  console.log(`HAR analysis server listening on http://127.0.0.1:${port}`);
});
