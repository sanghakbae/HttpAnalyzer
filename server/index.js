import cors from "cors";
import { execFile } from "child_process";
import { randomUUID } from "crypto";
import dotenv from "dotenv";
import express from "express";
import fs from "fs/promises";
import multer from "multer";
import path from "path";
import { createClient } from "@supabase/supabase-js";
import { chromium } from "playwright";
import { fileURLToPath } from "url";
import { promisify } from "util";

dotenv.config();

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const proxyRulesPath = path.resolve(__dirname, "../proxy/rules.json");
const execFileAsync = promisify(execFile);

app.use(cors());
app.use(express.json({ limit: "4mb" }));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const disableCapture = process.env.DISABLE_CAPTURE === "true";
const playwrightHeadless =
  process.env.PLAYWRIGHT_HEADLESS === "true" || Boolean(process.env.RENDER);
const captureReadyDelayMs = Number(process.env.CAPTURE_READY_DELAY_MS || 3000);
const captureIdleAutoStopMs = Number(process.env.CAPTURE_IDLE_AUTO_STOP_MS || 10000);
const captureCrawlEnabled = process.env.CAPTURE_CRAWL_ENABLED !== "false";
const captureCrawlMaxPages = Number(process.env.CAPTURE_CRAWL_MAX_PAGES || 8);
const captureCrawlPageDelayMs = Number(process.env.CAPTURE_CRAWL_PAGE_DELAY_MS || 1500);
const captureLoginWaitMs = Number(process.env.CAPTURE_LOGIN_WAIT_MS || 3000);
const sqlmapBin = process.env.SQLMAP_BIN || "sqlmap";
const disableSqlmap = process.env.DISABLE_SQLMAP === "true" || Boolean(process.env.RENDER);
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
  sessionId: null,
  targetUrl: null,
  excludePatterns: [],
  lastActivityAt: null,
  stoppedAt: null,
  stopReason: null,
  idleTimer: null,
  crawlActive: false,
  crawlCompleted: false,
  crawlVisited: [],
  crawlQueue: [],
  crawlMaxPages: captureCrawlMaxPages,
  loginAttempted: false,
  loginStatus: "skipped",
  loginError: "",
  sessionApplied: false,
  sessionStatus: "skipped",
  sessionError: "",
  exchanges: [],
  errors: []
};

const memoryRecentCaptureEvents = [];

function resetCaptureCollections() {
  captureState.exchanges = [];
  captureState.errors = [];
  captureState.lastActivityAt = null;
  captureState.stoppedAt = null;
  captureState.stopReason = null;
  captureState.crawlActive = false;
  captureState.crawlCompleted = false;
  captureState.crawlVisited = [];
  captureState.crawlQueue = [];
  captureState.crawlMaxPages = captureCrawlMaxPages;
  captureState.loginAttempted = false;
  captureState.loginStatus = "skipped";
  captureState.loginError = "";
  captureState.sessionApplied = false;
  captureState.sessionStatus = "skipped";
  captureState.sessionError = "";
}

function trimCollection(collection, max = 250) {
  if (collection.length > max) {
    collection.splice(0, collection.length - max);
  }
}

function rememberCaptureEvent(payload, reason = "memory") {
  memoryRecentCaptureEvents.unshift({
    id: `memory-event-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    created_at: new Date().toISOString(),
    storage_reason: reason,
    ...payload
  });
  trimCollection(memoryRecentCaptureEvents, 50);
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function clearCaptureIdleTimer() {
  if (captureState.idleTimer) {
    clearTimeout(captureState.idleTimer);
    captureState.idleTimer = null;
  }
}

function scheduleCaptureIdleStop() {
  clearCaptureIdleTimer();

  if (!captureState.page || captureIdleAutoStopMs <= 0) {
    return;
  }

  captureState.idleTimer = setTimeout(() => {
    void closeCaptureBrowser({ clearMetadata: false, reason: "idle" });
  }, captureIdleAutoStopMs);
}

function touchCaptureActivity() {
  captureState.lastActivityAt = new Date().toISOString();
  scheduleCaptureIdleStop();
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

async function closeCaptureBrowser({ clearMetadata = true, reason = "manual" } = {}) {
  clearCaptureIdleTimer();

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
  captureState.stoppedAt = new Date().toISOString();
  captureState.stopReason = reason;
  captureState.crawlActive = false;
  captureState.crawlCompleted = reason === "crawl-complete";

  if (clearMetadata) {
    captureState.startedAt = null;
    captureState.sessionId = null;
    captureState.targetUrl = null;
    captureState.excludePatterns = [];
    captureState.lastActivityAt = null;
    captureState.stoppedAt = null;
    captureState.stopReason = null;
    captureState.crawlActive = false;
    captureState.crawlCompleted = false;
    captureState.crawlVisited = [];
    captureState.crawlQueue = [];
    captureState.loginAttempted = false;
    captureState.loginStatus = "skipped";
    captureState.loginError = "";
    captureState.sessionApplied = false;
    captureState.sessionStatus = "skipped";
    captureState.sessionError = "";
  }
}

function parseSessionCookies(sessionValue, targetUrl) {
  const value = String(sessionValue || "")
    .replace(/^cookie:\s*/i, "")
    .trim();

  if (!value) {
    return [];
  }

  const cookieSource = value.includes("=") ? value : `session=${value}`;
  const targetOrigin = new URL(targetUrl).origin;

  return cookieSource
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const separatorIndex = item.indexOf("=");
      if (separatorIndex <= 0) {
        return null;
      }

      const name = item.slice(0, separatorIndex).trim();
      const cookieValue = item.slice(separatorIndex + 1).trim();
      if (!name || !cookieValue) {
        return null;
      }

      return {
        url: targetOrigin,
        name,
        value: cookieValue,
        sameSite: "Lax"
      };
    })
    .filter(Boolean);
}

async function applySessionValue(context, targetUrl, sessionValue) {
  const value = String(sessionValue || "").trim();

  if (!value) {
    captureState.sessionApplied = false;
    captureState.sessionStatus = "skipped";
    captureState.sessionError = "";
    return false;
  }

  captureState.sessionApplied = true;
  captureState.sessionStatus = "applying";
  captureState.sessionError = "";

  try {
    const cookies = parseSessionCookies(value, targetUrl);
    if (cookies.length === 0) {
      captureState.sessionStatus = "invalid";
      captureState.sessionError = "Session value could not be parsed as a cookie.";
      return false;
    }

    await context.addCookies(cookies);
    captureState.sessionStatus = "applied";
    return true;
  } catch (error) {
    captureState.sessionStatus = "failed";
    captureState.sessionError = error instanceof Error ? error.message : "Failed to apply session value.";
    return false;
  }
}

async function fillFirstVisible(page, selectors, value) {
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    const count = await locator.count().catch(() => 0);
    if (count === 0) {
      continue;
    }

    const visible = await locator.isVisible().catch(() => false);
    const editable = await locator.isEditable().catch(() => false);
    if (!visible || !editable) {
      continue;
    }

    await locator.fill(value);
    return locator;
  }

  return null;
}

async function attemptPageLogin(page, credentials = {}) {
  const username = String(credentials.username || "").trim();
  const password = String(credentials.password || "");

  if (!username || !password) {
    captureState.loginAttempted = false;
    captureState.loginStatus = "skipped";
    captureState.loginError = "";
    return;
  }

  captureState.loginAttempted = true;
  captureState.loginStatus = "attempting";
  captureState.loginError = "";

  try {
    const usernameInput = await fillFirstVisible(
      page,
      [
        'input[type="email"]',
        'input[name*="email" i]',
        'input[id*="email" i]',
        'input[name*="user" i]',
        'input[id*="user" i]',
        'input[name*="login" i]',
        'input[id*="login" i]',
        'input[name*="id" i]',
        'input[id*="id" i]',
        'input[type="text"]',
        "input:not([type])"
      ],
      username
    );
    const passwordInput = await fillFirstVisible(page, ['input[type="password"]'], password);

    if (!usernameInput || !passwordInput) {
      captureState.loginStatus = "not-found";
      captureState.loginError = "Login inputs were not found on the first page.";
      return;
    }

    const submitButton = page
      .locator(
        'button[type="submit"], input[type="submit"], button:has-text("로그인"), button:has-text("Login"), button:has-text("Sign in"), button:has-text("로그인하기")'
      )
      .first();
    const hasSubmitButton = (await submitButton.count().catch(() => 0)) > 0;

    if (hasSubmitButton && (await submitButton.isVisible().catch(() => false))) {
      await Promise.allSettled([
        page.waitForLoadState("domcontentloaded", { timeout: 10000 }),
        submitButton.click()
      ]);
    } else {
      await Promise.allSettled([
        page.waitForLoadState("domcontentloaded", { timeout: 10000 }),
        passwordInput.press("Enter")
      ]);
    }

    if (captureLoginWaitMs > 0) {
      await sleep(captureLoginWaitMs);
    }

    captureState.loginStatus = "submitted";
  } catch (error) {
    captureState.loginStatus = "failed";
    captureState.loginError = error instanceof Error ? error.message : "Login automation failed.";
  }
}

function normalizeCrawlUrl(input, baseUrl, targetHost) {
  try {
    const parsedUrl = new URL(input, baseUrl);
    parsedUrl.hash = "";

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return null;
    }

    if (parsedUrl.host !== targetHost) {
      return null;
    }

    return parsedUrl.toString();
  } catch {
    return null;
  }
}

async function collectSameHostLinks(page, targetHost) {
  const currentUrl = page.url();
  const links = await page
    .evaluate(() =>
      [...document.querySelectorAll("a[href]")]
        .map((anchor) => anchor.getAttribute("href"))
        .filter(Boolean)
    )
    .catch(() => []);

  return [
    ...new Set(
      links
        .map((link) => normalizeCrawlUrl(link, currentUrl, targetHost))
        .filter(Boolean)
    )
  ];
}

async function crawlCapturePages(page, targetUrl, targetHost, sessionId) {
  if (!captureCrawlEnabled || !page || captureCrawlMaxPages <= 0) {
    return;
  }

  const visited = new Set();
  const queue = [targetUrl];
  captureState.crawlActive = true;
  captureState.crawlCompleted = false;
  captureState.crawlVisited = [];
  captureState.crawlQueue = [...queue];
  captureState.crawlMaxPages = captureCrawlMaxPages;
  clearCaptureIdleTimer();

  while (
    queue.length > 0 &&
    visited.size < captureCrawlMaxPages &&
    captureState.sessionId === sessionId &&
    captureState.page
  ) {
    const nextUrl = queue.shift();
    if (!nextUrl || visited.has(nextUrl)) {
      continue;
    }

    visited.add(nextUrl);
    captureState.crawlVisited = [...visited];
    captureState.crawlQueue = [...queue];

    try {
      if (page.url() !== nextUrl) {
        await page.goto(nextUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
      }

      if (captureCrawlPageDelayMs > 0) {
        await sleep(captureCrawlPageDelayMs);
      }

      const links = await collectSameHostLinks(page, targetHost);
      for (const link of links) {
        if (
          !visited.has(link) &&
          !queue.includes(link) &&
          visited.size + queue.length < captureCrawlMaxPages
        ) {
          queue.push(link);
        }
      }
      captureState.crawlQueue = [...queue];
    } catch (error) {
      captureState.errors.push({
        id: nextUrl + "-" + Date.now(),
        timestamp: new Date().toISOString(),
        url: nextUrl,
        method: "CRAWL",
        errorText: error instanceof Error ? error.message : "Crawl navigation failed"
      });
      trimCollection(captureState.errors, 100);
    }
  }

  if (captureState.sessionId === sessionId && captureState.page) {
    await closeCaptureBrowser({ clearMetadata: false, reason: "crawl-complete" });
  }
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

function clampNumber(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return Math.min(max, Math.max(min, parsed));
}

function validateHttpUrl(value) {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only http/https URLs are supported.");
  }

  return url.toString();
}

function normalizeScanHeaders(input) {
  if (!input) {
    return [];
  }

  if (typeof input === "string") {
    return input
      .split(/\n+/)
      .map((line) => line.trim())
      .filter((line) => line.includes(":"))
      .slice(0, 20);
  }

  if (typeof input === "object") {
    return Object.entries(input)
      .slice(0, 20)
      .map(([key, value]) => `${key}: ${String(value)}`);
  }

  return [];
}

function buildCaptureSummaryPayload(capture) {
  const exchanges = Array.isArray(capture?.exchanges) ? capture.exchanges : [];
  const errors = Array.isArray(capture?.errors) ? capture.errors : [];

  return {
    targetUrl: capture?.targetUrl || "",
    capturedAt: new Date().toISOString(),
    totals: {
      exchanges: exchanges.length,
      errors: errors.length
    },
    exchanges: exchanges.slice(0, 30).map((exchange) => ({
      request: {
        method: exchange.request?.method || "",
        url: exchange.request?.url || "",
        resourceType: exchange.request?.resourceType || "",
        headers: exchange.request?.headers || {},
        bodyPreview: String(exchange.request?.postData || "").slice(0, 1200)
      },
      response: {
        status: exchange.response?.status || null,
        statusText: exchange.response?.statusText || "",
        url: exchange.response?.url || "",
        headers: exchange.response?.headers || {},
        bodyPreview: String(exchange.response?.bodyPreview || "").slice(0, 1200)
      }
    })),
    errors: errors.slice(0, 20)
  };
}

async function saveAnalysisRecord(payload) {
  if (!supabase) {
    return { saved: false, reason: "Supabase credentials are not configured." };
  }

  const { error } = await supabase.from("capture_har_analyses").insert(payload);

  if (error) {
    return { saved: false, reason: error.message };
  }

  return { saved: true };
}

async function saveCaptureRecord(payload) {
  if (!supabase) {
    rememberCaptureEvent(payload, "Supabase credentials are not configured.");
    return { saved: false, reason: "Supabase credentials are not configured." };
  }

  const { error } = await supabase.from("capture_http_events").insert(payload);

  if (error) {
    rememberCaptureEvent(payload, error.message);
    return { saved: false, reason: error.message };
  }

  return { saved: true };
}

async function saveInspectionRun(payload) {
  if (!supabase) {
    return { saved: false, reason: "Supabase credentials are not configured." };
  }

  const { error } = await supabase.from("capture_inspection_runs").insert(payload);

  if (error) {
    return { saved: false, reason: error.message };
  }

  return { saved: true };
}

async function loadRecentHarAnalyses(limit = 10) {
  if (!supabase) {
    return [];
  }

  const { data, error } = await supabase
    .from("capture_har_analyses")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error) {
    throw error;
  }

  return data || [];
}

async function loadRecentCaptureEvents(limit = 20) {
  if (!supabase) {
    return [];
  }

  const { data, error } = await supabase
    .from("capture_http_events")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error) {
    throw error;
  }

  return data || [];
}

async function loadRecentInspectionRuns(limit = 15) {
  if (!supabase) {
    return [];
  }

  const { data, error } = await supabase
    .from("capture_inspection_runs")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error) {
    throw error;
  }

  return data || [];
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

    touchCaptureActivity();

    const id = request.url() + "-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
    const entry = {
      id,
      timestamp: new Date().toISOString(),
      persisted: false,
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

    touchCaptureActivity();

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
      if (!pairedEntry.persisted) {
        pairedEntry.persisted = true;
        void saveCaptureRecord({
          capture_session_id: captureState.sessionId,
          target_url: captureState.targetUrl,
          request_timestamp: pairedEntry.timestamp,
          request_method: pairedEntry.request?.method ?? null,
          request_url: pairedEntry.request?.url ?? null,
          request_resource_type: pairedEntry.request?.resourceType ?? null,
          request_headers: pairedEntry.request?.headers ?? {},
          request_body: pairedEntry.request?.postData ?? "",
          response_timestamp: responsePayload.timestamp,
          response_url: responsePayload.url,
          response_status: responsePayload.status,
          response_status_text: responsePayload.statusText,
          response_headers: responsePayload.headers,
          response_body_preview: responsePayload.bodyPreview,
          error_text: null
        }).catch(() => {});
      }
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

    touchCaptureActivity();

    const failedEntry = {
      id: url + "-" + Date.now(),
      timestamp: new Date().toISOString(),
      url,
      method: request.method(),
      errorText: request.failure()?.errorText || "Unknown error"
    };

    captureState.errors.push(failedEntry);
    trimCollection(captureState.errors, 100);

    void saveCaptureRecord({
      capture_session_id: captureState.sessionId,
      target_url: captureState.targetUrl,
      request_timestamp: failedEntry.timestamp,
      request_method: failedEntry.method,
      request_url: failedEntry.url,
      request_resource_type: request.resourceType(),
      request_headers: sanitizeHeaders(request.headers()),
      request_body: request.postData() || "",
      response_timestamp: null,
      response_url: null,
      response_status: null,
      response_status_text: null,
      response_headers: {},
      response_body_preview: "",
      error_text: failedEntry.errorText
    }).catch(() => {});
  });
}

async function launchCaptureSession(domain, excludePatterns = [], authOptions = {}) {
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
    headless: playwrightHeadless,
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
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

  const sessionWasApplied = await applySessionValue(context, targetUrl, authOptions.sessionValue);

  captureState.browser = browser;
  captureState.context = context;
  captureState.startedAt = new Date().toISOString();
  captureState.sessionId = randomUUID();
  captureState.targetUrl = targetUrl;
  captureState.excludePatterns = excludePatterns;
  captureState.lastActivityAt = captureState.startedAt;
  captureState.stoppedAt = null;
  captureState.stopReason = null;

  const page = await context.newPage();
  captureState.page = page;
  attachCaptureListeners(page, targetHost);
  await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
  scheduleCaptureIdleStop();

  if (!sessionWasApplied) {
    await attemptPageLogin(page, authOptions.credentials);
  }

  if (captureReadyDelayMs > 0) {
    await sleep(captureReadyDelayMs);
  }

  if (captureCrawlEnabled) {
    const sessionId = captureState.sessionId;
    const crawlStartUrl = normalizeCrawlUrl(page.url(), targetUrl, targetHost) || targetUrl;
    void crawlCapturePages(page, crawlStartUrl, targetHost, sessionId).catch((error) => {
      captureState.errors.push({
        id: targetUrl + "-" + Date.now(),
        timestamp: new Date().toISOString(),
        url: targetUrl,
        method: "CRAWL",
        errorText: error instanceof Error ? error.message : "Crawl failed"
      });
      trimCollection(captureState.errors, 100);
      if (captureState.sessionId === sessionId && captureState.page) {
        void closeCaptureBrowser({ clearMetadata: false, reason: "crawl-error" });
      }
    });
  }
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

app.get("/api/capture/status", (_request, response) => {
  response.json({
    active: Boolean(captureState.page),
    startedAt: captureState.startedAt,
    sessionId: captureState.sessionId,
    targetUrl: captureState.targetUrl,
    excludePatterns: captureState.excludePatterns,
    lastActivityAt: captureState.lastActivityAt,
    stoppedAt: captureState.stoppedAt,
    stopReason: captureState.stopReason,
    idleAutoStopMs: captureIdleAutoStopMs,
    crawlEnabled: captureCrawlEnabled,
    crawlActive: captureState.crawlActive,
    crawlCompleted: captureState.crawlCompleted,
    crawlVisited: captureState.crawlVisited,
    crawlQueueLength: captureState.crawlQueue.length,
    crawlMaxPages: captureState.crawlMaxPages,
    loginAttempted: captureState.loginAttempted,
    loginStatus: captureState.loginStatus,
    loginError: captureState.loginError,
    sessionApplied: captureState.sessionApplied,
    sessionStatus: captureState.sessionStatus,
    sessionError: captureState.sessionError,
    exchanges: captureState.exchanges,
    errors: captureState.errors
  });
});

app.post("/api/capture/start", async (request, response) => {
  if (disableCapture) {
    response.status(403).json({
      error: "Capture is disabled on this backend. Use the local app for browser capture."
    });
    return;
  }

  const { domain, excludePatterns, credentials, sessionValue } = request.body ?? {};

  try {
    await launchCaptureSession(
      domain,
      Array.isArray(excludePatterns) ? excludePatterns.filter(Boolean) : [],
      {
        credentials: credentials && typeof credentials === "object" ? credentials : {},
        sessionValue: typeof sessionValue === "string" ? sessionValue : ""
      }
    );
    response.json({
      ok: true,
      sessionId: captureState.sessionId,
      targetUrl: captureState.targetUrl,
      startedAt: captureState.startedAt,
      excludePatterns: captureState.excludePatterns,
      crawlEnabled: captureCrawlEnabled,
      crawlMaxPages: captureState.crawlMaxPages,
      loginAttempted: captureState.loginAttempted,
      loginStatus: captureState.loginStatus,
      loginError: captureState.loginError,
      sessionApplied: captureState.sessionApplied,
      sessionStatus: captureState.sessionStatus,
      sessionError: captureState.sessionError
    });
  } catch (error) {
    response.status(400).json({
      error: error instanceof Error ? error.message : "Failed to start capture session"
    });
  }
});

app.post("/api/capture/stop", async (_request, response) => {
  if (disableCapture) {
    response.json({ ok: true, disabled: true });
    return;
  }

  await closeCaptureBrowser({ reason: "manual" });
  response.json({ ok: true });
});

app.get("/api/health", (_request, response) => {
  response.json({
    ok: true,
    service: "http-analyzer-api",
    supabaseConfigured: Boolean(supabase),
    captureDisabled: disableCapture,
    captureIdleAutoStopMs,
    captureCrawlEnabled,
    captureCrawlMaxPages,
    captureCrawlPageDelayMs,
    captureLoginWaitMs,
    sqlmapDisabled: disableSqlmap,
    sqlmapBin
  });
});

app.post("/api/inspection-runs", async (request, response) => {
  const payload = request.body ?? {};

  if (!payload.target_url) {
    response.status(400).json({ error: "target_url is required." });
    return;
  }

  try {
    const saved = await saveInspectionRun({
      capture_session_id: payload.capture_session_id ?? null,
      target_url: payload.target_url,
      started_at: payload.started_at ?? null,
      ended_at: payload.ended_at ?? new Date().toISOString(),
      total_exchanges: Number(payload.total_exchanges ?? 0),
      total_errors: Number(payload.total_errors ?? 0),
      total_findings: Number(payload.total_findings ?? 0),
      critical_findings: Number(payload.critical_findings ?? 0),
      high_findings: Number(payload.high_findings ?? 0),
      security_only: Boolean(payload.security_only),
      mask_sensitive: Boolean(payload.mask_sensitive),
      excluded_patterns: Array.isArray(payload.excluded_patterns) ? payload.excluded_patterns : [],
      owasp_summary: Array.isArray(payload.owasp_summary) ? payload.owasp_summary : [],
      endpoint_summary: Array.isArray(payload.endpoint_summary) ? payload.endpoint_summary : [],
      report_snapshot:
        payload.report_snapshot && typeof payload.report_snapshot === "object"
          ? payload.report_snapshot
          : {}
    });

    if (!saved.saved) {
      response.status(400).json(saved);
      return;
    }

    response.json(saved);
  } catch (error) {
    response.status(400).json({
      error: error instanceof Error ? error.message : "Failed to save inspection run"
    });
  }
});

app.post("/api/capture-events/batch", async (request, response) => {
  const events = Array.isArray(request.body?.events) ? request.body.events : null;

  if (!events || events.length === 0) {
    response.status(400).json({ error: "events array is required." });
    return;
  }

  if (!supabase) {
    response.status(400).json({ saved: false, reason: "Supabase credentials are not configured." });
    return;
  }

  const { error } = await supabase.from("capture_http_events").insert(events);

  if (error) {
    response.status(400).json({ saved: false, reason: error.message });
    return;
  }

  response.json({ saved: true, count: events.length });
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

app.post("/api/sqlmap/scan", async (request, response) => {
  if (disableSqlmap) {
    response.status(403).json({ error: "SQLMap scanning is disabled on this backend." });
    return;
  }

  const payload = request.body ?? {};

  try {
    const targetUrl = validateHttpUrl(payload.url);
    const method = String(payload.method || "GET").toUpperCase();
    const level = clampNumber(payload.level, 1, 5, 1);
    const risk = clampNumber(payload.risk, 1, 3, 1);
    const data = String(payload.data || "");
    const headers = normalizeScanHeaders(payload.headers);
    const args = [
      "-u",
      targetUrl,
      "--batch",
      "--level",
      String(level),
      "--risk",
      String(risk),
      "--timeout",
      "10",
      "--retries",
      "1"
    ];

    if (method && method !== "GET") {
      args.push("--method", method);
    }

    if (data) {
      args.push("--data", data);
    }

    for (const header of headers) {
      args.push("-H", header);
    }

    const startedAt = new Date().toISOString();
    const { stdout, stderr } = await execFileAsync(sqlmapBin, args, {
      timeout: 180000,
      maxBuffer: 1024 * 1024 * 3
    });

    response.json({
      ok: true,
      command: sqlmapBin,
      args,
      startedAt,
      endedAt: new Date().toISOString(),
      stdout: stdout.slice(-120000),
      stderr: stderr.slice(-20000)
    });
  } catch (error) {
    if (error?.code === "ENOENT") {
      response.status(501).json({
        error: "sqlmap is not installed or not found in PATH.",
        installHint: "Install sqlmap locally or set SQLMAP_BIN to the sqlmap executable path."
      });
      return;
    }

    response.status(400).json({
      error: error instanceof Error ? error.message : "SQLMap scan failed",
      stdout: error?.stdout ? String(error.stdout).slice(-120000) : "",
      stderr: error?.stderr ? String(error.stderr).slice(-20000) : ""
    });
  }
});

app.post("/api/openai/summary", async (request, response) => {
  const { apiKey, model, prompt, capture } = request.body ?? {};
  const key = String(apiKey || "").trim();
  const selectedModel = String(model || "gpt-4.1-mini").trim();
  const userPrompt = String(prompt || "").trim();

  if (!key) {
    response.status(400).json({ error: "OpenAI API key is required." });
    return;
  }

  if (!userPrompt) {
    response.status(400).json({ error: "Prompt is required." });
    return;
  }

  try {
    const capturePayload = buildCaptureSummaryPayload(capture);
    const openaiResponse = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: selectedModel,
        messages: [
          {
            role: "system",
            content:
              "You are a senior web security analyst. Summarize HTTP capture data clearly, prioritize exploitable risks, and avoid inventing evidence."
          },
          {
            role: "user",
            content: `${userPrompt}\n\nHTTP_CAPTURE_JSON:\n${JSON.stringify(capturePayload, null, 2)}`
          }
        ],
        temperature: 0.2
      })
    });

    const rawText = await openaiResponse.text();
    let data = {};
    try {
      data = rawText ? JSON.parse(rawText) : {};
    } catch {
      data = { rawText };
    }

    if (!openaiResponse.ok) {
      response.status(openaiResponse.status).json({
        error: data?.error?.message || rawText || "OpenAI summary request failed."
      });
      return;
    }

    response.json({
      ok: true,
      model: selectedModel,
      summary: data?.choices?.[0]?.message?.content || "",
      usage: data?.usage || null
    });
  } catch (error) {
    response.status(400).json({
      error: error instanceof Error ? error.message : "OpenAI summary request failed."
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

app.get("/api/recent-analyses", async (_request, response) => {
  const [harAnalyses, captureEvents, inspectionRuns] = await Promise.allSettled([
    loadRecentHarAnalyses(10),
    loadRecentCaptureEvents(20),
    loadRecentInspectionRuns(15)
  ]);

  const errors = [harAnalyses, captureEvents, inspectionRuns]
    .filter((item) => item.status === "rejected")
    .map((item) => {
      const reason = item.reason;
      return reason instanceof Error ? reason.message : reason?.message || String(reason);
    });

  if (errors.length > 0) {
    console.warn("Recent analyses partial load failure:", errors.join(" | "));
  }

  response.json({
    harAnalyses: harAnalyses.status === "fulfilled" ? harAnalyses.value : [],
    captureEvents: [
      ...memoryRecentCaptureEvents,
      ...(captureEvents.status === "fulfilled" ? captureEvents.value : [])
    ].slice(0, 50),
    inspectionRuns: inspectionRuns.status === "fulfilled" ? inspectionRuns.value : [],
    partialErrors: errors
  });
});

const port = process.env.PORT || 4000;
const host = process.env.HOST || (process.env.RENDER ? "0.0.0.0" : "127.0.0.1");
app.listen(port, host, () => {
  console.log(`HAR analysis server listening on http://${host}:${port}`);
});
