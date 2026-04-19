import { useEffect, useRef, useState } from "react";
import { supabase } from "./lib/supabase";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:4000";
const GOOGLE_CLIENT_ID =
  "924920443826-k59m97pgabmdb42qv9cq63plmuuvvn7s.apps.googleusercontent.com";
const AUTH_STORAGE_KEY = "http-analyzer-auth-user";
const ALLOWED_GOOGLE_EMAIL = "totoriverce@gmail.com";
const LOCAL_HAR_HISTORY_KEY = "http-analyzer-local-har-history";
const LOCAL_INSPECTION_RUNS_KEY = "http-analyzer-local-inspection-runs";
const LOCAL_CAPTURE_EVENTS_KEY = "http-analyzer-local-capture-events";
const ABORTED_ERROR_REGEX = /net::ERR_ABORTED/i;
const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1"]);
const TOKEN_REGEX = new RegExp(
  `("(?:\\\\.|[^"])*":)|("(?:\\\\.|[^"])*")|('(?:\\\\.|[^'])*')|(<!--.*?-->)|(<!DOCTYPE[^>]*>)|(</?[\\w:-]+[^>]*>)|\\b\\d+(?:\\.\\d+)?\\b|\\btrue\\b|\\bfalse\\b|\\bnull\\b|[{}\\[\\](),:]`,
  "g"
);
const SECURITY_REGEX =
  /\b(authorization|cookie|set-cookie|token|bearer|csrf|password|secret|session|jwt|api[-_ ]?key)\b/i;
const SECURITY_REASON_REGEX =
  /\b(authorization|cookie|set-cookie|token|bearer|csrf|password|secret|session|jwt|api[-_ ]?key)\b/gi;
const URL_SECRET_REGEX =
  /(?:[?&](?:access_token|refresh_token|id_token|token|api[_-]?key|apikey|secret|password|passwd|session(?:id)?|jwt|code)=)[^&]+/i;
const RESPONSE_SECRET_REGEX =
  /\b(access_token|refresh_token|id_token|api[_-]?key|apikey|client_secret|private[_-]?key|authorization|bearer|password|passwd|secret|session(?:id)?|jwt)\b/i;
const JWT_REGEX = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b/;
const PRIVATE_KEY_REGEX = /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/i;
const STACK_TRACE_REGEX =
  /(traceback \(most recent call last\)|exception:|stack trace|sql syntax.*mysql|syntax error at or near|ORA-\d{5}|ReferenceError:|TypeError:|NullPointerException|at [\w.$]+\(.*:\d+:\d+\))/i;
const DIRECTORY_LISTING_REGEX = /<title>\s*Index of\s*\/|<h1>\s*Index of\s*\/|directory listing/i;
const SERVER_DISCLOSURE_REGEX =
  /\b(nginx\/\d|apache\/\d|iis\/\d|php\/\d|express|node\.js|gunicorn\/\d|uvicorn\/\d|tomcat\/\d)\b/i;
const SQLI_REGEX =
  /(?:'|"|%27|%22)\s*(?:or|and)\s*(?:'?\d+'?\s*=\s*'?\d+'?|true|false)|union\s+select|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|information_schema|load_file\s*\(/i;
const XSS_REGEX =
  /<script\b|javascript:|onerror\s*=|onload\s*=|<img[^>]+src=|<svg[^>]+onload=|document\.cookie|alert\s*\(/i;
const PATH_TRAVERSAL_REGEX = /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%252e%252e%252f)/i;
const COMMAND_INJECTION_REGEX = /(?:;|\|\||&&|\|)\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|powershell|cmd)\b/i;
const OPEN_REDIRECT_REGEX =
  /(?:[?&](?:next|url|target|dest|destination|redirect|return|returnUrl|continue)=https?:\/\/)[^&]+/i;
const SSRF_REGEX =
  /(?:[?&](?:url|uri|path|target|dest|destination|endpoint)=https?:\/\/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.169\.254)/i;

const SEVERITY_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low"
};

const OWASP_LABELS = {
  A01: "A01 Broken Access Control",
  A02: "A02 Cryptographic Failures",
  A03: "A03 Injection",
  A04: "A04 Insecure Design",
  A05: "A05 Security Misconfiguration",
  A06: "A06 Vulnerable and Outdated Components",
  A07: "A07 Identification and Authentication Failures",
  A08: "A08 Software and Data Integrity Failures",
  A09: "A09 Security Logging and Monitoring Failures",
  A10: "A10 Server-Side Request Forgery"
};

const FIXED_EXCLUDE_PATTERNS = [
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".svg",
  ".ico",
  ".bmp",
  ".avif",
  ".tiff",
  ".jfif",
  "/image",
  "image="
];

function prettyJson(value) {
  if (!value) {
    return "";
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function sanitizeMermaidText(value) {
  return String(value || "")
    .replace(/"/g, '\\"')
    .replace(/\n+/g, " ")
    .trim();
}

function buildCaptureMermaid(exchanges) {
  if (!Array.isArray(exchanges) || exchanges.length === 0) {
    return 'flowchart LR\n  A["No Capture Data"]';
  }

  const rootUrl = exchanges[0]?.request?.url || "";
  let rootHost = "Captured Site";

  try {
    rootHost = new URL(rootUrl).hostname || rootHost;
  } catch {
    rootHost = "Captured Site";
  }

  const lines = ['flowchart LR', `  site["${sanitizeMermaidText(rootHost)}"]`];
  const seenHosts = new Set();
  const seenEndpoints = new Set();

  exchanges.slice(0, 24).forEach((exchange, index) => {
    const requestUrl = exchange?.request?.url || "";
    const method = exchange?.request?.method || "GET";
    const endpointLabel = `${method} ${exchange?.endpointKey || requestUrl || `Request ${index + 1}`}`;
    let host = rootHost;

    try {
      host = new URL(requestUrl).hostname || rootHost;
    } catch {
      host = rootHost;
    }

    const hostId = `host${index}`;
    const endpointId = `endpoint${index}`;

    if (!seenHosts.has(host)) {
      lines.push(`  ${hostId}["${sanitizeMermaidText(host)}"]`);
      lines.push(`  site --> ${hostId}`);
      seenHosts.add(host);
    } else {
      const existingHostIndex = exchanges
        .slice(0, index)
        .findIndex((item) => {
          try {
            return new URL(item?.request?.url || "").hostname === host;
          } catch {
            return false;
          }
        });

      if (existingHostIndex >= 0) {
        lines.push(`  host${existingHostIndex} --> ${endpointId}`);
        seenEndpoints.add(endpointLabel);
        lines.push(`  ${endpointId}["${sanitizeMermaidText(endpointLabel)}"]`);
        return;
      }
    }

    lines.push(`  ${endpointId}["${sanitizeMermaidText(endpointLabel)}"]`);
    lines.push(`  ${hostId} --> ${endpointId}`);
    seenEndpoints.add(endpointLabel);
  });

  return lines.join("\n");
}

function isAbortedErrorText(value) {
  return ABORTED_ERROR_REGEX.test(String(value || ""));
}

function isLocalRuntime() {
  if (typeof window === "undefined") {
    return true;
  }

  return LOCAL_HOSTNAMES.has(window.location.hostname);
}

async function loadRecentFromSupabase() {
  if (!supabase) {
    return {
      harAnalyses: [],
      captureEvents: [],
      inspectionRuns: []
    };
  }

  const [harResponse, eventsResponse, runsResponse] = await Promise.all([
    supabase.from("capture_har_analyses").select("*").order("created_at", { ascending: false }).limit(10),
    supabase.from("capture_http_events").select("*").order("created_at", { ascending: false }).limit(20),
    supabase.from("capture_inspection_runs").select("*").order("created_at", { ascending: false }).limit(15)
  ]);

  if (harResponse.error || eventsResponse.error || runsResponse.error) {
    throw harResponse.error || eventsResponse.error || runsResponse.error;
  }

  return {
    harAnalyses: harResponse.data || [],
    captureEvents: eventsResponse.data || [],
    inspectionRuns: runsResponse.data || []
  };
}

function NavigationIcon({ name }) {
  const commonProps = {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": "true"
  };

  switch (name) {
    case "overview":
      return (
        <svg {...commonProps}>
          <rect x="3" y="4" width="7" height="7" rx="1.5" />
          <rect x="14" y="4" width="7" height="5" rx="1.5" />
          <rect x="14" y="12" width="7" height="8" rx="1.5" />
          <rect x="3" y="14" width="7" height="6" rx="1.5" />
        </svg>
      );
    case "capture":
      return (
        <svg {...commonProps}>
          <path d="M4 8.5 12 4l8 4.5v7L12 20l-8-4.5z" />
          <path d="M12 11.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5Z" />
          <path d="M8.5 9.5h.01M15.5 9.5h.01" />
        </svg>
      );
    case "findings":
      return (
        <svg {...commonProps}>
          <path d="M12 3 4 7v5c0 5 3.4 7.8 8 9 4.6-1.2 8-4 8-9V7z" />
          <path d="M12 8v5" />
          <path d="M12 16h.01" />
        </svg>
      );
    case "har":
      return (
        <svg {...commonProps}>
          <path d="M8 3h6l5 5v11a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" />
          <path d="M14 3v5h5" />
          <path d="M9 13h6M9 17h6" />
        </svg>
      );
    case "recent":
      return (
        <svg {...commonProps}>
          <circle cx="12" cy="12" r="8" />
          <path d="M12 7v5l3 2" />
        </svg>
      );
    default:
      return null;
  }
}

function getStoredValue(key, fallback = "") {
  if (typeof window === "undefined") {
    return fallback;
  }

  try {
    return window.localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
}

function setStoredValue(key, value) {
  if (typeof window === "undefined") {
    return;
  }

  try {
    window.localStorage.setItem(key, value);
  } catch {
    return;
  }
}

function getStoredJson(key, fallback = null) {
  const raw = getStoredValue(key);
  if (!raw) {
    return fallback;
  }

  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function normalizeHeaderValue(value) {
  if (Array.isArray(value)) {
    return value.join("\n");
  }

  if (value === undefined || value === null) {
    return "";
  }

  return String(value);
}

function normalizeHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers || {}).map(([key, value]) => [key.toLowerCase(), normalizeHeaderValue(value)])
  );
}

function getHeader(headers, name) {
  return headers[name.toLowerCase()] || "";
}

function collectSetCookieHeaders(headers) {
  const raw = getHeader(headers, "set-cookie");
  if (!raw) {
    return [];
  }

  return String(raw)
    .split(/\n+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function extractKeywords(value) {
  const matches = String(value || "").match(SECURITY_REASON_REGEX) || [];
  return [...new Set(matches.map((item) => item.toLowerCase()))];
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function truncateText(value, max = 220) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) {
    return "";
  }

  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function findSnippet(value, pattern, fallback = "") {
  const source = String(value || "");
  if (!source) {
    return fallback;
  }

  const regex = pattern instanceof RegExp ? new RegExp(pattern.source, pattern.flags.replace("g", "")) : null;
  const match = regex ? regex.exec(source) : null;
  if (!match) {
    return truncateText(source, 180) || fallback;
  }

  const start = Math.max(0, match.index - 60);
  const end = Math.min(source.length, match.index + match[0].length + 90);
  return truncateText(source.slice(start, end), 220);
}

function containsReflectedPayload(requestValue, responseValue, regex) {
  const requestMatch = String(requestValue || "").match(regex);
  if (!requestMatch?.[0] || !responseValue) {
    return false;
  }

  const reflected = new RegExp(escapeRegExp(requestMatch[0]), "i");
  return reflected.test(String(responseValue));
}

function getConfidenceLabel(level) {
  switch (level) {
    case "high":
      return "높음 - 응답/헤더 근거가 직접 보입니다";
    case "medium":
      return "중간 - 맥락상 의심되며 재현 검증이 권장됩니다";
    default:
      return "낮음 - 공격 흔적 또는 설정 힌트 수준입니다";
  }
}

function buildFinding({
  key,
  title,
  severity,
  owasp,
  area,
  evidence,
  guide,
  remediation,
  checklist = [],
  confidence = "medium"
}) {
  return {
    key,
    title,
    severity,
    severityLabel: SEVERITY_LABELS[severity] || severity,
    owasp,
    owaspLabel: OWASP_LABELS[owasp] || owasp,
    area,
    evidence,
    guide,
    remediation,
    checklist,
    confidence,
    confidenceLabel: getConfidenceLabel(confidence)
  };
}

function summarizeFindingsByOwasp(findings) {
  const counts = new Map();

  for (const finding of findings) {
    const key = finding.owasp || "Unmapped";
    counts.set(key, (counts.get(key) || 0) + 1);
  }

  return [...counts.entries()]
    .map(([key, count]) => ({
      key,
      label: OWASP_LABELS[key] || key,
      count
    }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

function normalizeEndpoint(url) {
  if (!url) {
    return "(unknown)";
  }

  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return url.split("?")[0] || url;
  }
}

function getCombinedExcludePatterns(input) {
  const userPatterns = String(input || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  return [...new Set([...FIXED_EXCLUDE_PATTERNS, ...userPatterns])];
}

function isImageLikeExchange(exchange) {
  const resourceType = String(exchange.request?.resourceType || "").toLowerCase();
  if (resourceType === "image") {
    return true;
  }

  const urls = [exchange.request?.url || "", exchange.response?.url || ""].map((value) =>
    String(value).toLowerCase()
  );

  return urls.some((url) =>
    [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif", ".tiff", ".jfif"]
      .some((ext) => url.includes(ext))
  );
}

function getSeverityWeight(severity) {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 2;
    default:
      return 1;
  }
}

function buildFindingSignature(finding, exchange) {
  return `${normalizeEndpoint(exchange.request?.url || exchange.response?.url)}::${finding.key}`;
}

function getHostFromUrl(url) {
  if (!url) {
    return "";
  }

  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function buildSuppressionRule(scope, finding, exchange) {
  const endpoint = normalizeEndpoint(exchange.request?.url || exchange.response?.url);
  const host = getHostFromUrl(exchange.request?.url || exchange.response?.url);

  if (scope === "global") {
    return {
      id: `global::${finding.key}`,
      scope,
      findingKey: finding.key,
      label: `Global · ${finding.title}`
    };
  }

  if (scope === "host") {
    return {
      id: `host::${host}::${finding.key}`,
      scope,
      host,
      findingKey: finding.key,
      label: `Host(${host || "unknown"}) · ${finding.title}`
    };
  }

  if (scope === "session") {
    return {
      id: `session::${buildFindingSignature(finding, exchange)}`,
      scope,
      signature: buildFindingSignature(finding, exchange),
      findingKey: finding.key,
      label: `Session · ${endpoint} · ${finding.title}`
    };
  }

  return {
    id: `endpoint::${endpoint}::${finding.key}`,
    scope: "endpoint",
    endpoint,
    findingKey: finding.key,
    label: `Endpoint(${endpoint}) · ${finding.title}`
  };
}

function matchesSuppressionRule(rule, finding, exchange) {
  const endpoint = normalizeEndpoint(exchange.request?.url || exchange.response?.url);
  const host = getHostFromUrl(exchange.request?.url || exchange.response?.url);
  const signature = buildFindingSignature(finding, exchange);

  if (rule.scope === "global") {
    return rule.findingKey === finding.key;
  }

  if (rule.scope === "host") {
    return rule.findingKey === finding.key && rule.host === host;
  }

  if (rule.scope === "session") {
    return rule.signature === signature;
  }

  return rule.findingKey === finding.key && rule.endpoint === endpoint;
}

function summarizeEndpoints(exchanges) {
  const buckets = new Map();

  for (const exchange of exchanges) {
    const endpoint = normalizeEndpoint(exchange.request?.url || exchange.response?.url);
    const bucket = buckets.get(endpoint) || {
      endpoint,
      requests: 0,
      findings: 0,
      score: 0,
      highestSeverity: "low",
      topCategories: new Map()
    };

    bucket.requests += 1;

    for (const finding of exchange.securityFindings || []) {
      bucket.findings += 1;
      bucket.score += getSeverityWeight(finding.severity);
      bucket.topCategories.set(finding.owaspLabel, (bucket.topCategories.get(finding.owaspLabel) || 0) + 1);

      if (getSeverityWeight(finding.severity) > getSeverityWeight(bucket.highestSeverity)) {
        bucket.highestSeverity = finding.severity;
      }
    }

    buckets.set(endpoint, bucket);
  }

  return [...buckets.values()]
    .map((bucket) => ({
      ...bucket,
      highestSeverityLabel: SEVERITY_LABELS[bucket.highestSeverity] || bucket.highestSeverity,
      topCategories: [...bucket.topCategories.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([label, count]) => `${label} (${count})`)
    }))
    .sort((a, b) => b.score - a.score || b.findings - a.findings || a.endpoint.localeCompare(b.endpoint));
}

function buildDiffSummary(current, previous) {
  if (!previous) {
    return null;
  }

  const currentRequestHeaders = normalizeHeaders(current.request?.headers);
  const previousRequestHeaders = normalizeHeaders(previous.request?.headers);
  const currentResponseHeaders = normalizeHeaders(current.response?.headers);
  const previousResponseHeaders = normalizeHeaders(previous.response?.headers);

  const requestHeaderChanges = new Set([
    ...Object.keys(currentRequestHeaders).filter((key) => currentRequestHeaders[key] !== previousRequestHeaders[key]),
    ...Object.keys(previousRequestHeaders).filter((key) => currentRequestHeaders[key] !== previousRequestHeaders[key])
  ]);
  const responseHeaderChanges = new Set([
    ...Object.keys(currentResponseHeaders).filter((key) => currentResponseHeaders[key] !== previousResponseHeaders[key]),
    ...Object.keys(previousResponseHeaders).filter((key) => currentResponseHeaders[key] !== previousResponseHeaders[key])
  ]);

  const requestBodyChanged = (current.request?.postData || "") !== (previous.request?.postData || "");
  const responseBodyChanged = (current.response?.bodyPreview || "") !== (previous.response?.bodyPreview || "");
  const statusChanged = String(current.response?.status || "") !== String(previous.response?.status || "");

  if (
    requestHeaderChanges.size === 0 &&
    responseHeaderChanges.size === 0 &&
    !requestBodyChanged &&
    !responseBodyChanged &&
    !statusChanged
  ) {
    return {
      previousId: previous.id,
      summary: "이전 동일 엔드포인트 호출과 비교해 큰 차이가 없습니다.",
      requestHeaderChanges: [],
      responseHeaderChanges: [],
      requestHeaderDiffs: [],
      responseHeaderDiffs: [],
      requestBodyBefore: previous.request?.postData || "",
      requestBodyAfter: current.request?.postData || "",
      responseBodyBefore: previous.response?.bodyPreview || "",
      responseBodyAfter: current.response?.bodyPreview || "",
      statusBefore: String(previous.response?.status || ""),
      statusAfter: String(current.response?.status || "")
    };
  }

  return {
    previousId: previous.id,
    summary: [
      statusChanged ? "응답 상태가 변경되었습니다." : null,
      requestBodyChanged ? "요청 본문이 변경되었습니다." : null,
      responseBodyChanged ? "응답 본문이 변경되었습니다." : null,
      requestHeaderChanges.size > 0 ? `요청 헤더 ${requestHeaderChanges.size}건 변경` : null,
      responseHeaderChanges.size > 0 ? `응답 헤더 ${responseHeaderChanges.size}건 변경` : null
    ]
      .filter(Boolean)
      .join(" "),
    requestHeaderChanges: [...requestHeaderChanges].slice(0, 8),
    responseHeaderChanges: [...responseHeaderChanges].slice(0, 8),
    requestHeaderDiffs: [...requestHeaderChanges].slice(0, 8).map((key) => ({
      key,
      before: previousRequestHeaders[key] || "",
      after: currentRequestHeaders[key] || ""
    })),
    responseHeaderDiffs: [...responseHeaderChanges].slice(0, 8).map((key) => ({
      key,
      before: previousResponseHeaders[key] || "",
      after: currentResponseHeaders[key] || ""
    })),
    requestBodyBefore: previous.request?.postData || "",
    requestBodyAfter: current.request?.postData || "",
    responseBodyBefore: previous.response?.bodyPreview || "",
    responseBodyAfter: current.response?.bodyPreview || "",
    statusBefore: String(previous.response?.status || ""),
    statusAfter: String(current.response?.status || "")
  };
}

function maskSensitiveText(value) {
  return String(value || "")
    .replace(/(authorization"\s*:\s*")[^"]+(")/gi, '$1***MASKED***$2')
    .replace(/(authorization:\s*)(.+)/gi, "$1***MASKED***")
    .replace(/(bearer\s+)[A-Za-z0-9._-]+/gi, "$1***MASKED***")
    .replace(/((?:set-cookie|cookie)"\s*:\s*")[^"]+(")/gi, '$1***MASKED***$2')
    .replace(/((?:set-cookie|cookie):\s*)(.+)/gi, "$1***MASKED***")
    .replace(/((?:access_token|refresh_token|id_token|token|api[_-]?key|apikey|secret|password|passwd|session(?:id)?|jwt)=)[^&\s]+/gi, "$1***MASKED***")
    .replace(/(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)[\s\S]*?(-----END (?:RSA |EC |DSA )?PRIVATE KEY-----)/gi, "$1\n***MASKED***\n$2")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b/g, "***MASKED_JWT***");
}

function maybeMask(value, enabled) {
  return enabled ? maskSensitiveText(value) : String(value || "");
}

function downloadTextFile(content, fileName, type = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type });
  const blobUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = blobUrl;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(blobUrl);
}

function buildInspectionConclusion({ totalFindings, criticalFindings, highFindings, totalErrors }) {
  if (criticalFindings > 0) {
    return "즉시 조치 필요: Critical finding이 존재하므로 우선 차단과 원인 분석이 필요합니다.";
  }

  if (highFindings > 0) {
    return "우선 개선 권장: High finding이 존재하므로 재현 검증 후 빠른 시정이 필요합니다.";
  }

  if (totalFindings > 0 || totalErrors > 0) {
    return "추가 검토 필요: 치명 이슈는 없지만 보안 징후 또는 오류 응답이 보여 후속 점검이 필요합니다.";
  }

  return "양호: 현재 캡처 범위에서는 두드러진 보안 이상 징후가 확인되지 않았습니다.";
}

function buildPeriodStats(runs) {
  const today = new Date();
  const windows = [
    { key: "7d", label: "최근 7일", days: 7 },
    { key: "30d", label: "최근 30일", days: 30 }
  ];

  return windows.map((windowInfo) => {
    const threshold = new Date(today);
    threshold.setDate(threshold.getDate() - (windowInfo.days - 1));

    const filtered = runs.filter((item) => {
      const createdAt = new Date(item.created_at || item.ended_at || item.started_at || 0);
      return !Number.isNaN(createdAt.getTime()) && createdAt >= threshold;
    });

    return {
      ...windowInfo,
      runCount: filtered.length,
      totalFindings: filtered.reduce((sum, item) => sum + Number(item.total_findings || 0), 0),
      criticalFindings: filtered.reduce((sum, item) => sum + Number(item.critical_findings || 0), 0),
      highFindings: filtered.reduce((sum, item) => sum + Number(item.high_findings || 0), 0),
      totalExchanges: filtered.reduce((sum, item) => sum + Number(item.total_exchanges || 0), 0)
    };
  });
}

function generateFindingPoc(finding, exchange) {
  const method = exchange.request?.method || "GET";
  const url = exchange.request?.url || exchange.response?.url || "";
  const headers = prettyJson(exchange.request?.headers);

  const bodyByKey = {
    "sqli-pattern": "' OR 1=1 --",
    "xss-pattern": "<script>alert(1)</script>",
    "path-traversal-pattern": "../../etc/passwd",
    "command-injection-pattern": "; id",
    "open-redirect-pattern": "https://attacker.example",
    "ssrf-pattern": "http://127.0.0.1:8080/admin"
  };

  const payload = bodyByKey[finding.key] || exchange.request?.postData || "";

  return [
    `Endpoint: ${normalizeEndpoint(url)}`,
    `Finding: ${finding.title}`,
    `OWASP: ${finding.owaspLabel}`,
    "",
    "Suggested verification flow:",
    ...finding.checklist.map((item, index) => `${index + 1}. ${item}`),
    "",
    "Replay template:",
    `Method: ${method}`,
    `URL: ${url}`,
    `Headers: ${headers || "{}"}`,
    `Body/Payload: ${payload || "(none)"}`
  ].join("\n");
}

function analyzeHarLocally(har) {
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
      slowestEntry = { time, url, method, status };
    }

    slowestEntries.push({ method, status, time, url });
    largestResponses.push({ method, status, size: responseSize, url });

    if (status >= 400) {
      failedRequests.push({ method, status, time, url });
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

function analyzeSecurityFindings(exchange) {
  const requestUrl = exchange.request?.url || "";
  const responseUrl = exchange.response?.url || "";
  const requestHeaders = normalizeHeaders(exchange.request?.headers);
  const responseHeaders = normalizeHeaders(exchange.response?.headers);
  const requestBody = exchange.request?.postData || "";
  const responseBody = exchange.response?.bodyPreview || "";
  const responseStatus = Number(exchange.response?.status || 0);
  const requestText = [requestUrl, prettyJson(exchange.request?.headers), requestBody].join("\n");
  const findings = [];
  const responseContentType = getHeader(responseHeaders, "content-type").toLowerCase();
  const isHtmlResponse =
    responseContentType.includes("text/html") ||
    responseBody.includes("<html") ||
    responseBody.includes("<!DOCTYPE html");
  const targetUrl = responseUrl || requestUrl;
  const isHttps = /^https:\/\//i.test(targetUrl);
  const responseSetCookie = getHeader(responseHeaders, "set-cookie");
  const hasSensitiveResponseBody =
    responseBody &&
    (RESPONSE_SECRET_REGEX.test(responseBody) || JWT_REGEX.test(responseBody) || PRIVATE_KEY_REGEX.test(responseBody));
  const hasSensitiveRequestBody =
    requestBody && (RESPONSE_SECRET_REGEX.test(requestBody) || JWT_REGEX.test(requestBody));
  const requestContainsXss = XSS_REGEX.test(requestText);
  const reflectedXss = containsReflectedPayload(requestText, responseBody, XSS_REGEX);
  const requestContainsSqli = SQLI_REGEX.test(requestText);
  const requestContainsTraversal = PATH_TRAVERSAL_REGEX.test(requestText);
  const requestContainsCommand = COMMAND_INJECTION_REGEX.test(requestText);
  const requestContainsOpenRedirect = OPEN_REDIRECT_REGEX.test(requestText);
  const requestContainsSsrf = SSRF_REGEX.test(requestText);
  const authorizationHeader = getHeader(requestHeaders, "authorization");
  const locationHeader = getHeader(responseHeaders, "location");
  const wwwAuthenticate = getHeader(responseHeaders, "www-authenticate");

  if (URL_SECRET_REGEX.test(requestUrl) || URL_SECRET_REGEX.test(responseUrl)) {
    const matchedUrl = URL_SECRET_REGEX.test(requestUrl) ? requestUrl : responseUrl;
    findings.push(
      buildFinding({
        key: "sensitive-data-in-url",
        title: "민감정보가 URL에 포함됨",
        severity: "high",
        owasp: "A02",
        area: "Request/Response URL",
        evidence: `민감 파라미터가 URL에 보입니다. Snippet: ${findSnippet(matchedUrl, URL_SECRET_REGEX, matchedUrl)}`,
        guide:
          "URL은 브라우저 기록, 프록시 로그, 서버 접근 로그, Referer 헤더에 남기 쉬워서 평문 저장 경로가 넓습니다. 특히 access_token, code, sessionid 같은 이름이 보이면 즉시 토큰 전달 방식을 재검토해야 합니다.",
        remediation:
          "민감값은 URL 쿼리 대신 POST 본문이나 Authorization 헤더로 옮기고, 이미 발급된 토큰은 폐기 후 재발급하세요. 로그, APM, CDN, 웹서버 access log에서 해당 파라미터를 마스킹하도록 설정하는 것도 필요합니다.",
        checklist: [
          "같은 기능을 Authorization 헤더 또는 POST body 기반으로 호출했을 때도 동작하는지 확인합니다.",
          "서버 access log, CDN log, 브라우저 히스토리에 해당 파라미터가 그대로 남는지 점검합니다.",
          "Referer를 발생시키는 외부 이동이 있는 페이지라면 값이 외부로 전파되는지 확인합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (hasSensitiveResponseBody) {
    findings.push(
      buildFinding({
        key: "secret-exposed-in-response-body",
        title: "응답 본문에 민감정보 노출 가능성",
        severity: PRIVATE_KEY_REGEX.test(responseBody) ? "critical" : "high",
        owasp: "A02",
        area: "Response Body",
        evidence: `응답 본문에 민감 데이터 흔적이 있습니다. Snippet: ${
          findSnippet(responseBody, PRIVATE_KEY_REGEX.test(responseBody) ? PRIVATE_KEY_REGEX : RESPONSE_SECRET_REGEX) ||
          "jwt/private key pattern"
        }`,
        guide:
          "응답 본문에 access token, API key, private key, 비밀번호, 세션값이 직접 포함되면 사용자 브라우저, 로그, 캐시, 3rd-party 스크립트에 그대로 노출될 수 있습니다. JWT 형태 문자열이나 private key 헤더가 보이면 즉시 유출 사고로 취급하는 편이 안전합니다.",
        remediation:
          "클라이언트에 반드시 필요한 최소 필드만 반환하고, 비밀값은 서버 측 저장소에 보관하세요. 이미 노출된 토큰/키는 회전하고, 직렬화 계층에서 민감 필드를 제외하는 응답 DTO 또는 allowlist 기반 serializer로 바꾸는 것이 좋습니다.",
        checklist: [
          "실제 응답 원문에서 토큰, 키, 개인식별자, 비밀번호가 그대로 내려오는지 재확인합니다.",
          "브라우저 개발자도구, CDN 캐시, API 로그에도 같은 값이 남는지 확인합니다.",
          "이미 노출된 자격증명이라면 즉시 폐기/회전 후 영향 범위를 추적합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (hasSensitiveRequestBody) {
    findings.push(
      buildFinding({
        key: "sensitive-request-payload",
        title: "요청 본문에 민감정보 포함",
        severity: isHttps ? "medium" : "high",
        owasp: "A02",
        area: "Request Body",
        evidence: `요청 본문에 인증 또는 비밀값 추정 키가 있습니다. Snippet: ${findSnippet(
          requestBody,
          RESPONSE_SECRET_REGEX
        )}`,
        guide:
          "로그인이나 토큰 교환처럼 정상적인 흐름일 수 있지만, 이 데이터가 애플리케이션 로그나 예외 메시지에 복사되면 2차 노출로 이어지기 쉽습니다. HTTP 평문 구간이 있다면 위험도는 더 높아집니다.",
        remediation:
          "민감 필드를 서버와 클라이언트 양쪽 로그에서 마스킹하고, HTTPS만 허용하며, 요청 저장 샘플링 기능이 있다면 password, token, secret 계열 키를 즉시 비식별화하세요.",
        checklist: [
          "애플리케이션 로그, APM, 에러 리포트에 요청 body가 그대로 저장되는지 확인합니다.",
          "TLS가 강제되지 않는 엔드포인트인지 확인하고, HTTP 접근이 가능하면 즉시 차단합니다.",
          "민감 필드 allowlist/denylist 기반 마스킹이 실제 저장 경로 전체에 적용됐는지 검토합니다."
        ],
        confidence: isHttps ? "medium" : "high"
      })
    );
  }

  if (/^basic\s+/i.test(authorizationHeader) || /^basic\s+/i.test(wwwAuthenticate)) {
    findings.push(
      buildFinding({
        key: "basic-auth-observed",
        title: "Basic 인증 사용 흔적",
        severity: isHttps ? "medium" : "high",
        owasp: "A07",
        area: "Request/Response Headers",
        evidence: /^basic\s+/i.test(authorizationHeader)
          ? "Authorization 헤더에 Basic 인증이 보입니다."
          : "WWW-Authenticate 헤더에 Basic challenge가 보입니다.",
        guide:
          "Basic 인증은 TLS 위에서만 제한적으로 허용하는 편이 안전합니다. 브라우저 자동 저장, 중간 프록시, 재전송 과정에서 자격증명이 노출되기 쉬워 현대 서비스의 기본 인증 방식으로는 권장되지 않습니다.",
        remediation:
          "가능하면 세션 기반 로그인, OAuth/OIDC, 단기 토큰 기반 인증으로 전환하세요. 유지가 필요하다면 HTTPS 강제, 재시도 제한, 자격증명 회전, 캐시 금지, 민감 로그 마스킹을 함께 적용해야 합니다.",
        checklist: [
          "HTTP로도 같은 엔드포인트가 열리는지 확인합니다.",
          "브라우저/프록시/로그에 Authorization 값이 저장되는지 확인합니다.",
          "대체 인증 수단으로 전환 가능한지 영향 범위를 검토합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (/^https?:\/\//i.test(locationHeader)) {
    findings.push(
      buildFinding({
        key: "absolute-location-observed",
        title: "외부 절대 URL Location 헤더 검토 필요",
        severity: "low",
        owasp: "A01",
        area: "Response Headers",
        evidence: `Location: ${locationHeader}`,
        guide:
          "절대 URL Location 자체는 정상일 수 있지만, 사용자 입력과 결합되면 open redirect 체인으로 이어질 수 있습니다. 인증 직후나 토큰 포함 URL이면 우선순위를 높여 봐야 합니다.",
        remediation:
          "리다이렉트 목적지는 내부 경로나 allowlist 기반 외부 목적지만 허용하세요. 로그인/로그아웃/결제 플로우에서는 user-controlled redirect를 더 엄격히 제한하는 편이 좋습니다.",
        checklist: [
          "Location 값이 사용자 입력에 의해 바뀌는지 확인합니다.",
          "외부 도메인으로 리다이렉트될 때 인증 정보나 코드 값이 함께 붙는지 확인합니다.",
          "302/303/307 등 상태코드별 동작 차이도 점검합니다."
        ],
        confidence: "low"
      })
    );
  }

  const acao = getHeader(responseHeaders, "access-control-allow-origin");
  const acac = getHeader(responseHeaders, "access-control-allow-credentials");
  const origin = getHeader(requestHeaders, "origin");
  if (acao === "*" && acac.toLowerCase() === "true") {
    findings.push(
      buildFinding({
        key: "cors-wildcard-with-credentials",
        title: "CORS가 와일드카드와 자격증명을 함께 허용함",
        severity: "critical",
        owasp: "A05",
        area: "Response Headers",
        evidence: "Access-Control-Allow-Origin: * 와 Access-Control-Allow-Credentials: true 조합이 확인되었습니다.",
        guide:
          "이 조합은 브라우저 보안 모델상 매우 위험합니다. 인증 쿠키나 세션이 붙는 API가 모든 Origin에서 읽힐 수 있는 구성이면 계정 탈취나 데이터 유출로 이어질 수 있습니다.",
        remediation:
          "허용 Origin을 정확한 allowlist로 제한하고, credential이 필요한 API에는 `*`를 절대 사용하지 마세요. 프록시와 앱 서버 양쪽 설정을 함께 확인하고, Origin 반사 방식이면 서버 코드에서 정적 allowlist 검증으로 바꾸세요.",
        checklist: [
          "임의 Origin 헤더로 preflight와 실제 요청을 보내 응답 헤더가 동일하게 열리는지 확인합니다.",
          "쿠키 인증 또는 Authorization이 붙은 요청이 브라우저에서 cross-origin으로 읽히는지 검증합니다.",
          "프록시, CDN, 앱 서버 각 계층 중 어디에서 CORS 헤더가 붙는지 분리 확인합니다."
        ],
        confidence: "high"
      })
    );
  } else if (origin && acao && acac.toLowerCase() === "true" && acao === origin) {
    findings.push(
      buildFinding({
        key: "cors-origin-reflection-review",
        title: "Origin 반사형 CORS 설정 검토 필요",
        severity: "medium",
        owasp: "A05",
        area: "Request/Response Headers",
        evidence: `요청 Origin(${origin})이 응답 Access-Control-Allow-Origin에 그대로 반영되었습니다.`,
        guide:
          "정상 allowlist 매칭일 수도 있지만, 서버가 들어온 Origin을 검증 없이 반사하면 임의 사이트에서 인증 응답을 읽게 될 수 있습니다. 이 교환만으로는 확정할 수 없어 추가 검증이 필요합니다.",
        remediation:
          "Origin 검증 로직을 확인해 정규식 남용이나 suffix 매칭 허점을 제거하고, 정확한 호스트/스킴/포트 기준의 allowlist 비교로 바꾸세요. 테스트 시 허용되지 않은 Origin으로 preflight와 실제 요청을 모두 재검증하는 것이 좋습니다.",
        checklist: [
          "허용되지 않아야 하는 Origin을 여러 패턴으로 바꿔 넣어도 동일하게 반사되는지 확인합니다.",
          "서브도메인 우회, 접미사 매칭, 포트 차이, 스킴 차이를 각각 테스트합니다.",
          "Credential 포함 요청에서 실제 브라우저 read 가능 여부를 확인합니다."
        ],
        confidence: "medium"
      })
    );
  }

  const setCookies = collectSetCookieHeaders(responseHeaders);
  for (const cookie of setCookies) {
    const lowered = cookie.toLowerCase();
    const isSessionCookie =
      /(session|sess|auth|token|jwt|sid)/i.test(cookie) || acac.toLowerCase() === "true";

    if (isSessionCookie && !lowered.includes("httponly")) {
      findings.push(
        buildFinding({
          key: `cookie-missing-httponly-${cookie}`,
          title: "세션 쿠키에 HttpOnly 누락",
          severity: "high",
          owasp: "A07",
          area: "Response Headers",
          evidence: `Set-Cookie: ${cookie}`,
          guide:
            "HttpOnly가 없으면 XSS 발생 시 document.cookie를 통해 세션 쿠키가 직접 탈취될 수 있습니다. 인증 쿠키에는 거의 항상 필요한 속성입니다.",
          remediation:
            "세션/인증 쿠키에는 `HttpOnly`를 기본값으로 적용하세요. 프레임워크 세션 미들웨어와 리버스 프록시가 별도로 쿠키를 재작성하는지 함께 확인해야 합니다.",
          checklist: [
            "브라우저 개발자도구에서 해당 쿠키에 HttpOnly 속성이 실제 설정되는지 확인합니다.",
            "인증 쿠키 이름 규칙이 프레임워크 기본값과 다르면 누락된 쿠키가 없는지 전수 확인합니다.",
            "XSS가 가능한 화면이 있다면 document.cookie로 접근 가능한지 테스트합니다."
          ],
          confidence: "high"
        })
      );
    }

    if (isHttps && !lowered.includes("secure")) {
      findings.push(
        buildFinding({
          key: `cookie-missing-secure-${cookie}`,
          title: "HTTPS 쿠키에 Secure 누락",
          severity: "high",
          owasp: "A02",
          area: "Response Headers",
          evidence: `Set-Cookie: ${cookie}`,
          guide:
            "Secure가 없으면 브라우저가 동일 쿠키를 HTTP 요청에도 전송할 수 있어, 다운그레이드나 중간자 구간에서 탈취 위험이 커집니다.",
          remediation:
            "운영 환경의 인증 쿠키에는 항상 `Secure`를 설정하세요. TLS 종료 지점이 프록시라면 백엔드 프레임워크가 HTTPS 요청으로 인식하도록 `X-Forwarded-Proto` 신뢰 설정도 맞춰야 합니다.",
          checklist: [
            "HTTPS와 HTTP 양쪽으로 접근했을 때 쿠키 전송 여부가 달라지는지 확인합니다.",
            "로드밸런서/프록시 뒤 환경에서 백엔드가 요청을 HTTPS로 인식하는지 검증합니다.",
            "개발/운영 설정 분기 때문에 운영에서만 빠지는 쿠키가 없는지 확인합니다."
          ],
          confidence: "high"
        })
      );
    }

    if (!lowered.includes("samesite")) {
      findings.push(
        buildFinding({
          key: `cookie-missing-samesite-${cookie}`,
          title: "쿠키에 SameSite 정책 누락",
          severity: "medium",
          owasp: "A01",
          area: "Response Headers",
          evidence: `Set-Cookie: ${cookie}`,
          guide:
            "SameSite가 없으면 브라우저 기본값에 의존하게 되고, 일부 환경에서는 교차 사이트 요청과 함께 쿠키가 전송될 수 있습니다. 특히 상태 변경 요청이 있는 서비스라면 CSRF 노출면이 넓어집니다.",
          remediation:
            "인증 쿠키에는 `SameSite=Lax` 또는 필요한 경우에만 `SameSite=None; Secure`를 명시하세요. 크로스사이트 로그인/결제 플로우가 있으면 영향 범위를 먼저 점검한 뒤 적용하는 것이 좋습니다.",
          checklist: [
            "상태 변경 요청이 cross-site 폼 또는 이미지/스크립트 요청으로 트리거될 수 있는지 확인합니다.",
            "브라우저 기본 SameSite 동작에 의존하지 않고 명시 설정되는지 검증합니다.",
            "SSO, 외부 결제, 외부 IdP 로그인 흐름에 부작용이 없는지 회귀 테스트합니다."
          ],
          confidence: "high"
        })
      );
    } else if (lowered.includes("samesite=none") && !lowered.includes("secure")) {
      findings.push(
        buildFinding({
          key: `cookie-samesite-none-without-secure-${cookie}`,
          title: "SameSite=None 쿠키에 Secure 누락",
          severity: "high",
          owasp: "A07",
          area: "Response Headers",
          evidence: `Set-Cookie: ${cookie}`,
          guide:
            "`SameSite=None`은 교차 사이트 전송을 허용하는 대신 `Secure`가 함께 있어야 합니다. 그렇지 않으면 최신 브라우저에서 거부되거나 잘못된 보안 구성이 됩니다.",
          remediation:
            "해당 쿠키가 정말 cross-site에 필요하다면 `SameSite=None; Secure`를 함께 설정하고, 필요 없다면 `Lax` 또는 `Strict`로 낮추세요.",
          checklist: [
            "브라우저가 해당 쿠키를 거부하는지 네트워크/스토리지 탭에서 확인합니다.",
            "cross-site 인증 플로우가 필요한 쿠키인지 식별하고 최소 범위만 허용합니다.",
            "테스트 환경 예외 설정이 운영으로 유입되지 않았는지 확인합니다."
          ],
          confidence: "high"
        })
      );
    }
  }

  if (isHtmlResponse && !getHeader(responseHeaders, "content-security-policy")) {
    findings.push(
      buildFinding({
        key: "missing-csp",
        title: "Content-Security-Policy 누락",
        severity: "medium",
        owasp: "A05",
        area: "Response Headers",
        evidence: "HTML 응답으로 보이지만 Content-Security-Policy 헤더가 없습니다.",
        guide:
          "CSP는 XSS가 완전히 없도록 보장하진 않지만, 인라인 스크립트 실행과 외부 스크립트 로딩을 통제하는 중요한 2차 방어선입니다. HTML 페이지에서 누락되어 있으면 브라우저 측 보호막이 약합니다.",
        remediation:
          "기본적으로 `default-src 'self'` 기반 정책을 두고, 필요한 출처만 점진적으로 허용하세요. 가능하면 nonce/hash 기반 스크립트 정책과 `frame-ancestors`, `object-src 'none'`, `base-uri 'self'`도 함께 정의하는 편이 좋습니다.",
        checklist: [
          "HTML 엔드포인트 전체에 CSP가 일관되게 적용되는지 확인합니다.",
          "report-only로 먼저 배포해 실제 차단 영향을 수집한 뒤 enforcement로 전환합니다.",
          "인라인 스크립트, 외부 위젯, 분석도구 때문에 완화된 정책이 필요한지 검토합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (isHtmlResponse && !getHeader(responseHeaders, "x-frame-options")) {
    const csp = getHeader(responseHeaders, "content-security-policy");
    if (!csp.toLowerCase().includes("frame-ancestors")) {
      findings.push(
        buildFinding({
          key: "missing-clickjacking-protection",
          title: "클릭재킹 방어 헤더 누락",
          severity: "medium",
          owasp: "A05",
          area: "Response Headers",
          evidence: "X-Frame-Options와 CSP frame-ancestors가 모두 보이지 않습니다.",
          guide:
            "페이지가 다른 사이트의 iframe 안에 삽입될 수 있으면 UI redress 공격으로 민감 동작을 유도당할 수 있습니다. 관리자 페이지, 결제, 설정 페이지에서 특히 위험합니다.",
          remediation:
            "최소한 `X-Frame-Options: DENY` 또는 `SAMEORIGIN`을 적용하고, 최신 브라우저 대응을 위해 CSP의 `frame-ancestors`도 함께 설정하세요.",
          checklist: [
            "대상 페이지를 외부 도메인 iframe에 넣었을 때 실제 로드되는지 확인합니다.",
            "관리자, 결제, 프로필 수정 등 민감 화면이 별도 예외 없이 보호되는지 점검합니다.",
            "레거시 브라우저 대응이 필요하면 X-Frame-Options와 CSP를 함께 유지합니다."
          ],
          confidence: "high"
        })
      );
    }
  }

  if (!getHeader(responseHeaders, "x-content-type-options")) {
    findings.push(
      buildFinding({
        key: "missing-nosniff",
        title: "X-Content-Type-Options 누락",
        severity: "low",
        owasp: "A05",
        area: "Response Headers",
        evidence: "X-Content-Type-Options 헤더가 없습니다.",
        guide:
          "브라우저 MIME sniffing을 막지 않으면 의도하지 않은 콘텐츠 해석으로 스크립트 실행면이 생길 수 있습니다. 업로드나 정적 파일 제공 기능이 있는 서비스에서 특히 의미가 큽니다.",
        remediation:
          "모든 동적/정적 응답에 `X-Content-Type-Options: nosniff`를 추가하세요. CDN이나 정적 파일 서버가 별도라면 그 구간 설정도 함께 맞춰야 합니다.",
        checklist: [
          "정적 파일 서버와 앱 서버 양쪽 응답 헤더를 각각 확인합니다.",
          "사용자 업로드 파일 다운로드 경로에 동일 정책이 적용되는지 확인합니다.",
          "MIME 타입이 잘못된 파일이 브라우저에서 실행 컨텍스트로 해석되는지 테스트합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (isHttps && !getHeader(responseHeaders, "strict-transport-security")) {
    findings.push(
      buildFinding({
        key: "missing-hsts",
        title: "HSTS 누락",
        severity: "medium",
        owasp: "A05",
        area: "Response Headers",
        evidence: "HTTPS 응답으로 보이지만 Strict-Transport-Security 헤더가 없습니다.",
        guide:
          "HSTS가 없으면 최초 접속이나 링크 클릭 시 HTTP로 다운그레이드될 여지가 남습니다. 네트워크 공격자가 평문 접속을 가로채 HTTPS 전환을 방해할 수 있습니다.",
        remediation:
          "`Strict-Transport-Security: max-age=31536000; includeSubDomains` 수준으로 설정하고, 서브도메인 영향도를 점검한 뒤 preload 등록 여부를 결정하세요.",
        checklist: [
          "최상위 도메인과 주요 서브도메인 모두에서 HSTS가 응답되는지 확인합니다.",
          "HTTP 접속이 HTTPS로 강제되는지, preload 후보인지 점검합니다.",
          "서브도메인 중 HTTPS 미지원 자산이 남아 있지 않은지 확인합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (SERVER_DISCLOSURE_REGEX.test(getHeader(responseHeaders, "server")) || SERVER_DISCLOSURE_REGEX.test(getHeader(responseHeaders, "x-powered-by"))) {
    findings.push(
      buildFinding({
        key: "server-banner-disclosure",
        title: "서버/프레임워크 버전 노출",
        severity: "low",
        owasp: "A06",
        area: "Response Headers",
        evidence: `Server: ${getHeader(responseHeaders, "server") || "-"}, X-Powered-By: ${
          getHeader(responseHeaders, "x-powered-by") || "-"
        }`,
        guide:
          "배너 정보만으로 취약점이 성립하진 않지만, 공격자는 여기서 프레임워크와 버전을 파악해 알려진 CVE를 우선 시도합니다. 불필요한 식별자는 줄이는 편이 좋습니다.",
        remediation:
          "웹서버와 애플리케이션 프레임워크의 배너 헤더를 제거하거나 일반화하세요. 동시에 실제 패치 상태가 최신인지 별도로 확인해야 하며, 배너 숨김만으로 보안이 해결되지는 않습니다.",
        checklist: [
          "노출된 버전이 실제 배포 버전과 일치하는지 확인합니다.",
          "해당 버전에 알려진 CVE가 있는지 별도 점검합니다.",
          "배너 제거 후에도 업그레이드/패치 프로세스가 유지되는지 확인합니다."
        ],
        confidence: "medium"
      })
    );
  }

  if (STACK_TRACE_REGEX.test(responseBody)) {
    findings.push(
      buildFinding({
        key: "verbose-error-disclosure",
        title: "상세 에러/스택트레이스 노출 가능성",
        severity: "high",
        owasp: "A05",
        area: "Response Body",
        evidence: `응답 본문에서 예외/스택트레이스 패턴이 보입니다. Snippet: ${findSnippet(
          responseBody,
          STACK_TRACE_REGEX
        )}`,
        guide:
          "스택트레이스, SQL 오류, 프레임워크 예외 메시지는 내부 경로, 라이브러리, 쿼리 구조, 클래스명 같은 민감한 구현 정보를 드러냅니다. 공격자가 다음 공격 단계를 정교화하는 데 매우 유용합니다.",
        remediation:
          "운영 환경에서는 공통 오류 응답 포맷만 반환하고 상세 예외는 서버 내부 로그로 제한하세요. Express/Node라면 전역 에러 핸들러에서 메시지를 정규화하고, 디버그 모드가 운영에 켜져 있지 않은지도 확인해야 합니다.",
        checklist: [
          "같은 오류 조건에서 운영/스테이징/개발 응답이 어떻게 다른지 확인합니다.",
          "에러 페이지에 파일 경로, SQL 문장, 클래스명, 환경변수명이 포함되는지 점검합니다.",
          "중앙 에러 핸들러와 프록시 에러 페이지가 서로 다른 상세 정보를 노출하지 않는지 검토합니다."
        ],
        confidence: "high"
      })
    );
  } else if (responseStatus >= 500) {
    findings.push(
      buildFinding({
        key: "server-error-observed",
        title: "5xx 서버 오류 관찰됨",
        severity: "low",
        owasp: "A09",
        area: "Response Status",
        evidence: `HTTP ${responseStatus} 서버 오류가 관찰되었습니다.`,
        guide:
          "5xx 자체는 취약점이 아니지만, 특정 페이로드나 특정 파라미터 조합에서 반복된다면 취약점 탐사 단서가 될 수 있습니다. 상세 오류가 숨겨져 있어도 입력 처리 경계가 흔들리는 신호로 볼 수 있습니다.",
        remediation:
          "실패한 요청 조건을 재현하고, 서버 로그에서 예외 원인과 입력 검증 누락 여부를 확인하세요. 동일 요청이 특정 비정상 입력에서만 5xx를 일으키면 해당 코드 경로를 우선 점검하는 편이 좋습니다.",
        checklist: [
          "동일 요청을 정상 입력과 비교해 어떤 파라미터가 5xx를 유발하는지 확인합니다.",
          "서버 로그, APM trace, 에러 모니터링에서 스택과 근본 원인을 추적합니다.",
          "예외가 사용자 입력 검증 실패인지, 외부 의존성 오류인지 구분합니다."
        ],
        confidence: "low"
      })
    );
  }

  if (DIRECTORY_LISTING_REGEX.test(responseBody)) {
    findings.push(
      buildFinding({
        key: "directory-listing",
        title: "디렉터리 인덱싱 노출",
        severity: "medium",
        owasp: "A05",
        area: "Response Body",
        evidence: "응답 본문에서 `Index of /` 형태의 디렉터리 목록 패턴이 감지되었습니다.",
        guide:
          "디렉터리 목록이 열려 있으면 백업 파일, 소스맵, 업로드 파일, 관리용 스크립트 등 의도치 않은 자산이 그대로 노출될 수 있습니다.",
        remediation:
          "웹서버의 autoindex/directory listing 기능을 끄고, 정적 파일 경로는 명시적으로 노출할 디렉터리만 allowlist로 지정하세요. `.env`, 백업 zip, 소스맵 같은 민감 파일은 별도 접근 차단도 필요합니다.",
        checklist: [
          "상위 경로와 하위 경로에서 자동 인덱싱이 반복되는지 확인합니다.",
          "목록에 소스맵, 백업 파일, 업로드 파일, 관리자 스크립트가 포함되는지 확인합니다.",
          "웹서버 autoindex 설정과 앱 라우팅 fallback 설정을 같이 점검합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (isHtmlResponse && !getHeader(responseHeaders, "referrer-policy")) {
    findings.push(
      buildFinding({
        key: "missing-referrer-policy",
        title: "Referrer-Policy 누락",
        severity: "low",
        owasp: "A05",
        area: "Response Headers",
        evidence: "HTML 응답에 Referrer-Policy가 없습니다.",
        guide:
          "민감 파라미터가 URL에 있을 경우 다른 사이트로 이동하면서 Referer에 전송될 수 있습니다. 앞선 URL 민감정보 문제와 같이 나타나면 위험도가 커집니다.",
        remediation:
          "`Referrer-Policy: strict-origin-when-cross-origin` 이상을 기본값으로 적용하고, 더 엄격해야 하면 `no-referrer`도 검토하세요.",
        checklist: [
          "민감 파라미터가 있는 페이지에서 외부 링크/리소스 호출 시 Referer를 캡처해 확인합니다.",
          "앱 전역과 특정 민감 페이지의 정책이 다르게 적용되는지 점검합니다.",
          "URL 민감정보 문제와 결합될 때 위험도가 커지는지 함께 평가합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (
    (responseSetCookie || hasSensitiveResponseBody) &&
    !/(no-store|private)/i.test(getHeader(responseHeaders, "cache-control"))
  ) {
    findings.push(
      buildFinding({
        key: "sensitive-response-cache-control",
        title: "민감 응답에 캐시 제한 부족",
        severity: "medium",
        owasp: "A02",
        area: "Response Headers",
        evidence: "민감 응답처럼 보이지만 Cache-Control에 `no-store` 또는 `private`가 확인되지 않습니다.",
        guide:
          "인증 결과나 개인정보가 포함된 응답이 공유 캐시나 브라우저 히스토리에 남으면, 다른 사용자 또는 후속 세션에서 재노출될 수 있습니다.",
        remediation:
          "인증/개인정보 응답에는 `Cache-Control: no-store, private`를 기본으로 검토하세요. CDN, 프록시, 브라우저 캐시 지시자가 일관되게 적용되는지도 확인해야 합니다.",
        checklist: [
          "브라우저 뒤로가기/새로고침에서 민감 페이지가 캐시로 재표시되는지 확인합니다.",
          "CDN, 프록시, 브라우저 각 계층의 캐시 동작을 개별적으로 검증합니다.",
          "로그아웃 후 이전 민감 응답이 브라우저에 남는지 확인합니다."
        ],
        confidence: "medium"
      })
    );
  }

  if (requestContainsSqli) {
    findings.push(
      buildFinding({
        key: "sqli-pattern",
        title: "SQL Injection 공격 패턴 흔적",
        severity: "high",
        owasp: "A03",
        area: "Request URL/Body",
        evidence: `요청에 SQLi 유사 페이로드가 있습니다. Snippet: ${findSnippet(requestText, SQLI_REGEX)}`,
        guide:
          "이것만으로 취약점 확정은 아니지만, 실제 서비스가 이런 입력을 에러 없이 처리하거나 응답 차이를 보인다면 SQL Injection 가능성을 집중 점검해야 합니다.",
        remediation:
          "모든 DB 쿼리를 prepared statement/parameter binding으로 바꾸고, 동적 쿼리 조합 구간을 제거하세요. 에러 응답과 응답 시간 차이를 함께 확인해 블라인드 SQLi 가능성도 검증하는 것이 좋습니다.",
        checklist: [
          "정상 입력 대비 응답 코드, 본문, 응답 시간 차이가 나는지 비교합니다.",
          "인코딩된 페이로드와 숫자형/문자형 파라미터 모두에서 재현해 봅니다.",
          "DB 에러 로그와 ORM/raw query 구간을 함께 확인합니다."
        ],
        confidence: responseStatus >= 500 || STACK_TRACE_REGEX.test(responseBody) ? "medium" : "low"
      })
    );
  }

  if (requestContainsXss || reflectedXss || (isHtmlResponse && XSS_REGEX.test(responseBody))) {
    findings.push(
      buildFinding({
        key: "xss-pattern",
        title: "XSS 관련 페이로드 또는 반사 흔적",
        severity: "high",
        owasp: "A03",
        area: "Request/Response Body",
        evidence: reflectedXss
          ? `요청 페이로드가 응답에 반사되는 정황이 있습니다. Request snippet: ${findSnippet(requestText, XSS_REGEX)}`
          : `XSS 유사 패턴이 감지되었습니다. Snippet: ${findSnippet(
              requestContainsXss ? requestText : responseBody,
              XSS_REGEX
            )}`,
        guide:
          "요청에 삽입된 스크립트 조각이 응답에 그대로 반사되거나 HTML 컨텍스트에서 보이면 반사형/저장형 XSS를 의심할 수 있습니다. CSP가 함께 없으면 악용 난도가 더 낮아집니다.",
        remediation:
          "출력 시점 컨텍스트에 맞는 escaping을 적용하고, HTML sanitization이 필요한 필드는 allowlist 기반 sanitizer를 사용하세요. 템플릿 엔진의 raw HTML 렌더링 지점을 우선 점검하고 CSP도 함께 강화해야 합니다.",
        checklist: [
          "요청에 넣은 payload가 응답 HTML, DOM, JS 문자열 중 어디에 반영되는지 확인합니다.",
          "브라우저에서 실제 스크립트 실행 여부를 안전한 테스트 payload로 검증합니다.",
          "출력 인코딩, 템플릿 raw HTML, markdown/html sanitizer 우회 가능성을 점검합니다."
        ],
        confidence: reflectedXss ? "medium" : "low"
      })
    );
  }

  if (requestContainsTraversal) {
    findings.push(
      buildFinding({
        key: "path-traversal-pattern",
        title: "경로 조작(Path Traversal) 시도 흔적",
        severity: "medium",
        owasp: "A01",
        area: "Request URL/Body",
        evidence: `경로 이탈 패턴이 보입니다. Snippet: ${findSnippet(requestText, PATH_TRAVERSAL_REGEX)}`,
        guide:
          "파일 다운로드, 이미지 조회, 템플릿 로딩 API에서 이런 패턴이 정상적으로 처리되면 상위 디렉터리 파일 노출로 이어질 수 있습니다.",
        remediation:
          "사용자 입력으로 경로를 직접 결합하지 말고, 허용된 파일 식별자만 받아 서버 측 매핑으로 변환하세요. `path.normalize` 후에도 루트 이탈 여부를 검증해야 하며, 심볼릭 링크 우회도 고려해야 합니다.",
        checklist: [
          "정상 파일 경로와 traversal payload에서 응답 차이가 있는지 비교합니다.",
          "인코딩 우회(`%2e%2e%2f`, 이중 인코딩, 백슬래시)도 함께 테스트합니다.",
          "실제 파일 시스템 접근 코드가 루트 디렉터리 탈출을 차단하는지 확인합니다."
        ],
        confidence: "low"
      })
    );
  }

  if (requestContainsCommand) {
    findings.push(
      buildFinding({
        key: "command-injection-pattern",
        title: "명령어 주입(Command Injection) 시도 흔적",
        severity: "high",
        owasp: "A03",
        area: "Request URL/Body",
        evidence: `명령어 체이닝 패턴이 보입니다. Snippet: ${findSnippet(requestText, COMMAND_INJECTION_REGEX)}`,
        guide:
          "백엔드가 이 입력을 셸 명령 구성에 사용한다면 원격 명령 실행으로 이어질 수 있습니다. 특히 ping, convert, ffmpeg, backup 스크립트 호출 기능에서 자주 문제됩니다.",
        remediation:
          "셸을 거치지 않는 안전한 라이브러리 호출로 바꾸고, 부득이하게 프로세스를 띄워야 하면 인자 배열 기반 실행과 엄격한 allowlist 검증을 적용하세요.",
        checklist: [
          "해당 입력을 사용하는 백엔드 기능이 실제로 외부 프로세스를 호출하는지 확인합니다.",
          "구분자(`;`, `&&`, `|`)와 백틱, `$()` 같은 우회 패턴도 함께 테스트합니다.",
          "응답 시간 증가, 출력 반영, 에러 메시지 변화가 있는지 비교합니다."
        ],
        confidence: "low"
      })
    );
  }

  if (requestContainsOpenRedirect) {
    findings.push(
      buildFinding({
        key: "open-redirect-pattern",
        title: "Open Redirect 파라미터 검토 필요",
        severity: "medium",
        owasp: "A01",
        area: "Request URL/Body",
        evidence: `외부 URL redirect 파라미터가 보입니다. Snippet: ${findSnippet(
          requestText,
          OPEN_REDIRECT_REGEX
        )}`,
        guide:
          "로그인 후 이동, 결제 완료 이동 로직에서 이 값이 검증 없이 사용되면 피싱과 토큰 탈취 체인으로 이어질 수 있습니다.",
        remediation:
          "리다이렉트 대상은 내부 경로 allowlist 또는 서버 측 매핑 키만 허용하세요. 외부 URL이 꼭 필요하면 스킴, 호스트, 포트를 화이트리스트로 강제하고 서명값 검증도 고려해야 합니다.",
        checklist: [
          "절대 URL, 스킴 상대 URL, 이중 인코딩 URL 등으로 리다이렉트가 가능한지 확인합니다.",
          "로그인/로그아웃/결제 완료 플로우에서 외부 도메인 이동이 허용되는지 검증합니다.",
          "허용된 내부 경로만 통과하도록 서버 측 검증이 있는지 확인합니다."
        ],
        confidence: "low"
      })
    );
  }

  if (requestContainsSsrf) {
    findings.push(
      buildFinding({
        key: "ssrf-pattern",
        title: "SSRF 대상 지정 패턴",
        severity: "high",
        owasp: "A10",
        area: "Request URL/Body",
        evidence: `내부망 또는 메타데이터 대상 URL 패턴이 있습니다. Snippet: ${findSnippet(
          requestText,
          SSRF_REGEX
        )}`,
        guide:
          "이 입력이 서버 측에서 실제로 fetch된다면 내부망 스캔, 클라우드 메타데이터 탈취, 내부 관리자 API 접근으로 이어질 수 있습니다. 이 교환은 SSRF 시도나 취약 파라미터를 강하게 시사합니다.",
        remediation:
          "서버가 호출할 수 있는 목적지 호스트를 allowlist로 제한하고, DNS 재바인딩과 사설 IP 우회를 함께 차단하세요. URL 스킴, 포트, 리다이렉트 추적 여부까지 서버 측에서 엄격히 검증해야 합니다.",
        checklist: [
          "서버가 해당 URL을 실제로 요청하는지 outbound 로그/프록시 로그로 확인합니다.",
          "localhost, 사설망 IP, 메타데이터 IP, DNS rebinding 대상 호스트로 각각 테스트합니다.",
          "리다이렉트를 따라가면서 내부망으로 우회 가능한지 검증합니다."
        ],
        confidence: "low"
      })
    );
  }

  return findings;
}

function classifyToken(token) {
  if (!token) return "plain";
  if (token.startsWith("<!--")) return "comment";
  if (token.startsWith("<")) return "tag";
  if (token.startsWith('"') && token.endsWith('":')) return "key";
  if (
    (token.startsWith('"') && token.endsWith('"')) ||
    (token.startsWith("'") && token.endsWith("'"))
  ) {
    return "string";
  }
  if (/^(true|false|null)$/.test(token)) return "keyword";
  if (/^\d+(\.\d+)?$/.test(token)) return "number";
  return "punctuation";
}

function renderHighlightedLine(line, lineIndex) {
  const nodes = [];
  let lastIndex = 0;
  let match;

  TOKEN_REGEX.lastIndex = 0;

  while ((match = TOKEN_REGEX.exec(line)) !== null) {
    const token = match[0];
    const start = match.index;

    if (start > lastIndex) {
      nodes.push(
        <span key={`text-${lineIndex}-${lastIndex}`} className="token plain">
          {line.slice(lastIndex, start)}
        </span>
      );
    }

    nodes.push(
      <span key={`token-${lineIndex}-${start}`} className={`token ${classifyToken(token)}`}>
        {token}
      </span>
    );

    lastIndex = start + token.length;
  }

  if (lastIndex < line.length) {
    nodes.push(
      <span key={`tail-${lineIndex}-${lastIndex}`} className="token plain">
        {line.slice(lastIndex)}
      </span>
    );
  }

  if (nodes.length === 0) {
    nodes.push(
      <span key={`empty-${lineIndex}`} className="token plain">
        {" "}
      </span>
    );
  }

  return nodes;
}

function CodeBlock({ sections, maskSensitive = true }) {
  const lines = sections.flatMap((section) => {
    const contentLines = maybeMask(section.content || "(empty)", maskSensitive).split("\n");
    return [section.label, ...contentLines];
  });

  return (
    <div className="code-block">
      {lines.map((line, index) => (
        <div key={`${index}-${line}`} className="code-line">
          <span className="line-number">{index + 1}</span>
          <span
            className={`line-content ${
              line &&
              !line.includes(" ") &&
              !line.includes("{") &&
              !line.includes("<") &&
              !line.includes(":")
                ? "section-line"
                : ""
            } ${SECURITY_REGEX.test(line) ? "security-line" : ""}`}
          >
            {renderHighlightedLine(line, index)}
          </span>
        </div>
      ))}
    </div>
  );
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDateTime(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("ko-KR");
}

function decodeJwtPayload(token) {
  if (!token || typeof window === "undefined") {
    return null;
  }

  try {
    const [, payload] = token.split(".");
    if (!payload) {
      return null;
    }

    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const binary = window.atob(padded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    const decoded = new TextDecoder("utf-8").decode(bytes);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

function getStoredAuthUser() {
  const user = getStoredJson(AUTH_STORAGE_KEY);
  if (!user || typeof user !== "object") {
    return null;
  }

  return user.email ? user : null;
}

function getStoredHarHistory() {
  const items = getStoredJson(LOCAL_HAR_HISTORY_KEY, []);
  return Array.isArray(items) ? items : [];
}

function getStoredInspectionRuns() {
  const items = getStoredJson(LOCAL_INSPECTION_RUNS_KEY, []);
  return Array.isArray(items) ? items : [];
}

function getStoredCaptureEvents() {
  const items = getStoredJson(LOCAL_CAPTURE_EVENTS_KEY, []);
  return Array.isArray(items) ? items : [];
}

function buildHarHistoryFingerprint({ fileName, fileSize, summary }) {
  return [
    fileName || "",
    String(fileSize || ""),
    String(summary?.totalEntries || 0),
    String(summary?.averageWaitMs || 0),
    summary?.slowestEntry?.url || ""
  ].join("::");
}

async function readJsonSafely(response) {
  const rawText = await response.text();

  try {
    return {
      data: rawText ? JSON.parse(rawText) : {},
      rawText
    };
  } catch {
    return {
      data: null,
      rawText
    };
  }
}

function LoginScreen({ onLogin }) {
  const [loginError, setLoginError] = useState("");
  const loginShellRef = useRef(null);
  const showLocalDevLogin = isLocalRuntime();

  useEffect(() => {
    let cancelled = false;

    function renderGoogleButton() {
      if (cancelled || typeof window === "undefined" || !window.google?.accounts?.id) {
        return;
      }

      const buttonRoot = document.getElementById("google-login-button");
      if (!buttonRoot) {
        return;
      }

      buttonRoot.innerHTML = "";
      window.google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: (response) => {
          const payload = decodeJwtPayload(response?.credential);
          if (!payload?.email) {
            setLoginError("구글 로그인 응답을 해석하지 못했습니다.");
            return;
          }

          if (String(payload.email).toLowerCase() !== ALLOWED_GOOGLE_EMAIL) {
            setLoginError(`허용된 계정만 접속할 수 있습니다: ${ALLOWED_GOOGLE_EMAIL}`);
            return;
          }

          setLoginError("");
          onLogin({
            id: payload.sub,
            email: payload.email,
            name: payload.name || payload.email,
            picture: payload.picture || "",
            credential: response.credential
          });
        }
      });
      window.google.accounts.id.renderButton(buttonRoot, {
        theme: "outline",
        size: "large",
        shape: "pill",
        text: "signin_with",
        width: 320
      });
    }

    if (window.google?.accounts?.id) {
      renderGoogleButton();
      return () => {
        cancelled = true;
      };
    }

    const existingScript = document.querySelector('script[src="https://accounts.google.com/gsi/client"]');
    if (existingScript) {
      existingScript.addEventListener("load", renderGoogleButton);
      existingScript.addEventListener("error", () =>
        setLoginError("구글 로그인 스크립트를 불러오지 못했습니다.")
      );

      return () => {
        cancelled = true;
        existingScript.removeEventListener("load", renderGoogleButton);
      };
    }

    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = renderGoogleButton;
    script.onerror = () => setLoginError("구글 로그인 스크립트를 불러오지 못했습니다.");
    document.head.appendChild(script);

    return () => {
      cancelled = true;
      script.onload = null;
      script.onerror = null;
    };
  }, [onLogin]);

  function handleLocalDevLogin() {
    onLogin({
      id: "local-dev",
      email: ALLOWED_GOOGLE_EMAIL,
      name: "Local Developer",
      picture: "",
      credential: "local-dev"
    });
  }

  return (
    <main ref={loginShellRef} className="login-shell">
      <section className="login-card">
        <p className="login-eyebrow">Google Sign-In</p>
        <h1 className="page-title">HTTP Analyzer Login</h1>
        <p className="login-copy">
          캡처와 HAR 분석 화면에 들어가기 전에 구글 계정으로 로그인하세요. 로그인 정보는
          이 브라우저에만 저장됩니다.
        </p>
        <p className="login-copy">
          허용된 계정: <strong>{ALLOWED_GOOGLE_EMAIL}</strong>
        </p>
        <div className="login-actions">
          <div id="google-login-button" className="google-login-button" />
          {showLocalDevLogin ? (
            <button type="button" className="local-dev-login-button" onClick={handleLocalDevLogin}>
              로컬 개발 로그인
            </button>
          ) : null}
          {loginError ? <div className="error-strip">{loginError}</div> : null}
        </div>
      </section>
    </main>
  );
}

function ReplayModal({
  modalState,
  setModalState,
  replayResponse,
  replayLoading,
  replayError,
  onReplay,
  maskSensitive
}) {
  if (!modalState) return null;

  return (
    <div className="modal-backdrop" onClick={() => setModalState(null)}>
      <div className="modal-shell" onClick={(event) => event.stopPropagation()}>
        <div className="modal-grid">
          <section className="modal-panel">
            <div className="modal-fields">
              <input
                value={modalState.method}
                onChange={(event) =>
                  setModalState((current) => ({ ...current, method: event.target.value }))
                }
              />
              <input
                value={modalState.url}
                onChange={(event) =>
                  setModalState((current) => ({ ...current, url: event.target.value }))
                }
              />
              <textarea
                rows={10}
                value={modalState.headers}
                onChange={(event) =>
                  setModalState((current) => ({ ...current, headers: event.target.value }))
                }
              />
              <textarea
                rows={12}
                value={modalState.body}
                onChange={(event) =>
                  setModalState((current) => ({ ...current, body: event.target.value }))
                }
              />
              <div className="action-row">
                <button type="button" onClick={onReplay} disabled={replayLoading}>
                  {replayLoading ? "요청 중..." : "요청"}
                </button>
                <button type="button" onClick={() => setModalState(null)}>
                  닫기
                </button>
              </div>
              {replayError ? <div className="error-strip">{replayError}</div> : null}
            </div>
          </section>

          <section className="modal-panel">
            <CodeBlock
              sections={[
                { label: "Status", content: replayResponse ? `${replayResponse.status} ${replayResponse.statusText}` : "(empty)" },
                { label: "Headers", content: prettyJson(replayResponse?.headers) },
                { label: "Body", content: replayResponse?.body || "(empty)" }
              ]}
              maskSensitive={maskSensitive}
            />
          </section>
        </div>
      </div>
    </div>
  );
}

function InspectionRunModal({ run, onClose, onDownloadHtml, onDownloadPdf }) {
  if (!run) {
    return null;
  }

  const snapshot = run.report_snapshot || {};
  const summary = snapshot.summary || {};
  const conclusion = snapshot.conclusion || buildInspectionConclusion({
    totalFindings: run.total_findings,
    criticalFindings: run.critical_findings,
    highFindings: run.high_findings,
    totalErrors: run.total_errors
  });

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-shell inspection-modal-shell" onClick={(event) => event.stopPropagation()}>
        <div className="inspection-modal-header">
          <div>
            <h2 className="section-title">점검 이력 상세</h2>
            <p className="section-copy">{run.target_url || "-"}</p>
          </div>
          <div className="action-row">
            <button type="button" onClick={() => onDownloadHtml(run)}>
              HTML 재다운로드
            </button>
            <button type="button" onClick={() => onDownloadPdf(run)}>
              PDF 재다운로드
            </button>
            <button type="button" onClick={onClose}>
              닫기
            </button>
          </div>
        </div>
        <div className="inspection-modal-grid">
          <div className="recent-card">
            <strong>표지 정보</strong>
            <span>점검자: {snapshot.inspector || "-"}</span>
            <span>점검 일시: {formatDateTime(run.started_at)} ~ {formatDateTime(run.ended_at)}</span>
            <span>세션: {run.capture_session_id || "-"}</span>
          </div>
          <div className="recent-card">
            <strong>결론</strong>
            <span>{conclusion}</span>
          </div>
          <div className="recent-card">
            <strong>요약 지표</strong>
            <span>요청 {run.total_exchanges}건 / 에러 {run.total_errors}건</span>
            <span>Finding {run.total_findings}건 / Critical {run.critical_findings} / High {run.high_findings}</span>
            <span>Security Only: {run.security_only ? "ON" : "OFF"} / Mask: {run.mask_sensitive ? "ON" : "OFF"}</span>
          </div>
          <div className="recent-card">
            <strong>제외 패턴</strong>
            <span>{Array.isArray(run.excluded_patterns) && run.excluded_patterns.length > 0 ? run.excluded_patterns.join(", ") : "-"}</span>
          </div>
          <div className="recent-card inspection-modal-wide">
            <strong>OWASP Summary</strong>
            <div className="owasp-overview-chips">
              {(run.owasp_summary || []).map((item) => (
                <span key={`${run.id}-${item.key}`} className="owasp-chip">
                  {item.label} ({item.count})
                </span>
              ))}
            </div>
          </div>
          <div className="recent-card inspection-modal-wide">
            <strong>Endpoint Priority Snapshot</strong>
            <div className="endpoint-overview-list">
              {(run.endpoint_summary || []).map((item) => (
                <div key={`${run.id}-${item.endpoint}`} className="endpoint-card">
                  <span className="endpoint-title">{item.endpoint}</span>
                  <span>Score: {item.score}</span>
                  <span>Findings: {item.findings}</span>
                  <span>Highest: {item.highestSeverityLabel || item.highestSeverity}</span>
                </div>
              ))}
            </div>
          </div>
          {summary && Object.keys(summary).length > 0 ? (
            <div className="recent-card inspection-modal-wide">
              <strong>저장된 리포트 메타</strong>
              <span>Visible Pairs: {summary.visiblePairs ?? "-"}</span>
              <span>총 Findings: {summary.totalFindings ?? "-"}</span>
              <span>생성 시각: {formatDateTime(snapshot.exportedAt)}</span>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function MermaidModal({ code, onClose, onCopy }) {
  if (!code) {
    return null;
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-shell mermaid-modal-shell" onClick={(event) => event.stopPropagation()}>
        <div className="mermaid-modal-header">
          <div />
          <button type="button" onClick={onCopy}>
            복사
          </button>
        </div>
        <pre className="mermaid-modal-code">{code}</pre>
      </div>
    </div>
  );
}

export default function App() {
  const appShellRef = useRef(null);
  const activeRef = useRef(false);
  const autoStoppedSessionRef = useRef("");
  const readOnlyDeployment = false;
  const [authUser, setAuthUser] = useState(() => getStoredAuthUser());
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => getStoredValue("http-analyzer-sidebar-collapsed") === "true"
  );
  const [activeSection, setActiveSection] = useState(() =>
    getStoredValue("http-analyzer-active-section", "overview")
  );
  const [domain, setDomain] = useState(() => getStoredValue("http-analyzer-domain"));
  const [excludeInput, setExcludeInput] = useState(() =>
    getStoredValue("http-analyzer-exclude-patterns")
  );
  const [loginId, setLoginId] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [sessionValue, setSessionValue] = useState("");
  const [securityOnly, setSecurityOnly] = useState(
    () => getStoredValue("http-analyzer-security-only") === "true"
  );
  const [maskSensitive, setMaskSensitive] = useState(
    () => getStoredValue("http-analyzer-mask-sensitive", "true") !== "false"
  );
  const [suppressedFindings, setSuppressedFindings] = useState(() => {
    const raw = getStoredValue("http-analyzer-suppressed-findings", "[]");
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((item) => item && typeof item === "object") : [];
    } catch {
      return [];
    }
  });
  const [sessionSuppressedFindings, setSessionSuppressedFindings] = useState(() => {
    if (typeof window === "undefined") {
      return [];
    }

    try {
      const raw = window.sessionStorage.getItem("http-analyzer-session-suppressed-findings") || "[]";
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((item) => item && typeof item === "object") : [];
    } catch {
      return [];
    }
  });
  const [statusMessage, setStatusMessage] = useState("");
  const [active, setActive] = useState(false);
  const [captureSessionId, setCaptureSessionId] = useState("");
  const [captureStartedAt, setCaptureStartedAt] = useState("");
  const [captureMeta, setCaptureMeta] = useState({
    stopReason: "",
    crawlActive: false,
    crawlCompleted: false,
    crawlVisited: [],
    crawlQueueLength: 0,
    crawlMaxPages: 0,
    loginAttempted: false,
    loginStatus: "skipped",
    loginError: "",
    sessionApplied: false,
    sessionStatus: "skipped",
    sessionError: ""
  });
  const [exchanges, setExchanges] = useState([]);
  const [errors, setErrors] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [modalState, setModalState] = useState(null);
  const [replayResponse, setReplayResponse] = useState(null);
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayError, setReplayError] = useState("");
  const [inspectionModalRun, setInspectionModalRun] = useState(null);
  const [harFile, setHarFile] = useState(null);
  const [harUploading, setHarUploading] = useState(false);
  const [harUploadResult, setHarUploadResult] = useState(null);
  const [harUploadError, setHarUploadError] = useState("");
  const [localHarHistory, setLocalHarHistory] = useState(() => getStoredHarHistory());
  const [localInspectionRuns, setLocalInspectionRuns] = useState(() => getStoredInspectionRuns());
  const [localCaptureEvents, setLocalCaptureEvents] = useState(() => getStoredCaptureEvents());
  const [selectedHarHistoryKey, setSelectedHarHistoryKey] = useState("");
  const [recentHarAnalyses, setRecentHarAnalyses] = useState([]);
  const [recentCaptureEvents, setRecentCaptureEvents] = useState([]);
  const [recentInspectionRuns, setRecentInspectionRuns] = useState([]);
  const [recentLoading, setRecentLoading] = useState(false);
  const [backendHealth, setBackendHealth] = useState({
    checkedAt: "",
    checking: true,
    ok: false,
    error: "",
    service: "",
    supabaseConfigured: false,
    captureDisabled: null
  });
  const [captureMermaidModal, setCaptureMermaidModal] = useState("");
  const [focusedFindingExchangeId, setFocusedFindingExchangeId] = useState("");
  const mergedHarHistory = [
    ...localHarHistory.map((item) => ({ ...item, historySource: "local" })),
    ...recentHarAnalyses
      .map((item) => ({
        ...item,
        historySource: "db",
        fingerprint:
          item.fingerprint ||
          buildHarHistoryFingerprint({
            fileName: item.file_name,
            fileSize: item.file_size,
            summary: {
              totalEntries: item.total_entries,
              averageWaitMs: item.average_wait_ms,
              slowestEntry: { url: item.slowest_url }
            }
          })
      }))
      .filter(
        (item) => !localHarHistory.some((localItem) => localItem.fingerprint === item.fingerprint)
      )
  ];
  const mergedInspectionRuns = [
    ...localInspectionRuns.map((item) => ({ ...item, historySource: "local" })),
    ...recentInspectionRuns
      .map((item) => ({ ...item, historySource: "db" }))
      .filter(
        (item) =>
          !localInspectionRuns.some(
            (localItem) =>
              (localItem.capture_session_id || "") === (item.capture_session_id || "") &&
              (localItem.target_url || "") === (item.target_url || "") &&
              (localItem.ended_at || "") === (item.ended_at || "")
          )
      )
  ];
  const mergedCaptureEvents = [
    ...localCaptureEvents.map((item) => ({ ...item, historySource: "local" })),
    ...recentCaptureEvents
      .map((item) => ({ ...item, historySource: "db" }))
      .filter(
        (item) =>
          !localCaptureEvents.some(
            (localItem) =>
              (localItem.capture_session_id || "") === (item.capture_session_id || "") &&
              (localItem.request_url || "") === (item.request_url || "") &&
              (localItem.created_at || "") === (item.created_at || "")
          )
      )
  ].filter((item) => !isAbortedErrorText(item.error_text));
  const normalizedHarHistory = mergedHarHistory.map((item) => ({
    ...item,
    historyKey: `${item.historySource}:${item.id || item.fingerprint || item.created_at || item.file_name}`,
    displayFileName: item.file_name || item.fileName || "-",
    displayCreatedAt: item.created_at || item.createdAt || "",
    summary:
      item.summary || {
        totalEntries: item.total_entries ?? 0,
        averageWaitMs: item.average_wait_ms ?? 0,
        slowestEntry: { url: item.slowest_url || "-" }
      }
  }));
  const selectedHarHistory =
    normalizedHarHistory.find((item) => item.historyKey === selectedHarHistoryKey) || null;

  const liveExcludePatterns = getCombinedExcludePatterns(excludeInput);

  const analyzedExchanges = exchanges.map((exchange) => ({
    ...exchange,
    endpointKey: normalizeEndpoint(exchange.request?.url || exchange.response?.url),
    securityFindings: analyzeSecurityFindings(exchange).filter(
      (finding) =>
        ![...suppressedFindings, ...sessionSuppressedFindings].some((rule) =>
          matchesSuppressionRule(rule, finding, exchange)
        )
    )
  }));
  const allSecurityFindings = analyzedExchanges.flatMap((exchange) => exchange.securityFindings);
  const owaspSummary = summarizeFindingsByOwasp(allSecurityFindings);
  const endpointSummary = summarizeEndpoints(analyzedExchanges);
  const criticalAlerts = allSecurityFindings.filter((finding) => finding.severity === "critical");
  const highAlerts = allSecurityFindings.filter((finding) => finding.severity === "high");
  const periodStats = buildPeriodStats(mergedInspectionRuns);

  const exchangesWithDiffs = analyzedExchanges.map((exchange, index) => {
    const previous = analyzedExchanges
      .slice(0, index)
      .reverse()
      .find((candidate) => candidate.endpointKey === exchange.endpointKey);

    return {
      ...exchange,
      diffSummary: buildDiffSummary(exchange, previous)
    };
  });

  const visibleExchanges = exchangesWithDiffs.filter((exchange) => {
    if (securityOnly && exchange.securityFindings.length === 0) {
      return false;
    }

    if (isImageLikeExchange(exchange)) {
      return false;
    }

    if (liveExcludePatterns.length === 0) return true;
    const requestUrl = exchange.request?.url || "";
    const responseUrl = exchange.response?.url || "";
    return !liveExcludePatterns.some(
      (pattern) =>
        (requestUrl && requestUrl.includes(pattern)) ||
        (responseUrl && responseUrl.includes(pattern))
    );
  });
  const visibleErrors = errors.filter((item) => !isAbortedErrorText(item?.errorText));

  useEffect(() => {
    if (authUser) {
      setStoredValue(AUTH_STORAGE_KEY, JSON.stringify(authUser));
      return;
    }

    if (typeof window !== "undefined") {
      window.localStorage.removeItem(AUTH_STORAGE_KEY);
    }
  }, [authUser]);

  useEffect(() => {
    let cancelled = false;

    const checkBackendHealth = async () => {
      setBackendHealth((current) => ({ ...current, checking: true }));

      try {
        const response = await fetch(`${API_BASE_URL}/api/health`);
        const data = await response.json().catch(() => ({}));

        if (cancelled) {
          return;
        }

        setBackendHealth({
          checkedAt: new Date().toISOString(),
          checking: false,
          ok: response.ok && Boolean(data.ok),
          error: response.ok ? "" : data?.error || `HTTP ${response.status}`,
          service: data?.service || "http-analyzer-api",
          supabaseConfigured: Boolean(data?.supabaseConfigured),
          captureDisabled:
            typeof data?.captureDisabled === "boolean" ? data.captureDisabled : null
        });
      } catch (error) {
        if (cancelled) {
          return;
        }

        setBackendHealth({
          checkedAt: new Date().toISOString(),
          checking: false,
          ok: false,
          error: error instanceof Error ? error.message : "Backend health check failed",
          service: "",
          supabaseConfigured: false,
          captureDisabled: null
        });
      }
    };

    checkBackendHealth();
    const timer = window.setInterval(checkBackendHealth, 30000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (readOnlyDeployment) {
      return;
    }

    const syncCaptureStatus = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/capture/status`);
        if (!response.ok) return;
        const data = await response.json();
        const nextActive = Boolean(data.active);
        const wasActive = activeRef.current;
        const autoStopped =
          wasActive &&
          !nextActive &&
          ["idle", "crawl-complete", "crawl-error"].includes(data.stopReason) &&
          data.sessionId &&
          autoStoppedSessionRef.current !== data.sessionId;

        activeRef.current = nextActive;
        setActive(nextActive);
        setCaptureSessionId(data.sessionId || "");
        setCaptureStartedAt(data.startedAt || "");
        setCaptureMeta({
          stopReason: data.stopReason || "",
          crawlActive: Boolean(data.crawlActive),
          crawlCompleted: Boolean(data.crawlCompleted),
          crawlVisited: Array.isArray(data.crawlVisited) ? data.crawlVisited : [],
          crawlQueueLength: Number(data.crawlQueueLength || 0),
          crawlMaxPages: Number(data.crawlMaxPages || 0),
          loginAttempted: Boolean(data.loginAttempted),
          loginStatus: data.loginStatus || "skipped",
          loginError: data.loginError || "",
          sessionApplied: Boolean(data.sessionApplied),
          sessionStatus: data.sessionStatus || "skipped",
          sessionError: data.sessionError || ""
        });
        setExchanges(data.exchanges || []);
        setErrors((data.errors || []).filter((item) => !isAbortedErrorText(item?.errorText)));

        if (autoStopped) {
          autoStoppedSessionRef.current = data.sessionId;
          const autoStopMessage =
            data.stopReason === "crawl-complete"
              ? "크롤링이 완료되어 캡처가 자동 중지되었습니다. Recent Data를 갱신했습니다."
              : data.stopReason === "crawl-error"
                ? "크롤링 중 오류가 발생해 캡처가 자동 중지되었습니다. Recent Data를 갱신했습니다."
                : "네트워크 활동이 없어 캡처가 자동 중지되었습니다. Recent Data를 갱신했습니다.";
          setStatusMessage(autoStopMessage);

          const recentResponse = await fetch(`${API_BASE_URL}/api/recent-analyses`).catch(() => null);
          if (recentResponse?.ok) {
            const recentData = await recentResponse.json();
            setRecentHarAnalyses(Array.isArray(recentData.harAnalyses) ? recentData.harAnalyses : []);
            setRecentCaptureEvents(Array.isArray(recentData.captureEvents) ? recentData.captureEvents : []);
            setRecentInspectionRuns(
              Array.isArray(recentData.inspectionRuns) ? recentData.inspectionRuns : []
            );
          }
        }

        const persistedDomain = getStoredValue("http-analyzer-domain");
        const persistedExcludeInput = getStoredValue("http-analyzer-exclude-patterns");
        const serverExcludeInput = Array.isArray(data.excludePatterns)
          ? data.excludePatterns.join(", ")
          : "";

        if (!persistedDomain && data.targetUrl) {
          setDomain((current) => current || data.targetUrl);
        }

        if (!persistedExcludeInput && serverExcludeInput) {
          setExcludeInput((current) => current || serverExcludeInput);
        }
      } catch {
        return;
      }
    };

    syncCaptureStatus();
    const timer = window.setInterval(syncCaptureStatus, 1000);

    return () => window.clearInterval(timer);
  }, [readOnlyDeployment]);

  useEffect(() => {
    const loadRecentAnalyses = async () => {
      setRecentLoading(true);
      try {
        const data = readOnlyDeployment
          ? await loadRecentFromSupabase()
          : await fetch(`${API_BASE_URL}/api/recent-analyses`).then(async (response) => {
              if (!response.ok) {
                return {
                  harAnalyses: [],
                  captureEvents: [],
                  inspectionRuns: []
                };
              }

              return response.json();
            });

        setRecentHarAnalyses(Array.isArray(data.harAnalyses) ? data.harAnalyses : []);
        setRecentCaptureEvents(Array.isArray(data.captureEvents) ? data.captureEvents : []);
        setRecentInspectionRuns(Array.isArray(data.inspectionRuns) ? data.inspectionRuns : []);
      } catch {
        return;
      } finally {
        setRecentLoading(false);
      }
    };

    loadRecentAnalyses();
    const timer = window.setInterval(loadRecentAnalyses, 15000);
    return () => window.clearInterval(timer);
  }, [readOnlyDeployment]);

  useEffect(() => {
    if (readOnlyDeployment) {
      return;
    }

    const syncLocalQueue = async () => {
      const pendingRuns = localInspectionRuns.filter((item) => item.pending_sync);
      const pendingEvents = localCaptureEvents.filter((item) => item.pending_sync);

      if (pendingRuns.length === 0 && pendingEvents.length === 0) {
        return;
      }

      try {
        for (const run of pendingRuns) {
          const response = await fetch(`${API_BASE_URL}/api/inspection-runs`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              capture_session_id: run.capture_session_id ?? null,
              target_url: run.target_url,
              started_at: run.started_at ?? null,
              ended_at: run.ended_at ?? null,
              total_exchanges: run.total_exchanges ?? 0,
              total_errors: run.total_errors ?? 0,
              total_findings: run.total_findings ?? 0,
              critical_findings: run.critical_findings ?? 0,
              high_findings: run.high_findings ?? 0,
              security_only: Boolean(run.security_only),
              mask_sensitive: Boolean(run.mask_sensitive),
              excluded_patterns: Array.isArray(run.excluded_patterns) ? run.excluded_patterns : [],
              owasp_summary: Array.isArray(run.owasp_summary) ? run.owasp_summary : [],
              endpoint_summary: Array.isArray(run.endpoint_summary) ? run.endpoint_summary : [],
              report_snapshot:
                run.report_snapshot && typeof run.report_snapshot === "object"
                  ? run.report_snapshot
                  : {}
            })
          });

          if (response.ok) {
            setLocalInspectionRuns((current) => current.filter((item) => item.id !== run.id));
          }
        }

        if (pendingEvents.length > 0) {
          const response = await fetch(`${API_BASE_URL}/api/capture-events/batch`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              events: pendingEvents.map((item) => ({
                capture_session_id: item.capture_session_id ?? null,
                target_url: item.target_url ?? null,
                request_timestamp: item.request_timestamp ?? item.created_at ?? null,
                request_method: item.request_method ?? null,
                request_url: item.request_url ?? null,
                request_resource_type: item.request_resource_type ?? null,
                request_headers: item.request_headers ?? {},
                request_body: item.request_body ?? "",
                response_timestamp: item.response_timestamp ?? null,
                response_url: item.response_url ?? null,
                response_status: item.response_status ?? null,
                response_status_text: item.response_status_text ?? null,
                response_headers: item.response_headers ?? {},
                response_body_preview: item.response_body_preview ?? "",
                error_text: item.error_text ?? null
              }))
            })
          });

          if (response.ok) {
            const syncedIds = new Set(pendingEvents.map((item) => item.id));
            setLocalCaptureEvents((current) => current.filter((item) => !syncedIds.has(item.id)));
          }
        }
      } catch {
        return;
      }
    };

    syncLocalQueue();
    const timer = window.setInterval(syncLocalQueue, 15000);
    return () => window.clearInterval(timer);
  }, [localInspectionRuns, localCaptureEvents, readOnlyDeployment]);

  useEffect(() => {
    if (!readOnlyDeployment) {
      return;
    }

    if (["capture", "har"].includes(activeSection)) {
      setActiveSection("recent");
    }
  }, [activeSection, readOnlyDeployment]);

  useEffect(() => {
    setStoredValue("http-analyzer-domain", domain);
  }, [domain]);

  useEffect(() => {
    setStoredValue("http-analyzer-exclude-patterns", excludeInput);
  }, [excludeInput]);

  useEffect(() => {
    setStoredValue("http-analyzer-security-only", String(securityOnly));
  }, [securityOnly]);

  useEffect(() => {
    setStoredValue("http-analyzer-mask-sensitive", String(maskSensitive));
  }, [maskSensitive]);

  useEffect(() => {
    setStoredValue("http-analyzer-active-section", activeSection);
  }, [activeSection]);

  useEffect(() => {
    setStoredValue("http-analyzer-sidebar-collapsed", String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  useEffect(() => {
    setStoredValue(LOCAL_INSPECTION_RUNS_KEY, JSON.stringify(localInspectionRuns));
  }, [localInspectionRuns]);

  useEffect(() => {
    setStoredValue(LOCAL_CAPTURE_EVENTS_KEY, JSON.stringify(localCaptureEvents));
  }, [localCaptureEvents]);

  useEffect(() => {
    setStoredValue(LOCAL_HAR_HISTORY_KEY, JSON.stringify(localHarHistory));
  }, [localHarHistory]);

  useEffect(() => {
    if (normalizedHarHistory.length === 0) {
      setSelectedHarHistoryKey("");
      return;
    }

    if (!normalizedHarHistory.some((item) => item.historyKey === selectedHarHistoryKey)) {
      setSelectedHarHistoryKey(normalizedHarHistory[0].historyKey);
    }
  }, [normalizedHarHistory, selectedHarHistoryKey]);

  useEffect(() => {
    setStoredValue("http-analyzer-suppressed-findings", JSON.stringify(suppressedFindings));
  }, [suppressedFindings]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    window.sessionStorage.setItem(
      "http-analyzer-session-suppressed-findings",
      JSON.stringify(sessionSuppressedFindings)
    );
  }, [sessionSuppressedFindings]);

  async function startCapture(event) {
    event.preventDefault();
    if (readOnlyDeployment) {
      setStatusMessage("배포 사이트에서는 캡처를 실행할 수 없습니다. 로컬 앱을 사용해주세요.");
      return;
    }

    setSubmitting(true);
    setStatusMessage("");

    try {
      const excludePatterns = excludeInput
        ? getCombinedExcludePatterns(excludeInput)
        : [...FIXED_EXCLUDE_PATTERNS];

      const credentials =
        !sessionValue.trim() && loginId.trim() && loginPassword
          ? {
              username: loginId.trim(),
              password: loginPassword
            }
          : null;

      const response = await fetch(`${API_BASE_URL}/api/capture/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain,
          excludePatterns,
          credentials,
          sessionValue: sessionValue.trim()
        })
      });

      const { data, rawText } = await readJsonSafely(response);
      if (!response.ok) {
        throw new Error(data?.error || rawText || "캡처 시작에 실패했습니다.");
      }

      const result = data || {};

      setStatusMessage("");
      setCaptureSessionId(result.sessionId || "");
      setCaptureStartedAt(result.startedAt || "");
      setCaptureMeta({
        stopReason: "",
        crawlActive: Boolean(result.crawlEnabled),
        crawlCompleted: false,
        crawlVisited: [],
        crawlQueueLength: 0,
        crawlMaxPages: Number(result.crawlMaxPages || 0),
        loginAttempted: Boolean(result.loginAttempted),
        loginStatus: result.loginStatus || "skipped",
        loginError: result.loginError || "",
        sessionApplied: Boolean(result.sessionApplied),
        sessionStatus: result.sessionStatus || "skipped",
        sessionError: result.sessionError || ""
      });
      activeRef.current = true;
      autoStoppedSessionRef.current = "";
      setExchanges([]);
      setErrors([]);
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function stopCapture() {
    if (readOnlyDeployment) {
      setStatusMessage("배포 사이트에서는 캡처를 중지할 수 없습니다. 로컬 앱을 사용해주세요.");
      return;
    }

    setSubmitting(true);
    setStatusMessage("");

    try {
      const snapshot = buildInspectionSnapshot();
      const endedAt = new Date().toISOString();
      const localRun = {
        id: `local-run-${Date.now()}`,
        created_at: endedAt,
        pending_sync: true,
        capture_session_id: captureSessionId || null,
        target_url: domain || getStoredValue("http-analyzer-domain") || "unknown",
        started_at: captureStartedAt || null,
        ended_at: endedAt,
        total_exchanges: analyzedExchanges.length,
        total_errors: errors.length,
        total_findings: allSecurityFindings.length,
        critical_findings: criticalAlerts.length,
        high_findings: highAlerts.length,
        security_only: securityOnly,
        mask_sensitive: maskSensitive,
        excluded_patterns: getCombinedExcludePatterns(excludeInput),
        owasp_summary: owaspSummary,
        endpoint_summary: endpointSummary.slice(0, 10),
        report_snapshot: snapshot
      };
      const localEvents = analyzedExchanges
        .slice()
        .reverse()
        .slice(0, 20)
        .map((exchange, index) => ({
          id: `local-event-${Date.now()}-${index}`,
          created_at: exchange.timestamp || endedAt,
          pending_sync: true,
          capture_session_id: captureSessionId || null,
          target_url: domain || getStoredValue("http-analyzer-domain") || "unknown",
          request_method: exchange.request?.method || "?",
          request_url: exchange.request?.url || exchange.endpointKey || "",
          request_resource_type: exchange.request?.resourceType || "-",
          request_timestamp: exchange.timestamp || endedAt,
          request_headers: exchange.request?.headers || {},
          request_body: exchange.request?.postData || "",
          response_status: exchange.response?.status || null,
          response_status_text: exchange.response?.statusText || null,
          response_timestamp: exchange.response?.timestamp || null,
          response_url: exchange.response?.url || null,
          response_headers: exchange.response?.headers || {},
          response_body_preview: exchange.response?.bodyPreview || "",
          error_text: "",
          historySource: "local"
        }))
        .filter((item) => !isAbortedErrorText(item.error_text));

      setLocalInspectionRuns((current) =>
        [localRun, ...current].slice(0, 20)
      );
      setLocalCaptureEvents((current) =>
        [...localEvents, ...current].filter((item) => !isAbortedErrorText(item.error_text)).slice(0, 40)
      );
      setErrors((current) => current.filter((item) => !isAbortedErrorText(item.errorText)));

      if (captureSessionId || domain) {
        const inspectionResponse = await fetch(`${API_BASE_URL}/api/inspection-runs`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            capture_session_id: captureSessionId || null,
            target_url: domain || getStoredValue("http-analyzer-domain") || "unknown",
            started_at: captureStartedAt || null,
            ended_at: endedAt,
            total_exchanges: analyzedExchanges.length,
            total_errors: errors.length,
            total_findings: allSecurityFindings.length,
            critical_findings: criticalAlerts.length,
            high_findings: highAlerts.length,
            security_only: securityOnly,
            mask_sensitive: maskSensitive,
            excluded_patterns: getCombinedExcludePatterns(excludeInput),
            owasp_summary: owaspSummary,
            endpoint_summary: endpointSummary.slice(0, 10),
            report_snapshot: snapshot
          })
        }).catch(() => null);

        if (inspectionResponse?.ok) {
          setLocalInspectionRuns((current) => current.filter((item) => item.id !== localRun.id));
        }
      }

      await fetch(`${API_BASE_URL}/api/capture/stop`, { method: "POST" });
      setStatusMessage("");
      setActive(false);
      activeRef.current = false;
      setCaptureSessionId("");
      setCaptureStartedAt("");

      try {
        const recentResponse = await fetch(`${API_BASE_URL}/api/recent-analyses`);
        if (recentResponse.ok) {
          const recentData = await recentResponse.json();
          setRecentHarAnalyses(Array.isArray(recentData.harAnalyses) ? recentData.harAnalyses : []);
          setRecentCaptureEvents(Array.isArray(recentData.captureEvents) ? recentData.captureEvents : []);
          setRecentInspectionRuns(
            Array.isArray(recentData.inspectionRuns) ? recentData.inspectionRuns : []
          );
        }
      } catch {
        return;
      }
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function uploadHarFile() {
    if (readOnlyDeployment) {
      setHarUploadError("배포 사이트에서는 HAR 업로드를 실행할 수 없습니다. 로컬 앱을 사용해주세요.");
      return;
    }

    if (!harFile) {
      setHarUploadError("HAR 파일을 먼저 선택해주세요.");
      return;
    }

    setHarUploading(true);
    setHarUploadError("");
    setHarUploadResult(null);

    try {
      const localHarText = await harFile.text();
      const localHar = JSON.parse(localHarText);
      const localSummary = analyzeHarLocally(localHar);
      const fingerprint = buildHarHistoryFingerprint({
        fileName: harFile.name,
        fileSize: harFile.size,
        summary: localSummary
      });
      const localHistoryItem = {
        id: `local-${Date.now()}`,
        created_at: new Date().toISOString(),
        file_name: harFile.name,
        file_size: harFile.size,
        total_entries: localSummary.totalEntries,
        average_wait_ms: localSummary.averageWaitMs,
        slowest_url: localSummary.slowestEntry?.url || null,
        summary: localSummary,
        fingerprint
      };

      setHarUploadResult({
        fileName: harFile.name,
        fileSize: harFile.size,
        summary: localSummary,
        storage: {
          saved: false,
          reason: "로컬 분석 결과입니다. 서버 저장 상태는 확인 중입니다."
        }
      });
      setLocalHarHistory((current) => [
        localHistoryItem,
        ...current.filter((item) => item.fingerprint !== fingerprint)
      ].slice(0, 12));
      setSelectedHarHistoryKey(`local:${localHistoryItem.id}`);

      const formData = new FormData();
      formData.append("har", harFile);

      const response = await fetch(`${API_BASE_URL}/api/analyze-har`, {
        method: "POST",
        body: formData
      });

      const { data, rawText } = await readJsonSafely(response);

      if (!response.ok) {
        throw new Error(data?.error || data?.message || rawText || "HAR 업로드에 실패했습니다.");
      }

      setHarUploadResult(data || null);
      if (data?.storage?.saved) {
        setLocalHarHistory((current) => current.filter((item) => item.fingerprint !== fingerprint));
      }

      try {
        const recentResponse = await fetch(`${API_BASE_URL}/api/recent-analyses`);
        if (recentResponse.ok) {
          const recentData = await recentResponse.json();
          setRecentHarAnalyses(Array.isArray(recentData.harAnalyses) ? recentData.harAnalyses : []);
          setRecentCaptureEvents(Array.isArray(recentData.captureEvents) ? recentData.captureEvents : []);
          setRecentInspectionRuns(
            Array.isArray(recentData.inspectionRuns) ? recentData.inspectionRuns : []
          );
        }
      } catch {
        return;
      }
    } catch (error) {
      setHarUploadError(error.message);
    } finally {
      setHarUploading(false);
    }
  }

  function suppressFinding(finding, exchange) {
    const rule = buildSuppressionRule("endpoint", finding, exchange);
    setSuppressedFindings((current) => (current.some((item) => item.id === rule.id) ? current : [...current, rule]));
  }

  function suppressFindingByScope(scope, finding, exchange) {
    const rule = buildSuppressionRule(scope, finding, exchange);

    if (scope === "session") {
      setSessionSuppressedFindings((current) =>
        current.some((item) => item.id === rule.id) ? current : [...current, rule]
      );
      return;
    }

    setSuppressedFindings((current) =>
      current.some((item) => item.id === rule.id) ? current : [...current, rule]
    );
  }

  function clearSuppressedFindings() {
    setSuppressedFindings([]);
    setSessionSuppressedFindings([]);
  }

  function injectPocIntoReplay(finding, exchange) {
    if (readOnlyDeployment) {
      setStatusMessage("배포 사이트에서는 Replay를 실행할 수 없습니다. 로컬 앱을 사용해주세요.");
      return;
    }

    if (!exchange.request) {
      return;
    }

    const template = generateFindingPoc(finding, exchange);
    const payloadMatch = template.match(/Body\/Payload:\s*([\s\S]*)$/);
    const payload = payloadMatch ? payloadMatch[1].trim() : exchange.request.postData || "";

    setReplayResponse(null);
    setReplayError("");
    setModalState({
      method: exchange.request.method,
      url: exchange.request.url,
      headers: prettyJson(exchange.request.headers),
      body: payload === "(none)" ? "" : payload
    });
  }

  function generateCaptureMermaid() {
    setCaptureMermaidModal(buildCaptureMermaid(visibleExchanges));
  }

  async function copyCaptureMermaid() {
    if (!captureMermaidModal || typeof navigator === "undefined" || !navigator.clipboard) {
      return;
    }

    try {
      await navigator.clipboard.writeText(captureMermaidModal);
      setCaptureMermaidModal("");
    } catch {
      return;
    }
  }

  function buildHtmlReportDocument(reportInput = {}, { forPrint = false } = {}) {
    const reportDomain = reportInput.domain ?? domain;
    const reportExcluded = reportInput.excluded ?? getCombinedExcludePatterns(excludeInput);
    const reportSecurityOnly = reportInput.securityOnly ?? securityOnly;
    const reportMaskSensitive = reportInput.maskSensitive ?? maskSensitive;
    const reportOwaspSummary = reportInput.owaspSummary ?? owaspSummary;
    const reportEndpointSummary = reportInput.endpointSummary ?? endpointSummary;
    const reportInspector = reportInput.inspector ?? authUser?.email ?? "-";
    const reportExportedAt = reportInput.exportedAt ?? new Date().toISOString();
    const reportConclusion =
      reportInput.conclusion ||
      buildInspectionConclusion({
        totalFindings: reportInput.totalFindings ?? allSecurityFindings.length,
        criticalFindings: reportInput.criticalFindings ?? criticalAlerts.length,
        highFindings: reportInput.highFindings ?? highAlerts.length,
        totalErrors: reportInput.totalErrors ?? errors.length
      });
    const reportExchanges = reportInput.exchanges ?? visibleExchanges;

    const sections = reportExchanges
      .map((exchange, index) => {
        const requestTitle = exchange.request
          ? `${exchange.request.method} ${maybeMask(exchange.request.url, reportMaskSensitive)}`
          : "(request unavailable)";
        const requestMeta = exchange.request
          ? `${exchange.request.resourceType} · ${exchange.timestamp}`
          : exchange.timestamp;
        const responseTitle = exchange.response
          ? `${exchange.response.status} ${maybeMask(exchange.response.url, maskSensitive)}`
          : "(pending response)";
        const responseMeta = exchange.response
          ? `${exchange.response.statusText} · ${exchange.response.timestamp}`
          : "";
        const findingsHtml =
          exchange.securityFindings.length > 0
            ? `<section class="findings">
                <h4>Security Findings</h4>
                <div class="owasp-summary">
                  ${summarizeFindingsByOwasp(exchange.securityFindings)
                    .map(
                      (item) =>
                        `<span class="owasp-chip">${escapeHtml(item.label)} (${item.count})</span>`
                    )
                    .join("")}
                </div>
                ${exchange.securityFindings
                  .map(
                    (finding) => `
                      <article class="finding-card finding-${finding.severity}">
                        <div class="finding-head">
                          <strong>${escapeHtml(finding.title)}</strong>
                          <span>${escapeHtml(finding.severityLabel)}</span>
                        </div>
                        <p><strong>OWASP:</strong> ${escapeHtml(finding.owaspLabel)}</p>
                        <p><strong>Area:</strong> ${escapeHtml(finding.area)}</p>
                        <p><strong>Evidence:</strong> ${escapeHtml(maybeMask(finding.evidence, reportMaskSensitive))}</p>
                        <p><strong>Guide:</strong> ${escapeHtml(finding.guide)}</p>
                        <p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>
                        <p><strong>Confidence:</strong> ${escapeHtml(finding.confidenceLabel)}</p>
                        <div class="finding-checklist">
                          <strong>Checklist</strong>
                          <ul>
                            ${finding.checklist
                              .map((item) => `<li>${escapeHtml(item)}</li>`)
                              .join("")}
                          </ul>
                        </div>
                      </article>
                    `
                  )
                  .join("")}
              </section>`
            : "";

        return `
          <section class="pair-card">
            <div class="pair-index">#${index + 1}</div>
            <div class="pair-grid">
              <article class="box request">
                <div class="chip request-chip">REQUEST</div>
                <h3>${escapeHtml(requestTitle)}</h3>
                <p class="meta">${escapeHtml(requestMeta)}</p>
                <pre>${escapeHtml(`Headers\n${maybeMask(prettyJson(exchange.request?.headers), reportMaskSensitive)}\n\nBody\n${
                  maybeMask(exchange.request?.postData || "(empty)", reportMaskSensitive)
                }`)}</pre>
              </article>
              <article class="box response">
                <div class="chip response-chip">RESPONSE</div>
                <h3>${escapeHtml(responseTitle)}</h3>
                <p class="meta">${escapeHtml(responseMeta)}</p>
                <pre>${escapeHtml(`Headers\n${maybeMask(prettyJson(exchange.response?.headers), reportMaskSensitive)}\n\nBody Preview\n${
                  maybeMask(exchange.response?.bodyPreview || "(binary, empty, or pending)", reportMaskSensitive)
                }`)}</pre>
              </article>
            </div>
            ${findingsHtml}
          </section>
        `;
      })
      .join("");

    return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HTTP Analyzer Report</title>
  <style>
    body{margin:0;padding:24px;background:#eef2f6;color:#172033;font-family:"KoPubDotum","KoPub돋움체",sans-serif}
    .wrap{max-width:1400px;margin:0 auto}
    .cover{padding:28px;border-radius:20px;background:linear-gradient(180deg,#e8f3eb,#dff1e6);border:1px solid #b9ddc4;box-shadow:0 12px 32px rgba(15,23,42,.08);margin-bottom:16px}
    .cover h1{margin:0 0 10px;font-size:34px}
    .cover p{margin:6px 0;color:#355240}
    .conclusion{margin-top:16px;padding:14px 16px;border-radius:14px;background:#fff;border:1px solid #d8e0ea}
    .hero{padding:20px 24px;border-radius:16px;background:#fff;border:1px solid #d8e0ea;box-shadow:0 12px 32px rgba(15,23,42,.08)}
    .hero h1{margin:0 0 8px;font-size:28px}
    .hero p{margin:4px 0;color:#475569}
    .pair-card{margin-top:16px;padding:16px;border-radius:16px;background:#fff;border:1px solid #d8e0ea;box-shadow:0 10px 24px rgba(15,23,42,.06)}
    .pair-index{margin-bottom:10px;font-weight:700;color:#64748b}
    .pair-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
    .findings{margin-top:16px;display:grid;gap:10px}
    .findings h4{margin:0;font-size:16px;color:#7c2d12}
    .owasp-summary{display:flex;flex-wrap:wrap;gap:8px}
    .owasp-chip{display:inline-flex;padding:4px 8px;border-radius:999px;background:#fef3c7;color:#92400e;font-size:12px;font-weight:700}
    .finding-card{padding:12px;border-radius:12px;border:1px solid #fcd34d;background:#fffbeb}
    .finding-head{display:flex;justify-content:space-between;gap:12px;margin-bottom:8px}
    .finding-head span{font-size:12px;font-weight:700;color:#92400e}
    .finding-card p{margin:6px 0;color:#78350f;font-size:13px;line-height:1.45}
    .finding-checklist strong{display:block;margin-top:8px;color:#7c2d12}
    .finding-checklist ul{margin:6px 0 0 18px;padding:0}
    .finding-checklist li{margin:4px 0;color:#78350f;font-size:13px;line-height:1.4}
    .box{padding:14px;border-radius:12px}
    .request{background:#eef7ff;border:1px solid #c7defc}
    .response{background:#fff6ec;border:1px solid #ffd5b5}
    .chip{display:inline-flex;padding:4px 8px;border-radius:999px;font-size:12px;font-weight:700;margin-bottom:10px}
    .request-chip{background:#dbeafe;color:#1d4ed8}
    .response-chip{background:#ffedd5;color:#c2410c}
    h3{margin:0 0 6px;font-size:16px;word-break:break-all}
    .meta{margin:0 0 12px;color:#64748b;font-size:13px}
    pre{margin:0;padding:12px;border-radius:10px;background:#f8fafc;border:1px solid #e2e8f0;white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.4;color:#334155}
    @media (max-width: 900px){.pair-grid{grid-template-columns:1fr}}
    @media print{body{background:#fff;padding:0}.wrap{max-width:none}.pair-card,.hero{box-shadow:none}${forPrint ? "" : ""}}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="cover">
      <h1>HTTP Analyzer Security Inspection Report</h1>
      <p><strong>점검자:</strong> ${escapeHtml(reportInspector)}</p>
      <p><strong>점검 일시:</strong> ${escapeHtml(formatDateTime(reportExportedAt))}</p>
      <p><strong>대상:</strong> ${escapeHtml(reportDomain || "-")}</p>
      <div class="conclusion">
        <strong>결론</strong>
        <p>${escapeHtml(reportConclusion)}</p>
      </div>
    </section>
    <section class="hero">
      <h1>HTTP Analyzer Report</h1>
      <p><strong>Domain:</strong> ${escapeHtml(reportDomain || "-")}</p>
      <p><strong>Excluded:</strong> ${escapeHtml(reportExcluded.join(", "))}</p>
      <p><strong>Security Check:</strong> ${reportSecurityOnly ? "ON" : "OFF"}</p>
      <p><strong>Visible Pairs:</strong> ${reportExchanges.length}</p>
      <p><strong>Mask Sensitive:</strong> ${reportMaskSensitive ? "ON" : "OFF"}</p>
      <p><strong>OWASP Summary:</strong> ${escapeHtml(
        reportOwaspSummary.map((item) => `${item.label}(${item.count})`).join(", ") || "-"
      )}</p>
      <p><strong>Top Endpoints:</strong> ${escapeHtml(
        reportEndpointSummary.slice(0, 3).map((item) => item.endpoint).join(", ") || "-"
      )}</p>
    </section>
    ${sections}
  </div>
</body>
<\/html>`;
  }

  function buildInspectionSnapshot() {
    return {
      exportedAt: new Date().toISOString(),
      inspector: authUser?.email || "-",
      domain,
      excluded: getCombinedExcludePatterns(excludeInput),
      securityOnly,
      maskSensitive,
      totalErrors: errors.length,
      totalFindings: allSecurityFindings.length,
      criticalFindings: criticalAlerts.length,
      highFindings: highAlerts.length,
      conclusion: buildInspectionConclusion({
        totalFindings: allSecurityFindings.length,
        criticalFindings: criticalAlerts.length,
        highFindings: highAlerts.length,
        totalErrors: errors.length
      }),
      owaspSummary,
      endpointSummary,
      summary: {
        visiblePairs: visibleExchanges.length,
        totalFindings: allSecurityFindings.length
      },
      exchanges: visibleExchanges.map((exchange) => ({
        ...exchange,
        securityFindings: (exchange.securityFindings || []).map((finding) => ({
          ...finding,
          evidence: maybeMask(finding.evidence, maskSensitive)
        })),
        request: exchange.request
          ? {
              ...exchange.request,
              url: maybeMask(exchange.request.url || "", maskSensitive),
              headers: exchange.request.headers,
              postData: maybeMask(exchange.request.postData || "", maskSensitive)
            }
          : null,
        response: exchange.response
          ? {
              ...exchange.response,
              url: maybeMask(exchange.response.url || "", maskSensitive),
              headers: exchange.response.headers,
              bodyPreview: maybeMask(exchange.response.bodyPreview || "", maskSensitive)
            }
          : null
      }))
    };
  }

  function downloadHtmlReport(snapshot = buildInspectionSnapshot()) {
    const html = buildHtmlReportDocument(snapshot);
    downloadTextFile(html, `http-analyzer-report-${Date.now()}.html`, "text/html;charset=utf-8");
  }

  function downloadPdfReport(snapshot = buildInspectionSnapshot()) {
    const html = buildHtmlReportDocument(snapshot, { forPrint: true });
    const reportWindow = window.open("", "_blank", "noopener,noreferrer");

    if (!reportWindow) {
      setStatusMessage("팝업이 차단되어 PDF 리포트를 열 수 없습니다.");
      return;
    }

    reportWindow.document.open();
    reportWindow.document.write(html.replace(
      "</body>",
      `<script>
window.addEventListener("load", () => {
  setTimeout(() => window.print(), 250);
});
</script></body>`
    ));
    reportWindow.document.close();
  }


  function downloadJsonReport() {
    const payload = {
      exportedAt: new Date().toISOString(),
      domain,
      excluded: getCombinedExcludePatterns(excludeInput),
      securityOnly,
      maskSensitive,
      owaspSummary,
      endpointSummary,
      exchanges: visibleExchanges.map((exchange) => ({
        id: exchange.id,
        endpoint: exchange.endpointKey,
        request: {
          method: exchange.request?.method || "",
          url: maybeMask(exchange.request?.url || "", maskSensitive),
          headers: maybeMask(prettyJson(exchange.request?.headers), maskSensitive),
          body: maybeMask(exchange.request?.postData || "", maskSensitive)
        },
        response: {
          status: exchange.response?.status || "",
          url: maybeMask(exchange.response?.url || "", maskSensitive),
          headers: maybeMask(prettyJson(exchange.response?.headers), maskSensitive),
          bodyPreview: maybeMask(exchange.response?.bodyPreview || "", maskSensitive)
        },
        findings: exchange.securityFindings.map((finding) => ({
          ...finding,
          evidence: maybeMask(finding.evidence, maskSensitive)
        }))
      }))
    };

    downloadTextFile(JSON.stringify(payload, null, 2), `http-analyzer-report-${Date.now()}.json`, "application/json;charset=utf-8");
  }

  function downloadMarkdownReport() {
    const markdown = [
      "# HTTP Analyzer Report",
      "",
      `- Domain: ${domain || "-"}`,
      `- Excluded: ${getCombinedExcludePatterns(excludeInput).join(", ") || "-"}`,
      `- Security Check: ${securityOnly ? "ON" : "OFF"}`,
      `- Mask Sensitive: ${maskSensitive ? "ON" : "OFF"}`,
      "",
      "## OWASP Summary",
      ...owaspSummary.map((item) => `- ${item.label}: ${item.count}`),
      "",
      "## Endpoint Risk Summary",
      ...endpointSummary.slice(0, 10).map(
        (item) =>
          `- ${item.endpoint} | score=${item.score} | findings=${item.findings} | highest=${item.highestSeverityLabel}`
      ),
      "",
      "## Findings"
    ]
      .concat(
        visibleExchanges.flatMap((exchange, index) => {
          const lines = [
            `### ${index + 1}. ${exchange.request?.method || "?"} ${exchange.endpointKey}`,
            ""
          ];

          if (exchange.securityFindings.length === 0) {
            lines.push("- No findings", "");
            return lines;
          }

          for (const finding of exchange.securityFindings) {
            lines.push(`- ${finding.title} [${finding.severityLabel}]`);
            lines.push(`  OWASP: ${finding.owaspLabel}`);
            lines.push(`  Evidence: ${maybeMask(finding.evidence, maskSensitive)}`);
            lines.push(`  Guide: ${finding.guide}`);
            lines.push(`  Remediation: ${finding.remediation}`);
            lines.push(`  Confidence: ${finding.confidenceLabel}`);
          }

          lines.push("");
          return lines;
        })
      )
      .join("\n");

    downloadTextFile(markdown, `http-analyzer-report-${Date.now()}.md`, "text/markdown;charset=utf-8");
  }

  function downloadCsvReport() {
    const rows = [
      ["endpoint", "method", "status", "title", "severity", "owasp", "evidence", "confidence"].join(",")
    ];

    for (const exchange of visibleExchanges) {
      for (const finding of exchange.securityFindings) {
        const values = [
          exchange.endpointKey,
          exchange.request?.method || "",
          String(exchange.response?.status || ""),
          finding.title,
          finding.severityLabel,
          finding.owaspLabel,
          maybeMask(finding.evidence, maskSensitive),
          finding.confidenceLabel
        ].map((value) => `"${String(value).replaceAll('"', '""')}"`);

        rows.push(values.join(","));
      }
    }

    downloadTextFile(rows.join("\n"), `http-analyzer-report-${Date.now()}.csv`, "text/csv;charset=utf-8");
  }

  function openReplayModal(exchange) {
    if (readOnlyDeployment) {
      setStatusMessage("배포 사이트에서는 Replay를 실행할 수 없습니다. 로컬 앱을 사용해주세요.");
      return;
    }

    if (!exchange.request) return;
    setReplayResponse(null);
    setReplayError("");
    setModalState({
      method: exchange.request.method,
      url: exchange.request.url,
      headers: prettyJson(exchange.request.headers),
      body: exchange.request.postData || ""
    });
  }

  async function replayRequest() {
    if (readOnlyDeployment) {
      setReplayError("배포 사이트에서는 Replay를 실행할 수 없습니다. 로컬 앱을 사용해주세요.");
      return;
    }

    if (!modalState) return;
    setReplayLoading(true);
    setReplayError("");
    setReplayResponse(null);

    try {
      const headers = modalState.headers ? JSON.parse(modalState.headers) : {};
      const response = await fetch(`${API_BASE_URL}/api/replay-request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          method: modalState.method,
          url: modalState.url,
          headers,
          body: modalState.body
        })
      });

      const { data, rawText } = await readJsonSafely(response);

      if (!response.ok) {
        throw new Error(data?.error || rawText || "요청 재전송에 실패했습니다.");
      }

      if (!data) {
        throw new Error(rawText || "서버가 JSON 응답을 반환하지 않았습니다.");
      }

      setReplayResponse(data.response);
    } catch (error) {
      setReplayError(error.message);
    } finally {
      setReplayLoading(false);
    }
  }

  function handleLogin(user) {
    setAuthUser(user);
  }

  function handleLogout() {
    setAuthUser(null);
    if (typeof window !== "undefined" && window.google?.accounts?.id) {
      window.google.accounts.id.disableAutoSelect();
    }
  }

  function openInspectionRun(run) {
    setInspectionModalRun(run);
  }

  const findingEntries = visibleExchanges.flatMap((exchange) =>
    (exchange.securityFindings || []).map((finding) => ({ exchange, finding }))
  );
  const displayedFindingEntries = focusedFindingExchangeId
    ? findingEntries.filter(({ exchange }) => exchange.id === focusedFindingExchangeId)
    : findingEntries;
  const capturedCount = visibleExchanges.length;
  const totalCapturedCount = analyzedExchanges.length;
  const captureErrorCount = visibleErrors.length;
  const crawledPageCount = captureMeta.crawlVisited.length;
  const captureStateLabel = active
    ? captureMeta.crawlActive
      ? "crawling"
      : "running"
    : captureMeta.stopReason === "crawl-complete"
      ? "complete"
      : captureMeta.stopReason === "crawl-error"
        ? "error"
        : "idle";
  const loginStateLabel = captureMeta.loginAttempted
    ? captureMeta.loginStatus || "attempting"
    : captureMeta.sessionApplied
      ? `session ${captureMeta.sessionStatus || "applied"}`
    : "no login";
  const captureProgressPercent = active
    ? captureMeta.crawlMaxPages > 0
      ? Math.min(96, Math.max(12, (crawledPageCount / captureMeta.crawlMaxPages) * 100))
      : Math.min(96, Math.max(12, capturedCount * 12))
    : capturedCount > 0
      ? 100
      : 0;

  const navigationItems = [
    {
      key: "overview",
      icon: "overview",
      label: "Overview",
      description: "위험도와 요약 현황",
      count: allSecurityFindings.length
    },
    {
      key: "capture",
      icon: "capture",
      label: "Capture",
      description: "실시간 캡처와 요청 목록",
      count: visibleExchanges.length
    },
    {
      key: "findings",
      icon: "findings",
      label: "Findings",
      description: "탐지된 보안 이슈",
      count: findingEntries.length
    },
    {
      key: "har",
      icon: "har",
      label: "HAR",
      description: "파일 업로드와 분석 결과",
      count: mergedHarHistory.length
    },
    {
      key: "recent",
      icon: "recent",
      label: "Recent Data",
      description: "최근 저장된 캡처 기록",
      count: mergedCaptureEvents.length + mergedInspectionRuns.length
    }
  ].filter((item) => !readOnlyDeployment || !["capture", "har"].includes(item.key));

  function navigateToSection(sectionKey) {
    if (sectionKey !== "findings") {
      setFocusedFindingExchangeId("");
    }

    if (sectionKey === "findings" && activeSection !== "capture") {
      setFocusedFindingExchangeId("");
    }

    setActiveSection(sectionKey);
  }

  useEffect(() => {
    if (activeSection !== "findings" || !focusedFindingExchangeId) {
      return;
    }

    const timer = window.setTimeout(() => {
      const target = document.querySelector(
        `[data-finding-exchange-id="${CSS.escape(focusedFindingExchangeId)}"]`
      );
      target?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 60);

    return () => window.clearTimeout(timer);
  }, [activeSection, focusedFindingExchangeId, displayedFindingEntries.length]);

  if (!authUser) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <main ref={appShellRef} className="page-shell">
      <div className={`app-layout ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
        <aside className="sidebar-card">
          <div className="sidebar-brand">
            <div className="sidebar-brand-row">
              <h1 className="page-title sidebar-title">HTTP Analyzer</h1>
              <button
                type="button"
                className="sidebar-toggle-button"
                onClick={() => setSidebarCollapsed((current) => !current)}
              >
                {sidebarCollapsed ? "열기" : "숨기기"}
              </button>
            </div>
          </div>
          <nav className="sidebar-nav">
            {navigationItems.map((item) => (
              <button
                key={item.key}
                type="button"
                className={`sidebar-nav-item ${activeSection === item.key ? "active" : ""}`}
                onClick={() => navigateToSection(item.key)}
              >
                <div className="sidebar-nav-topline">
                  <span className="sidebar-nav-icon">
                    <NavigationIcon name={item.icon} />
                  </span>
                  <span className="sidebar-nav-label">{item.label}</span>
                </div>
                <span className="sidebar-nav-description">{item.description}</span>
                <span className="sidebar-nav-count">{item.count}</span>
              </button>
            ))}
          </nav>
          <div className={`backend-status-card ${backendHealth.ok ? "online" : "offline"}`}>
            <div className="capture-progress-panel">
              <div className="capture-progress-topline">
                <strong>Capture</strong>
                <span>{captureStateLabel}</span>
              </div>
              <div className="capture-progress-track" aria-label="capture progress">
                <span
                  className={active ? "active" : ""}
                  style={{ width: `${captureProgressPercent}%` }}
                />
              </div>
              <div className="capture-progress-meta">
                <span>{capturedCount} captured</span>
                <span>{totalCapturedCount} total</span>
                <span>
                  {crawledPageCount}/{captureMeta.crawlMaxPages || "-"} pages
                </span>
                <span>login {loginStateLabel}</span>
                <span>{captureErrorCount} errors</span>
              </div>
            </div>
            <div className="backend-status-topline">
              <span className="backend-status-dot" />
              <strong>Backend</strong>
              <span>{backendHealth.checking ? "checking" : backendHealth.ok ? "online" : "offline"}</span>
            </div>
            <div className="backend-status-body">
              <span>API: {API_BASE_URL.replace(/^https?:\/\//, "")}</span>
              <span>
                Capture:{" "}
                {backendHealth.captureDisabled === null
                  ? "-"
                  : backendHealth.captureDisabled
                    ? "disabled"
                    : "enabled"}
              </span>
              <span>DB: {backendHealth.supabaseConfigured ? "connected" : "not set"}</span>
              <span>
                Last:{" "}
                {backendHealth.checkedAt
                  ? new Date(backendHealth.checkedAt).toLocaleTimeString()
                  : "-"}
              </span>
              {backendHealth.error ? <span className="backend-status-error">{backendHealth.error}</span> : null}
            </div>
          </div>
        </aside>

        <div className="content-shell">
          <section className="hero-card filter-shell">
            <div className="topbar">
              <div>
                <p className="eyebrow">Operations Overview</p>
                <h1 className="page-title">HTTP Analyzer</h1>
              </div>
              <div className="topbar-badges">
                <div className="login-user-copy">
                  {authUser.picture ? (
                    <img src={authUser.picture} alt={authUser.name} className="user-avatar" />
                  ) : null}
                  <div>
                    <span>{authUser.email}</span>
                  </div>
                </div>
                <span className={`capture-badge ${active ? "live" : ""}`}>
                  {active ? "LIVE" : "IDLE"}
                </span>
                <label className="security-toggle">
                  <input
                    type="checkbox"
                    checked={securityOnly}
                    onChange={(event) => setSecurityOnly(event.target.checked)}
                  />
                  <span>Security Check</span>
                </label>
                <label className="security-toggle">
                  <input
                    type="checkbox"
                    checked={maskSensitive}
                    onChange={(event) => setMaskSensitive(event.target.checked)}
                  />
                  <span>Mask Secrets</span>
                </label>
                <button type="button" className="logout-button" onClick={handleLogout}>
                  로그아웃
                </button>
              </div>
            </div>
            <div className="dashboard-ribbon">
              <div className="dashboard-ribbon-card">
                <span className="dashboard-ribbon-label">Current Module</span>
                <strong>{navigationItems.find((item) => item.key === activeSection)?.label || "Overview"}</strong>
              </div>
              <div className="dashboard-ribbon-card">
                <span className="dashboard-ribbon-label">Security Findings</span>
                <strong>{allSecurityFindings.length}</strong>
              </div>
              <div className="dashboard-ribbon-card">
                <span className="dashboard-ribbon-label">Visible Requests</span>
                <strong>{visibleExchanges.length}</strong>
              </div>
              <div className="dashboard-ribbon-card">
                <span className="dashboard-ribbon-label">Recent HAR Runs</span>
                <strong>{mergedHarHistory.length}</strong>
              </div>
            </div>
            {readOnlyDeployment ? (
              <div className="readonly-banner">
                배포 사이트는 조회 전용입니다. 캡처, Replay, HAR 업로드는 로컬 앱에서 실행하고
                이 화면에서는 DB에 저장된 이력을 확인합니다.
              </div>
            ) : null}

            {activeSection === "capture" ? (
              <div className="capture-control-panel">
                <form className="capture-form filter-bar" onSubmit={startCapture}>
                  <div className="capture-filter-row">
                    <label className="field-label field-card">
                      <span>URL:</span>
                      <input
                        type="text"
                        placeholder="도메인 입력"
                        value={domain}
                        onChange={(event) => setDomain(event.target.value)}
                      />
                    </label>
                    <label className="field-label field-card">
                      <span>Excluded:</span>
                      <input
                        type="text"
                        placeholder="추가 제외 패턴 입력"
                        value={excludeInput}
                        onChange={(event) => setExcludeInput(event.target.value)}
                      />
                    </label>
                  </div>
                  <div className="auth-fields">
                    <label className="field-label field-card">
                      <span>ID:</span>
                      <input
                        type="text"
                        autoComplete="username"
                        placeholder="로그인 ID 또는 이메일"
                        value={loginId}
                        onChange={(event) => setLoginId(event.target.value)}
                      />
                    </label>
                    <label className="field-label field-card">
                      <span>PW:</span>
                      <input
                        type="password"
                        autoComplete="current-password"
                        placeholder="비밀번호"
                        value={loginPassword}
                        onChange={(event) => setLoginPassword(event.target.value)}
                      />
                    </label>
                    <label className="field-label field-card session-field">
                      <span>Session:</span>
                      <input
                        type="password"
                        autoComplete="off"
                        placeholder="SESSIONID=... 또는 Cookie 문자열"
                        value={sessionValue}
                        onChange={(event) => setSessionValue(event.target.value)}
                      />
                    </label>
                  </div>
                  <p className="field-hint">
                    이미지 요청은 항상 제외됩니다. ID/PW 또는 Session 중 하나를 입력하면 인증된 상태로 스캔합니다.
                  </p>
                  <div className="action-row action-card">
                    <button type="submit" disabled={submitting || active}>
                      {submitting ? "처리 중..." : "캡처 시작"}
                    </button>
                    <button type="button" disabled={submitting || !active} onClick={stopCapture}>
                      캡처 중지
                    </button>
                    <button
                      type="button"
                      disabled={visibleExchanges.length === 0}
                      onClick={generateCaptureMermaid}
                    >
                      Generate Mermaid
                    </button>
                    <details className="export-menu">
                      <summary className={visibleExchanges.length === 0 ? "disabled-summary" : ""}>
                        Export
                      </summary>
                      <div className="export-menu-list">
                        <button
                          type="button"
                          disabled={visibleExchanges.length === 0}
                          onClick={downloadHtmlReport}
                        >
                          HTML 출력
                        </button>
                        <button
                          type="button"
                          disabled={visibleExchanges.length === 0}
                          onClick={downloadPdfReport}
                        >
                          PDF 출력
                        </button>
                        <button
                          type="button"
                          disabled={visibleExchanges.length === 0}
                          onClick={downloadJsonReport}
                        >
                          JSON 출력
                        </button>
                        <button
                          type="button"
                          disabled={visibleExchanges.length === 0}
                          onClick={downloadMarkdownReport}
                        >
                          MD 출력
                        </button>
                        <button
                          type="button"
                          disabled={visibleExchanges.length === 0}
                          onClick={downloadCsvReport}
                        >
                          CSV 출력
                        </button>
                      </div>
                    </details>
                    <button
                      type="button"
                      disabled={suppressedFindings.length + sessionSuppressedFindings.length === 0}
                      onClick={clearSuppressedFindings}
                    >
                      오탐 초기화
                    </button>
                  </div>
                </form>
              </div>
            ) : activeSection === "overview" ||
              activeSection === "findings" ||
              activeSection === "har" ||
              activeSection === "recent" ? null : (
              <div className={`section-intro ${activeSection === "findings" ? "findings-intro" : ""}`}>
                <h2 className="section-title">
                  {navigationItems.find((item) => item.key === activeSection)?.label || "Overview"}
                </h2>
                <p className="section-copy">
                  {navigationItems.find((item) => item.key === activeSection)?.description ||
                    "필요한 보안/캡처 기능을 선택해 보세요."}
                </p>
              </div>
            )}

            {statusMessage ? <p className="status">{statusMessage}</p> : null}
            {visibleErrors.length > 0 ? (
              <div className="error-strip">{visibleErrors[visibleErrors.length - 1]?.errorText}</div>
            ) : null}
          </section>

          {activeSection === "overview" ? (
            <section className="pair-list">
              <article className="panel stacked-panel">
                {criticalAlerts.length > 0 ? (
                  <div className="alert-banner critical-banner">
                    Critical findings {criticalAlerts.length}건이 감지되었습니다. 우선 `URL 민감정보`,
                    `응답 본문 비밀값`, `위험한 CORS`를 먼저 확인하는 것을 권장합니다.
                  </div>
                ) : null}
                {criticalAlerts.length === 0 && highAlerts.length > 0 ? (
                  <div className="alert-banner high-banner">
                    High findings {highAlerts.length}건이 감지되었습니다. 엔드포인트 우선순위와 재현
                    체크리스트를 따라 순서대로 검증해보면 됩니다.
                  </div>
                ) : null}
                {owaspSummary.length > 0 ? (
                  <div className="owasp-overview">
                    <strong>OWASP Top 10 Summary</strong>
                    <div className="owasp-overview-chips">
                      {owaspSummary.map((item) => (
                        <span key={item.key} className="owasp-chip">
                          {item.label} ({item.count})
                        </span>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="empty-state-card">아직 탐지된 보안 finding이 없습니다.</div>
                )}
                {endpointSummary.length > 0 ? (
                  <div className="endpoint-overview" open="open">
                    <strong>Endpoint Priority</strong>
                    <div className="endpoint-overview-list">
                      {endpointSummary.slice(0, 12).map((item) => (
                        <div
                          key={item.endpoint}
                          className={`endpoint-card severity-${item.highestSeverity}`}
                        >
                          <span className="endpoint-title">{item.endpoint}</span>
                          <span>Score: {item.score}</span>
                          <span>Findings: {item.findings}</span>
                          <span>Highest: {item.highestSeverityLabel}</span>
                          <span>{item.topCategories.join(", ") || "No categories"}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </article>
            </section>
          ) : null}

          {activeSection === "har" ? (
            <section className="pair-list">
              <article className="panel stacked-panel">
                <div className="har-panel section-panel">
                  <strong>HAR Upload</strong>
                  <div className="har-upload-row">
                    <div className="har-upload-inline">
                      <input
                        type="file"
                        accept=".har,application/json"
                        onChange={(event) => setHarFile(event.target.files?.[0] || null)}
                      />
                      <button
                        type="button"
                        onClick={uploadHarFile}
                        disabled={harUploading || !harFile}
                      >
                        {harUploading ? "업로드 중..." : "HAR 분석 업로드"}
                      </button>
                    </div>
                  </div>
                  {harUploadError ? <div className="error-strip">{harUploadError}</div> : null}
                  {harUploadResult ? (
                    <div className="har-latest-row">
                      <strong>방금 업로드한 결과</strong>
                      <div className="har-result-card">
                        <strong>{harUploadResult.fileName}</strong>
                        <span>
                          저장 상태:{" "}
                          {harUploadResult.storage?.saved
                            ? "Supabase 저장 완료"
                            : harUploadResult.storage?.reason || "로컬 분석 결과"}
                        </span>
                        <span>총 요청: {harUploadResult.summary?.totalEntries ?? 0}</span>
                        <span>평균 대기(ms): {harUploadResult.summary?.averageWaitMs ?? 0}</span>
                        <span>
                          가장 느린 URL: {harUploadResult.summary?.slowestEntry?.url || "-"}
                        </span>
                      </div>
                    </div>
                  ) : null}
                  <div className="har-panel-grid">
                    <div className="har-upload-box">
                      <strong>HAR 분석 이력</strong>
                      <div className="har-history-list">
                        {normalizedHarHistory.length === 0 ? (
                          <span className="empty-copy">
                            {recentLoading ? "불러오는 중..." : "최근 HAR 분석 결과가 없습니다."}
                          </span>
                        ) : (
                          normalizedHarHistory.map((item) => (
                            <button
                              key={item.historyKey}
                              type="button"
                              className={`har-history-row ${
                                selectedHarHistoryKey === item.historyKey ? "active" : ""
                              }`}
                              onClick={() => setSelectedHarHistoryKey(item.historyKey)}
                            >
                              <span className="har-history-name">{item.displayFileName}</span>
                              <span className="har-history-meta">
                                {item.historySource === "local" ? "로컬" : "DB"} ·{" "}
                                {formatDateTime(item.displayCreatedAt)} · 요청 {item.summary?.totalEntries ?? 0}건
                              </span>
                            </button>
                          ))
                        )}
                      </div>
                    </div>
                    <div className="har-upload-box">
                      <strong>분석 결과</strong>
                      {selectedHarHistory ? (
                        <div className="har-result-card">
                          <strong>{selectedHarHistory.displayFileName}</strong>
                          <span>
                            저장 상태:{" "}
                            {selectedHarHistory.historySource === "db"
                              ? "Supabase 저장 완료"
                              : harUploadResult?.storage?.saved
                              ? "Supabase 저장 완료"
                              : harUploadResult?.storage?.reason || "로컬 분석 결과"}
                          </span>
                          <span>총 요청: {selectedHarHistory.summary?.totalEntries ?? 0}</span>
                          <span>평균 대기(ms): {selectedHarHistory.summary?.averageWaitMs ?? 0}</span>
                          <span>
                            가장 느린 URL: {selectedHarHistory.summary?.slowestEntry?.url || "-"}
                          </span>
                        </div>
                      ) : (
                        <span className="empty-copy">HAR 파일을 업로드하면 여기에서 분석 결과를 보여줍니다.</span>
                      )}
                    </div>
                  </div>
                </div>
              </article>
            </section>
          ) : null}

          {activeSection === "recent" ? (
            <section className="pair-list">
              <article className="panel stacked-panel">
                <div className="stats-dashboard">
                  {periodStats.map((item) => (
                    <div key={item.key} className="stats-card">
                      <strong>{item.label}</strong>
                      <span>점검 {item.runCount}회</span>
                      <span>요청 {item.totalExchanges}건</span>
                      <span>Finding {item.totalFindings}건</span>
                      <span>Critical {item.criticalFindings} / High {item.highFindings}</span>
                    </div>
                  ))}
                </div>
                <div className="recent-capture-panel section-panel">
                  <strong>Recent Inspection Runs</strong>
                  <div className="recent-list">
                    {mergedInspectionRuns.length === 0 ? (
                      <span className="empty-copy">
                        {recentLoading ? "불러오는 중..." : "최근 점검 이력이 없습니다."}
                      </span>
                    ) : (
                      mergedInspectionRuns.map((item) => (
                        <div key={item.id} className="recent-card">
                          <strong>{item.target_url || "-"}</strong>
                          <span>
                            출처:{" "}
                            {item.historySource === "local"
                              ? item.pending_sync
                                ? "로컬(대기)"
                                : "로컬"
                              : "DB"}
                          </span>
                          <span>
                            점검 시간: {formatDateTime(item.started_at)} ~ {formatDateTime(item.ended_at)}
                          </span>
                          <span>세션: {item.capture_session_id || "-"}</span>
                          <span>
                            요청 {item.total_exchanges}건 / 에러 {item.total_errors}건 / Finding{" "}
                            {item.total_findings}건
                          </span>
                          <span>
                            Critical {item.critical_findings} / High {item.high_findings}
                          </span>
                          <div className="action-row">
                            <button type="button" onClick={() => openInspectionRun(item)}>
                              상세 보기
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                downloadHtmlReport(
                                  item.report_snapshot && Object.keys(item.report_snapshot).length > 0
                                    ? item.report_snapshot
                                    : {
                                        domain: item.target_url,
                                        excluded: item.excluded_patterns || [],
                                        securityOnly: item.security_only,
                                        maskSensitive: item.mask_sensitive,
                                        inspector: authUser?.email || "-",
                                        exportedAt: item.ended_at || item.created_at,
                                        conclusion: buildInspectionConclusion({
                                          totalFindings: item.total_findings,
                                          criticalFindings: item.critical_findings,
                                          highFindings: item.high_findings,
                                          totalErrors: item.total_errors
                                        }),
                                        owaspSummary: item.owasp_summary || [],
                                        endpointSummary: item.endpoint_summary || [],
                                        exchanges: []
                                      }
                                )
                              }
                            >
                              HTML 재다운로드
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                downloadPdfReport(
                                  item.report_snapshot && Object.keys(item.report_snapshot).length > 0
                                    ? item.report_snapshot
                                    : {
                                        domain: item.target_url,
                                        excluded: item.excluded_patterns || [],
                                        securityOnly: item.security_only,
                                        maskSensitive: item.mask_sensitive,
                                        inspector: authUser?.email || "-",
                                        exportedAt: item.ended_at || item.created_at,
                                        conclusion: buildInspectionConclusion({
                                          totalFindings: item.total_findings,
                                          criticalFindings: item.critical_findings,
                                          highFindings: item.high_findings,
                                          totalErrors: item.total_errors
                                        }),
                                        owaspSummary: item.owasp_summary || [],
                                        endpointSummary: item.endpoint_summary || [],
                                        exchanges: []
                                      }
                                )
                              }
                            >
                              PDF 재다운로드
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                  <strong>Recent Capture Events</strong>
                  <div className="recent-list">
                    {mergedCaptureEvents.length === 0 ? (
                      <span className="empty-copy">
                        {recentLoading ? "불러오는 중..." : "최근 캡처 이벤트가 없습니다."}
                      </span>
                    ) : (
                      mergedCaptureEvents.map((item) => (
                        <div key={item.id} className="recent-card">
                          <strong>
                            {item.request_method || "?"}{" "}
                            {item.request_url || item.target_url || "-"}
                          </strong>
                          <span>
                            출처:{" "}
                            {item.historySource === "local"
                              ? item.pending_sync
                                ? "로컬(대기)"
                                : "로컬"
                              : "DB"}
                          </span>
                          <span>{formatDateTime(item.created_at)}</span>
                          <span>세션: {item.capture_session_id || "-"}</span>
                          <span>상태: {item.response_status || item.error_text || "-"}</span>
                          <span>타입: {item.request_resource_type || "-"}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </article>
            </section>
          ) : null}

          {activeSection === "findings" ? (
            <section className="pair-list">
              <article className="panel stacked-panel">
                <div className="entry-list findings-list">
                  {displayedFindingEntries.length === 0 ? (
                    <div className="empty-state-card">
                      현재 조건에서 보여줄 보안 finding이 없습니다.
                    </div>
                  ) : (
                    displayedFindingEntries.map(({ exchange, finding }, index) => (
                      <article
                        key={`${exchange.id}-${finding.key}-${index}`}
                        className={`finding-focus-card ${
                          exchange.id === focusedFindingExchangeId ? "finding-focus-card-active" : ""
                        }`}
                        data-finding-exchange-id={exchange.id}
                      >
                        <div className="finding-focus-head">
                          <div>
                            <strong>{finding.title}</strong>
                            <span>
                              {exchange.request?.method || "?"} {exchange.endpointKey}
                            </span>
                          </div>
                          <span className={`severity-chip severity-chip-${finding.severity}`}>
                            {finding.severityLabel}
                          </span>
                        </div>
                        <div className="security-reason-list">
                          <div className={`security-reason-item severity-${finding.severity}`}>
                            <span className="security-reason-owasp">OWASP: {finding.owaspLabel}</span>
                            <span className="security-reason-area">Area: {finding.area}</span>
                            <span className="security-reason-description">
                              Evidence: {maybeMask(finding.evidence, maskSensitive)}
                            </span>
                            <span className="security-reason-guide">Guide: {finding.guide}</span>
                            <span className="security-reason-remediation">
                              Remediation: {finding.remediation}
                            </span>
                            <span className="security-reason-confidence">
                              Confidence: {finding.confidenceLabel}
                            </span>
                            <details className="security-poc">
                              <summary>PoC Template</summary>
                              <pre>{maybeMask(generateFindingPoc(finding, exchange), maskSensitive)}</pre>
                            </details>
                            <div className="security-reason-checklist">
                              <strong>Reproduction Checklist</strong>
                              <ul>
                                {finding.checklist.map((item) => (
                                  <li key={item}>{item}</li>
                                ))}
                              </ul>
                            </div>
                            <div className="finding-actions">
                              <button type="button" onClick={() => injectPocIntoReplay(finding, exchange)}>
                                PoC를 Replay에 주입
                              </button>
                              <button
                                type="button"
                                onClick={() => suppressFindingByScope("session", finding, exchange)}
                              >
                                세션 오탐
                              </button>
                              <button
                                type="button"
                                onClick={() => suppressFindingByScope("endpoint", finding, exchange)}
                              >
                                엔드포인트 오탐
                              </button>
                              <button
                                type="button"
                                onClick={() => suppressFindingByScope("host", finding, exchange)}
                              >
                                호스트 오탐
                              </button>
                              <button
                                type="button"
                                onClick={() => suppressFindingByScope("global", finding, exchange)}
                              >
                                전역 오탐
                              </button>
                            </div>
                          </div>
                        </div>
                      </article>
                    ))
                  )}
                </div>
              </article>
            </section>
          ) : null}

          {activeSection === "capture" ? (
            <section className="pair-list">
              <article className="panel">
                <div className="entry-list">
                  {visibleExchanges.length === 0 ? (
                    <div className="empty-state-card">
                      아직 캡처된 요청이 없습니다. URL을 입력하고 캡처를 시작해보세요.
                    </div>
                  ) : (
                    visibleExchanges
                      .slice()
                      .reverse()
                      .map((exchange) => {
                        const securityFindings = exchange.securityFindings || [];

                        return (
                          <article key={exchange.id} className="exchange-card">
                            {securityFindings.length > 0 ? (
                              <div className="security-summary-bar">
                                <div className="security-summary-copy">
                                  <strong>Security Findings {securityFindings.length}건</strong>
                                  <span>
                                    Critical {securityFindings.filter((item) => item.severity === "critical").length}
                                    {" / "}High {securityFindings.filter((item) => item.severity === "high").length}
                                    {" / "}Medium {securityFindings.filter((item) => item.severity === "medium").length}
                                  </span>
                                </div>
                                <div className="security-summary-actions">
                                  {["critical", "high", "medium", "low"]
                                    .filter((severity) =>
                                      securityFindings.some((item) => item.severity === severity)
                                    )
                                    .map((severity) => (
                                      <span key={severity} className={`severity-chip severity-chip-${severity}`}>
                                        {SEVERITY_LABELS[severity]}
                                      </span>
                                    ))}
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setFocusedFindingExchangeId(exchange.id);
                                      setActiveSection("findings");
                                    }}
                                  >
                                    Findings에서 보기
                                  </button>
                                </div>
                              </div>
                            ) : null}
                  <button
                    type="button"
                    className="exchange-column interactive-column"
                    onClick={() => openReplayModal(exchange)}
                  >
                    <div className="entry-title-row">
                      <span className="panel-chip request-chip">REQUEST</span>
                      <strong>{exchange.request?.method || "(request unavailable)"}</strong>
                      {exchange.request?.url ? (
                        <span className="url-line">{maybeMask(exchange.request.url, maskSensitive)}</span>
                      ) : null}
                      <span>
                        {exchange.request
                          ? `${exchange.request.resourceType} · ${exchange.timestamp}`
                          : exchange.timestamp}
                      </span>
                    </div>
                    <CodeBlock
                      sections={[
                        { label: "Headers", content: prettyJson(exchange.request?.headers) },
                        { label: "Body", content: exchange.request?.postData || "(empty)" }
                      ]}
                      maskSensitive={maskSensitive}
                    />
                  </button>

                  <div className="exchange-column">
                    <div className="entry-title-row">
                      <span className="panel-chip response-chip">RESPONSE</span>
                      <strong>
                        {exchange.response ? String(exchange.response.status) : "(pending response)"}
                      </strong>
                      {exchange.response?.url ? (
                        <span className="url-line">{maybeMask(exchange.response.url, maskSensitive)}</span>
                      ) : null}
                      <span>
                        {exchange.response
                          ? `${exchange.response.statusText} · ${exchange.response.timestamp}`
                          : ""}
                      </span>
                    </div>
                    <CodeBlock
                      sections={[
                        { label: "Headers", content: prettyJson(exchange.response?.headers) },
                        {
                          label: "BodyPreview",
                          content: exchange.response?.bodyPreview || "(binary, empty, or pending)"
                        }
                      ]}
                      maskSensitive={maskSensitive}
                    />
                    {exchange.diffSummary ? (
                      <details className="diff-summary">
                        <summary>Diff vs Previous Same Endpoint</summary>
                        <span>{exchange.diffSummary.summary}</span>
                        <div className="diff-before-after-grid">
                          <div className="diff-panel">
                            <strong>Before</strong>
                            <span>Status: {exchange.diffSummary.statusBefore || "-"}</span>
                            {exchange.diffSummary.requestHeaderDiffs.length > 0 ? (
                              <div className="diff-section">
                                <span>Request headers</span>
                                <pre>{maybeMask(prettyJson(exchange.diffSummary.requestHeaderDiffs.map((item) => ({
                                  key: item.key,
                                  value: item.before
                                }))), maskSensitive)}</pre>
                              </div>
                            ) : null}
                            <div className="diff-section">
                              <span>Request body</span>
                              <pre>{maybeMask(exchange.diffSummary.requestBodyBefore || "(empty)", maskSensitive)}</pre>
                            </div>
                            {exchange.diffSummary.responseHeaderDiffs.length > 0 ? (
                              <div className="diff-section">
                                <span>Response headers</span>
                                <pre>{maybeMask(prettyJson(exchange.diffSummary.responseHeaderDiffs.map((item) => ({
                                  key: item.key,
                                  value: item.before
                                }))), maskSensitive)}</pre>
                              </div>
                            ) : null}
                            <div className="diff-section">
                              <span>Response body</span>
                              <pre>{maybeMask(exchange.diffSummary.responseBodyBefore || "(empty)", maskSensitive)}</pre>
                            </div>
                          </div>
                          <div className="diff-panel">
                            <strong>After</strong>
                            <span>Status: {exchange.diffSummary.statusAfter || "-"}</span>
                            {exchange.diffSummary.requestHeaderDiffs.length > 0 ? (
                              <div className="diff-section">
                                <span>Request headers</span>
                                <pre>{maybeMask(prettyJson(exchange.diffSummary.requestHeaderDiffs.map((item) => ({
                                  key: item.key,
                                  value: item.after
                                }))), maskSensitive)}</pre>
                              </div>
                            ) : null}
                            <div className="diff-section">
                              <span>Request body</span>
                              <pre>{maybeMask(exchange.diffSummary.requestBodyAfter || "(empty)", maskSensitive)}</pre>
                            </div>
                            {exchange.diffSummary.responseHeaderDiffs.length > 0 ? (
                              <div className="diff-section">
                                <span>Response headers</span>
                                <pre>{maybeMask(prettyJson(exchange.diffSummary.responseHeaderDiffs.map((item) => ({
                                  key: item.key,
                                  value: item.after
                                }))), maskSensitive)}</pre>
                              </div>
                            ) : null}
                            <div className="diff-section">
                              <span>Response body</span>
                              <pre>{maybeMask(exchange.diffSummary.responseBodyAfter || "(empty)", maskSensitive)}</pre>
                            </div>
                          </div>
                        </div>
                      </details>
                    ) : null}
                  </div>
                          </article>
                        );
                      })
                  )}
                </div>
              </article>
            </section>
          ) : null}
        </div>
      </div>

      <ReplayModal
        modalState={modalState}
        setModalState={setModalState}
        replayResponse={replayResponse}
        replayLoading={replayLoading}
        replayError={replayError}
        onReplay={replayRequest}
        maskSensitive={maskSensitive}
      />
      <InspectionRunModal
        run={inspectionModalRun}
        onClose={() => setInspectionModalRun(null)}
        onDownloadHtml={downloadHtmlReport}
        onDownloadPdf={downloadPdfReport}
      />
      <MermaidModal
        code={captureMermaidModal}
        onClose={() => setCaptureMermaidModal("")}
        onCopy={copyCaptureMermaid}
      />
    </main>
  );
}
