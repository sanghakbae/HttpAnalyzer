import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:4000";
const GOOGLE_CLIENT_ID =
  "924920443826-k59m97pgabmdb42qv9cq63plmuuvvn7s.apps.googleusercontent.com";
const AUTH_STORAGE_KEY = "http-analyzer-auth-user";
const ALLOWED_GOOGLE_EMAIL = "totoriverce@gmail.com";
const LOCAL_HAR_HISTORY_KEY = "http-analyzer-local-har-history";
const LOCAL_INSPECTION_RUNS_KEY = "http-analyzer-local-inspection-runs";
const LOCAL_CAPTURE_EVENTS_KEY = "http-analyzer-local-capture-events";
const LOCAL_LIVE_CAPTURE_KEY = "http-analyzer-live-capture";
const LOCAL_AI_SUMMARIES_KEY = "http-analyzer-local-ai-summaries";
const OPENAI_SETTINGS_KEY = "http-analyzer-openai-settings";
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
const SQL_ERROR_DISCLOSURE_REGEX =
  /(sql syntax.*mysql|you have an error in your sql syntax|warning.*mysql_|mysql_fetch_|unknown column .* in 'field list'|unclosed quotation mark after the character string|quoted string not properly terminated|syntax error at or near|org\.postgresql\.util\.PSQLException|pg_query\(|sqlstate\[[^\]]+\]|sqlite(?:_|\/|\.)|SQLite.Exception|ODBC SQL Server Driver|OLE DB Provider for SQL Server|ORA-\d{5})/i;
const XSS_REGEX =
  /<script\b|javascript:|onerror\s*=|onload\s*=|<img[^>]+src=|<svg[^>]+onload=|document\.cookie|alert\s*\(/i;
const JS_SECRET_LITERAL_REGEX =
  /\b(?:apiKey|api_key|clientSecret|client_secret|accessToken|access_token|refreshToken|refresh_token|idToken|id_token|jwt|secret|authorization|bearer|password|passwd)\b\s*[:=]\s*["'`][^"'`]{8,}|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}/i;
const JS_DANGEROUS_SINK_REGEX =
  /\b(?:eval|Function)\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*["'`]|document\.write\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML/i;
const JS_DOM_XSS_FLOW_REGEX =
  /(?:location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)|window\.name)[\s\S]{0,320}(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval|Function)/i;
const JS_POSTMESSAGE_WILDCARD_REGEX = /\.postMessage\s*\([^,]+,\s*["'`]\*["'`]/i;
const JS_SOURCE_MAP_REGEX = /(?:\/\/|\/\*)#\s*sourceMappingURL=|\.map(?:[?#]|$)/i;
const JS_DEBUG_ARTIFACT_REGEX = /\bdebugger\s*;|console\.(?:log|debug|trace)\s*\(/i;
const PATH_TRAVERSAL_REGEX = /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%252e%252e%252f)/i;
const COMMAND_INJECTION_REGEX = /(?:;|\|\||&&|\|)\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|powershell|cmd)\b/i;
const OPEN_REDIRECT_REGEX =
  /(?:[?&](?:next|url|target|dest|destination|redirect|return|returnUrl|continue)=https?:\/\/)[^&]+/i;
const SSRF_REGEX =
  /(?:[?&](?:url|uri|path|target|dest|destination|endpoint)=https?:\/\/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.169\.254)/i;
const DEFAULT_OPENAI_SUMMARY_PROMPT = `다음 HTTP 캡처 결과를 한국어로 분석해줘.

목표:
1. 전체 요약을 5줄 이내로 작성
2. 보안상 우선 확인해야 할 엔드포인트를 위험도 순으로 정리
3. SQL Injection, XSS, 인증/세션, CORS, 민감정보 노출 관점의 근거를 분리
4. 실제 캡처 데이터에서 확인되는 증거만 사용하고 추측은 "추가 확인 필요"로 표시
5. SQLMap으로 점검할 후보 URL과 파라미터를 제안
6. 개발자가 바로 수행할 다음 조치 체크리스트를 작성`;
const CHUNK_RELOAD_STORAGE_KEY = "http-analyzer-chunk-reload-attempted";
const HISTORY_PAGE_SIZE = 1000;
const HISTORY_MAX_ROWS = 5000;

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
  if (!API_BASE_URL) {
    return {
      harAnalyses: [],
      captureEvents: [],
      inspectionRuns: []
    };
  }

  const response = await fetch(`${API_BASE_URL}/api/recent-analyses`);
  if (!response.ok) {
    return {
      harAnalyses: [],
      captureEvents: [],
      inspectionRuns: []
    };
  }

  return response.json();
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
    case "checklist":
      return (
        <svg {...commonProps}>
          <path d="M9 6h11" />
          <path d="M9 12h11" />
          <path d="M9 18h11" />
          <path d="m4 6 1.2 1.2L7.5 4.9" />
          <path d="m4 12 1.2 1.2 2.3-2.3" />
          <path d="m4 18 1.2 1.2 2.3-2.3" />
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
    case "sqlmap":
      return (
        <svg {...commonProps}>
          <path d="M4 5h16" />
          <path d="M7 5v14" />
          <path d="M17 5v14" />
          <path d="M4 19h16" />
          <path d="M9 10h6" />
          <path d="M9 14h6" />
        </svg>
      );
    case "api":
      return (
        <svg {...commonProps}>
          <path d="M4 7h16" />
          <path d="M4 12h16" />
          <path d="M4 17h16" />
          <path d="M8 7v10" />
          <path d="M16 7v10" />
        </svg>
      );
    case "settings":
      return (
        <svg {...commonProps}>
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.8 1.8 0 0 0 .36 2l.04.04a2 2 0 0 1-2.83 2.83l-.04-.04a1.8 1.8 0 0 0-2-.36 1.8 1.8 0 0 0-1.1 1.66V21a2 2 0 0 1-4 0v-.06A1.8 1.8 0 0 0 8.7 19.3a1.8 1.8 0 0 0-2 .36l-.04.04a2 2 0 0 1-2.83-2.83l.04-.04a1.8 1.8 0 0 0 .36-2 1.8 1.8 0 0 0-1.66-1.1H2.5a2 2 0 0 1 0-4h.06A1.8 1.8 0 0 0 4.2 8.7a1.8 1.8 0 0 0-.36-2l-.04-.04a2 2 0 0 1 2.83-2.83l.04.04a1.8 1.8 0 0 0 2 .36h.01A1.8 1.8 0 0 0 9.8 2.6V2.5a2 2 0 0 1 4 0v.06a1.8 1.8 0 0 0 1.1 1.66 1.8 1.8 0 0 0 2-.36l.04-.04a2 2 0 0 1 2.83 2.83l-.04.04a1.8 1.8 0 0 0-.36 2 1.8 1.8 0 0 0 1.66 1.1h.06a2 2 0 0 1 0 4h-.06A1.8 1.8 0 0 0 19.4 15Z" />
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

function isDynamicImportError(reason) {
  const message = String(reason?.message || reason || "");
  return (
    message.includes("Failed to fetch dynamically imported module") ||
    message.includes("Importing a module script failed") ||
    message.includes("error loading dynamically imported module")
  );
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

function isSameTargetHostExchange(exchange, targetHost) {
  if (!targetHost) {
    return true;
  }

  const requestHost = getHostFromUrl(exchange.request?.url || "");
  const responseHost = getHostFromUrl(exchange.response?.url || "");
  return requestHost === targetHost || responseHost === targetHost;
}

function extractSqlmapCandidateParams(exchange) {
  const params = [];
  const seen = new Set();
  const requestUrl = exchange?.request?.url || exchange?.response?.url || "";
  const body = exchange?.request?.postData || "";

  function addParam(source, name) {
    const normalizedName = String(name || "").trim();
    if (!normalizedName) {
      return;
    }

    const key = `${source}:${normalizedName}`;
    if (seen.has(key)) {
      return;
    }

    seen.add(key);
    params.push({ source, name: normalizedName });
  }

  try {
    const parsedUrl = new URL(requestUrl);
    parsedUrl.searchParams.forEach((_value, key) => addParam("query", key));
    parsedUrl.pathname
      .split("/")
      .filter(Boolean)
      .forEach((segment, index) => {
        if (/^\d+$/.test(segment) || /^[0-9a-f-]{8,}$/i.test(segment)) {
          addParam("path", `segment${index + 1}`);
        }
      });
  } catch {
    const query = requestUrl.split("?")[1] || "";
    new URLSearchParams(query).forEach((_value, key) => addParam("query", key));
  }

  if (body) {
    try {
      const parsedBody = JSON.parse(body);
      if (parsedBody && typeof parsedBody === "object" && !Array.isArray(parsedBody)) {
        Object.keys(parsedBody).forEach((key) => addParam("json", key));
      }
    } catch {
      new URLSearchParams(body).forEach((_value, key) => addParam("body", key));
    }
  }

  return params;
}

function isSqlmapRelevantFinding(finding) {
  return ["sqli-pattern", "sqli-review-candidate", "sqli-error-disclosure"].includes(finding?.key);
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

function isApiLikeExchange(exchange) {
  if (isImageLikeExchange(exchange)) {
    return false;
  }

  const resourceType = String(exchange.request?.resourceType || "").toLowerCase();
  const requestUrl = String(exchange.request?.url || exchange.response?.url || "").toLowerCase();
  const requestBody = exchange.request?.postData || "";
  const contentType = String(
    exchange.response?.headers?.["content-type"] ||
      exchange.request?.headers?.["content-type"] ||
      ""
  ).toLowerCase();

  return (
    ["fetch", "xhr", "websocket", "eventsource"].includes(resourceType) ||
    contentType.includes("application/json") ||
    contentType.includes("application/graphql") ||
    requestUrl.includes("/api/") ||
    requestUrl.includes("/graphql") ||
    requestUrl.includes("api.") ||
    Boolean(requestBody)
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
  const sourceRun = exchange.sourceRunId || "";
  return `${sourceRun}::${normalizeEndpoint(exchange.request?.url || exchange.response?.url)}::${finding.key}`;
}

function normalizeStoredFinding(finding) {
  if (!finding?.key) {
    return null;
  }

  const severity = finding.severity || "low";
  const owasp = finding.owasp || "Unmapped";
  const confidence = finding.confidence || "medium";

  return {
    ...finding,
    severity,
    severityLabel: finding.severityLabel || SEVERITY_LABELS[severity] || severity,
    owasp,
    owaspLabel: finding.owaspLabel || OWASP_LABELS[owasp] || owasp,
    confidence,
    confidenceLabel: finding.confidenceLabel || getConfidenceLabel(confidence),
    checklist: Array.isArray(finding.checklist) ? finding.checklist : []
  };
}

function mergeSecurityFindings(storedFindings, detectedFindings, exchange) {
  const merged = [];
  const seen = new Set();

  for (const finding of [...(storedFindings || []), ...(detectedFindings || [])]) {
    const normalized = normalizeStoredFinding(finding);
    if (!normalized) {
      continue;
    }

    const signature = buildFindingSignature(normalized, exchange);
    if (seen.has(signature)) {
      continue;
    }

    seen.add(signature);
    merged.push(normalized);
  }

  return merged;
}

function getHostFromUrl(input) {
  if (!input) {
    return "";
  }

  try {
    return new URL(input).host;
  } catch {
    try {
      return new URL(`https://${input}`).host;
    } catch {
      return "";
    }
  }
}

function getRunDomainKey(run) {
  const targetUrl = run?.target_url || run?.report_snapshot?.domain || "";
  const host = getHostFromUrl(targetUrl);
  return (host || targetUrl || "unknown").replace(/^www\./i, "");
}

function getRunTimeValue(run) {
  const time = new Date(run?.ended_at || run?.created_at || run?.started_at || 0).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function getRunFindingStats(run) {
  const exchanges = Array.isArray(run?.report_snapshot?.exchanges)
    ? run.report_snapshot.exchanges
    : [];

  if (exchanges.length === 0) {
    return {
      total: Number(run?.total_findings || 0),
      critical: Number(run?.critical_findings || 0),
      high: Number(run?.high_findings || 0)
    };
  }

  const findings = exchanges.flatMap((exchange) =>
    mergeSecurityFindings(exchange.securityFindings, analyzeSecurityFindings(exchange), exchange)
  );

  return {
    total: findings.length,
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length
  };
}

function buildRunAggregateExchanges(run, domainKey, runIndex) {
  const exchanges = Array.isArray(run?.report_snapshot?.exchanges) ? run.report_snapshot.exchanges : [];

  return exchanges.map((exchange, exchangeIndex) => {
    const exchangeWithSource = {
      ...exchange,
      id: `domain-history-${domainKey || getRunDomainKey(run)}-${runIndex}-${exchange.id || exchangeIndex}`,
      endpointKey: exchange.endpointKey || exchange.endpoint || normalizeEndpoint(exchange.request?.url || exchange.response?.url),
      sourceRunId: run.id || run.capture_session_id || "",
      sourceRunEndedAt: run.ended_at || run.created_at || ""
    };

    return {
      ...exchangeWithSource,
      securityFindings: mergeSecurityFindings(
        exchange.securityFindings,
        analyzeSecurityFindings(exchangeWithSource),
        exchangeWithSource
      )
    };
  });
}

function buildDomainHistoryRuns(runs) {
  const grouped = new Map();

  for (const run of runs) {
    const domainKey = getRunDomainKey(run);
    const findingStats = getRunFindingStats(run);
    const current = grouped.get(domainKey);
    const currentLatestTime = current ? getRunTimeValue(current) : 0;
    const nextTime = getRunTimeValue(run);
    const runWithComputedStats = {
      ...run,
      total_findings: findingStats.total,
      critical_findings: findingStats.critical,
      high_findings: findingStats.high
    };

    if (!current || nextTime >= currentLatestTime) {
      const runsForDomain = current ? [...(current.runs || []), runWithComputedStats] : [runWithComputedStats];
      const aggregateExchanges = runsForDomain.flatMap((historyRun, runIndex) =>
        buildRunAggregateExchanges(historyRun, domainKey, runIndex)
      );
      grouped.set(domainKey, {
        ...runWithComputedStats,
        report_snapshot: {
          ...(runWithComputedStats.report_snapshot || {}),
          exchanges: aggregateExchanges
        },
        domainKey,
        runs: runsForDomain.sort((a, b) => getRunTimeValue(b) - getRunTimeValue(a)),
        scanCount: (current?.scanCount || 0) + 1,
        aggregate_total_exchanges:
          Number(current?.aggregate_total_exchanges || 0) + Number(run.total_exchanges || 0),
        aggregate_total_findings:
          Number(current?.aggregate_total_findings || 0) + findingStats.total,
        aggregate_critical_findings:
          Number(current?.aggregate_critical_findings || 0) + findingStats.critical,
        aggregate_high_findings:
          Number(current?.aggregate_high_findings || 0) + findingStats.high
      });
      continue;
    }

    current.runs = [...(current.runs || []), runWithComputedStats].sort(
      (a, b) => getRunTimeValue(b) - getRunTimeValue(a)
    );
    current.report_snapshot = {
      ...(current.report_snapshot || {}),
      exchanges: current.runs.flatMap((historyRun, runIndex) =>
        buildRunAggregateExchanges(historyRun, domainKey, runIndex)
      )
    };
    current.scanCount += 1;
    current.aggregate_total_exchanges += Number(run.total_exchanges || 0);
    current.aggregate_total_findings += findingStats.total;
    current.aggregate_critical_findings += findingStats.critical;
    current.aggregate_high_findings += findingStats.high;
  }

  return [...grouped.values()].sort((a, b) => getRunTimeValue(b) - getRunTimeValue(a));
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
      domainCount: new Set(filtered.map((item) => getRunDomainKey(item))).size,
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

const FINDING_DISPLAY_META = {
  "sensitive-data-in-url": {
    title: "Sensitive Data in URL",
    summary: "Secrets or one-time tokens appear in request/response URLs and can leak through logs, browser history, or referrers.",
    remediation: "Move secrets out of query strings into headers or POST bodies, then mask or purge existing logs.",
    example: "Example: /callback?access_token=... or /reset?code=..."
  },
  "secret-exposed-in-response-body": {
    title: "Secret Exposed in Response Body",
    summary: "The response appears to contain a token, API key, private key, or other sensitive material.",
    remediation: "Return only required fields, rotate exposed credentials, and exclude secrets from serialization.",
    example: "Example: JWT/API key/private key block returned inside JSON, HTML, or JS."
  },
  "sensitive-request-payload": {
    title: "Sensitive Data in Request Payload",
    summary: "The request body carries credentials or secrets that may be captured by logs, tracing tools, or exception reports.",
    remediation: "Mask sensitive fields end-to-end and confirm the endpoint is HTTPS-only.",
    example: "Example: password=..., token=..., secret=... stored in request logging."
  },
  "basic-auth-observed": {
    title: "Basic Authentication Observed",
    summary: "Basic authentication was detected and may be exposed through logs, proxies, or replay if not tightly controlled.",
    remediation: "Prefer session or token-based auth. If Basic auth remains, enforce HTTPS and log masking.",
    example: "Example: Authorization: Basic dXNlcjpwYXNz"
  },
  "absolute-location-observed": {
    title: "Absolute Redirect Location Review",
    summary: "A full absolute URL was observed in the Location header and may become an open redirect if user-controlled.",
    remediation: "Allow only internal paths or explicit allowlisted external destinations.",
    example: "Example: Location: https://evil.example/phish"
  },
  "cors-wildcard-with-credentials": {
    title: "CORS Wildcard with Credentials",
    summary: "The server appears to allow any origin while also allowing credentialed requests, which is highly dangerous.",
    remediation: "Replace wildcard CORS with a strict allowlist and never combine '*' with credentialed responses.",
    example: "Example: ACAO:* with ACAC:true for authenticated API responses."
  },
  "cors-origin-reflection-review": {
    title: "Reflected Origin CORS Review",
    summary: "The response may be reflecting the request Origin value and should be validated against a strict allowlist.",
    remediation: "Use exact origin matching and test hostile origins, subdomains, ports, and scheme variations.",
    example: "Example: Request Origin is echoed back in Access-Control-Allow-Origin."
  },
  "missing-httponly-cookie": {
    title: "Session Cookie Missing HttpOnly",
    summary: "A session or auth cookie is missing the HttpOnly flag and may be stolen if XSS is present.",
    remediation: "Set HttpOnly on all session and auth cookies and verify proxy/framework rewrite behavior.",
    example: "Example: Set-Cookie: SESSIONID=... without HttpOnly"
  },
  "missing-secure-cookie": {
    title: "HTTPS Cookie Missing Secure",
    summary: "A cookie used over HTTPS is missing the Secure flag and may be sent over downgraded or unintended channels.",
    remediation: "Set Secure on all production auth cookies and verify forwarded-proto handling behind proxies.",
    example: "Example: Set-Cookie: SESSIONID=... without Secure"
  },
  "missing-samesite-cookie": {
    title: "Cookie Missing SameSite Policy",
    summary: "The cookie does not explicitly define SameSite and may rely on browser defaults or expose CSRF surface.",
    remediation: "Set SameSite=Lax or Strict by default, or None+Secure only when cross-site behavior is required.",
    example: "Example: Session cookie set with no SameSite attribute"
  },
  "samesite-none-without-secure-cookie": {
    title: "SameSite=None Without Secure",
    summary: "A cookie allows cross-site sending but is not marked Secure, which is invalid or unsafe in modern browsers.",
    remediation: "Pair SameSite=None with Secure, or reduce scope to Lax/Strict if cross-site use is unnecessary.",
    example: "Example: Set-Cookie: token=...; SameSite=None"
  },
  "missing-csp": {
    title: "Missing Content Security Policy",
    summary: "HTML content is being served without a CSP, reducing browser-side mitigation against script injection.",
    remediation: "Deploy a baseline CSP and tighten script execution with nonce/hash-based rules where possible.",
    example: "Example: HTML page renders without any Content-Security-Policy header."
  },
  "missing-clickjacking-protection": {
    title: "Missing Clickjacking Protection",
    summary: "No X-Frame-Options or frame-ancestors protection was observed for HTML content.",
    remediation: "Set X-Frame-Options and/or CSP frame-ancestors to restrict framing.",
    example: "Example: Sensitive UI can be embedded in an attacker-controlled iframe."
  },
  "missing-x-content-type-options": {
    title: "Missing X-Content-Type-Options",
    summary: "The response is missing nosniff protection, which can increase MIME confusion risk.",
    remediation: "Add X-Content-Type-Options: nosniff to application responses.",
    example: "Example: Browser may sniff an uploaded file as executable content."
  },
  "missing-hsts": {
    title: "Missing HSTS",
    summary: "HTTPS is used but HSTS was not observed, leaving room for downgrade or first-visit interception.",
    remediation: "Enable HSTS with a suitable max-age and includeSubDomains when appropriate.",
    example: "Example: First request can be intercepted before HTTPS becomes sticky."
  },
  "server-version-disclosure": {
    title: "Server Version Disclosure",
    summary: "Server or framework version details appear to be exposed in headers or responses.",
    remediation: "Suppress version banners and keep inventory internally rather than public-facing.",
    example: "Example: Server: nginx/1.x or X-Powered-By: Express"
  },
  "stack-trace-disclosure": {
    title: "Detailed Error / Stack Trace Disclosure",
    summary: "The response appears to expose stack traces, class names, file paths, or database/framework internals.",
    remediation: "Return generic production errors and route diagnostic details to protected logs only.",
    example: "Example: stack trace, ORM exception, SQL syntax error, or internal file path in response."
  },
  "5xx-observed": {
    title: "5xx Server Error Observed",
    summary: "A server-side error was observed and may indicate instability or an input handling weakness worth reproducing.",
    remediation: "Correlate with server logs, compare against expected inputs, and verify whether the failure is user-triggerable.",
    example: "Example: 500/502/503 responses on input-driven endpoints."
  },
  "directory-indexing": {
    title: "Directory Listing Exposed",
    summary: "Directory indexing may be enabled, exposing file names, backup artifacts, or internal assets.",
    remediation: "Disable directory listing and restrict file exposure to explicit routes only.",
    example: "Example: /uploads/ or /backup/ shows a browsable file list."
  },
  "js-secret-literal": {
    title: "JavaScript Secret / Token Exposure",
    summary: "A JavaScript asset appears to contain tokens, keys, or internal secret-like literals.",
    remediation: "Move secrets server-side, rotate exposed values, and scan built bundles before release.",
    example: "Example: API key, bearer token, or internal secret string inside a JS bundle."
  },
  "js-dom-xss-source-to-sink": {
    title: "DOM XSS Source-to-Sink Flow",
    summary: "A likely path exists from URL or document-controlled input into an executable HTML/JS sink.",
    remediation: "Replace unsafe sinks with safe DOM APIs and sanitize untrusted inputs context-appropriately.",
    example: "Example: location.hash/search -> innerHTML, document.write, eval"
  },
  "js-dangerous-sink-usage": {
    title: "Dangerous JavaScript Sink Usage",
    summary: "A risky sink such as eval, Function, innerHTML, or document.write appears in the client code.",
    remediation: "Eliminate dynamic code execution and gate HTML rendering through safe APIs or sanitizers.",
    example: "Example: eval(), new Function(), innerHTML=, document.write()"
  },
  "js-postmessage-wildcard-target": {
    title: "postMessage Wildcard Target",
    summary: "postMessage appears to use '*' as targetOrigin, which may expose data to unintended windows.",
    remediation: "Use exact target origins and validate origin/source on the receiving side.",
    example: "Example: window.postMessage(payload, '*')"
  },
  "js-source-map-exposure": {
    title: "Source Map Exposure",
    summary: "A source map URL or .map file appears to be exposed and may reveal internal source structure.",
    remediation: "Disable public source maps in production or restrict access to them.",
    example: "Example: app.js.map downloadable from the public site."
  },
  "js-debug-artifact": {
    title: "Debug Artifact in Production JavaScript",
    summary: "Debug statements or verbose logging remain in production-facing JavaScript.",
    remediation: "Strip debugger/console noise in production builds and avoid logging sensitive runtime data.",
    example: "Example: debugger; or verbose console logs in deployed bundles."
  },
  "missing-referrer-policy": {
    title: "Missing Referrer Policy",
    summary: "The response does not define Referrer-Policy and may leak URL data during outbound navigation.",
    remediation: "Use a strict referrer policy such as strict-origin-when-cross-origin or stronger.",
    example: "Example: Sensitive query parameters are sent to third parties via Referer."
  },
  "sensitive-response-cache-control": {
    title: "Sensitive Response Missing Cache Controls",
    summary: "A sensitive response may be cacheable when it should be marked private or no-store.",
    remediation: "Use Cache-Control: private, no-store for authenticated or personal responses.",
    example: "Example: Account/profile API response cached in browser or shared proxy."
  },
  "sqli-pattern": {
    title: "SQL Injection Pattern",
    summary: "Input resembling SQL injection payloads was observed in a request and should be verified for impact.",
    remediation: "Use parameterized queries everywhere and compare status/body/timing across malicious and benign inputs.",
    example: "Example: id=1' OR '1'='1, UNION SELECT NULL--, SLEEP(5)"
  },
  "sqli-error-disclosure": {
    title: "SQL Error Disclosure",
    summary: "Database or SQL error signatures appear in the response and may indicate injection reachability.",
    remediation: "Hide DB errors from clients, inspect query construction, and verify with targeted SQLMap tests.",
    example: "Example: MySQL, PostgreSQL, Oracle, SQLite error text exposed to the client."
  },
  "sqli-review-candidate": {
    title: "SQLMap Review Candidate",
    summary: "This endpoint has request parameters that make it a practical SQLMap candidate even without direct proof yet.",
    remediation: "Run SQLMap with the correct method, session context, and candidate parameters from this exchange.",
    example: "Example: query/body/json/path parameters on stateful API endpoints."
  },
  "xss-pattern": {
    title: "XSS Payload or Reflection Pattern",
    summary: "Input or response content suggests possible reflected/stored XSS behavior.",
    remediation: "Apply context-aware output encoding, safe rendering patterns, sanitization, and CSP hardening.",
    example: "Example: <script>alert(1)</script>, \"><img src=x onerror=alert(1)>"
  },
  "path-traversal-pattern": {
    title: "Path Traversal Pattern",
    summary: "The request contains traversal syntax that could escape intended directories if backend validation is weak.",
    remediation: "Avoid direct path concatenation and enforce allowlisted file identifiers with root-bound validation.",
    example: "Example: ../../etc/passwd, ..%2f..%2fapp.env"
  },
  "command-injection-pattern": {
    title: "Command Injection Pattern",
    summary: "The request contains shell chaining or process execution patterns that may be dangerous if passed to a shell.",
    remediation: "Replace shell execution with safe library calls or strict argument-array invocation.",
    example: "Example: 127.0.0.1; id, test && whoami, $(cat /etc/passwd)"
  },
  "open-redirect-pattern": {
    title: "Open Redirect Pattern",
    summary: "A redirect parameter appears to accept external destinations and should be validated against an allowlist.",
    remediation: "Allow only internal paths or signed / allowlisted destinations.",
    example: "Example: /login?next=https://evil.example/phish"
  },
  "ssrf-pattern": {
    title: "SSRF Target Pattern",
    summary: "A parameter appears to target internal or metadata endpoints and may indicate SSRF surface.",
    remediation: "Validate outbound destinations strictly and block private, loopback, and metadata address spaces.",
    example: "Example: url=http://169.254.169.254/latest/meta-data"
  }
};

const FINDING_ATTACK_EXAMPLES = {
  "sensitive-data-in-url": "예: /callback?access_token=... 또는 /reset?code=... 형태로 토큰이 URL에 포함됨",
  "secret-exposed-in-response-body": "예: 응답 JSON/HTML/JS 안에 JWT, API Key, private key 헤더가 그대로 노출됨",
  "sensitive-request-payload": "예: password, token, secret 값이 요청 body에 포함된 채 로그/추적 시스템으로 저장됨",
  "basic-auth-observed": "예: Authorization: Basic dXNlcjpwYXNz 를 재사용하거나 프록시 로그에서 탈취",
  "absolute-location-observed": "예: Location: https://evil.example/phish 로 외부 절대 URL 리다이렉트",
  "cors-wildcard-with-credentials": "예: Origin: https://evil.example 요청에 ACAO:* 와 ACAC:true가 함께 응답됨",
  "cors-origin-reflection-review": "예: 임의 Origin 값을 넣었을 때 Access-Control-Allow-Origin 이 그대로 반사됨",
  "missing-csp": "예: HTML 응답에서 <script>alert(1)</script> 같은 XSS payload가 CSP 없이 실행될 수 있음",
  "missing-clickjacking-protection": "예: 민감 페이지를 iframe에 넣고 투명 레이어로 클릭 유도",
  "missing-x-content-type-options": "예: 업로드 파일을 브라우저가 스크립트로 MIME sniff 하여 실행",
  "missing-hsts": "예: 최초 HTTP 접근을 가로채 HTTPS 강제 전환 전에 세션 탈취 시도",
  "server-version-disclosure": "예: Server/X-Powered-By 헤더의 버전 정보를 바탕으로 취약 버전 공격 시도",
  "stack-trace-disclosure": "예: 예외 페이지에서 소스 경로, ORM/DB 쿼리, 내부 클래스명 노출",
  "directory-listing-exposed": "예: /uploads/, /backup/ 경로에서 파일 목록과 백업본 직접 열람",
  "js-secret-literal": "예: JS 번들 안의 API Key, Bearer token, internal endpoint를 재사용",
  "js-dom-xss-source-to-sink": "예: URL hash/search 값이 innerHTML/eval sink로 흘러 DOM XSS 발생",
  "js-dangerous-sink-usage": "예: eval(), document.write(), innerHTML 에 사용자 입력이 들어감",
  "js-postmessage-wildcard-target": "예: postMessage('*') 로 토큰/상태값이 다른 창에 전달됨",
  "js-source-map-exposure": "예: app.js.map 다운로드 후 원본 소스와 내부 API 경로 분석",
  "js-debug-artifact": "예: console/debugger 잔존으로 민감 응답과 내부 흐름 추적 가능",
  "missing-referrer-policy": "예: 외부 링크 이동 시 민감 파라미터가 Referer 로 전송",
  "sensitive-response-cache-control": "예: 개인정보 응답이 브라우저/프록시 캐시에 남아 재표시",
  "sqli-pattern": "예: id=1' OR '1'='1, UNION SELECT NULL--, SLEEP(5)",
  "sqli-error-disclosure": "예: You have an error in your SQL syntax, ORA-xxxxx, PSQLException 응답 노출",
  "sqli-review-candidate": "예: query/body/json/path 파라미터가 있는 API를 SQLMap으로 자동 점검",
  "xss-pattern": "예: <script>alert(1)</script>, \"><img src=x onerror=alert(1)>",
  "path-traversal-pattern": "예: ../../etc/passwd, ..%2f..%2fapp.env",
  "command-injection-pattern": "예: 127.0.0.1; id, test && whoami, $(cat /etc/passwd)",
  "open-redirect-pattern": "예: /login?next=https://evil.example/phish",
  "ssrf-pattern": "예: url=http://169.254.169.254/latest/meta-data 또는 내부 127.0.0.1 대상 호출"
};

function buildChecklistRowsFromFindings(findings) {
  const groups = new Map();

  for (const finding of findings || []) {
    if (!finding?.key) {
      continue;
    }

    const categoryKey = getChecklistCategoryKey(finding.key);
    const displayMeta = FINDING_DISPLAY_META[categoryKey] || {};
    const bucket = groups.get(categoryKey) || {
      key: categoryKey,
      title: displayMeta.title || finding.title,
      highestSeverity: finding.severity || "low",
      highestSeverityLabel: finding.severityLabel || SEVERITY_LABELS[finding.severity] || "Low",
      owaspLabel: finding.owaspLabel || OWASP_LABELS[finding.owasp] || finding.owasp || "Unmapped",
      description: displayMeta.summary || finding.guide || finding.area || "",
      remediation: displayMeta.remediation || finding.remediation || "",
      confidence:
        displayMeta.confidence ||
        finding.confidenceLabel ||
        getConfidenceLabel(finding.confidence || "medium"),
      count: 0,
      evidences: [],
      checklist: [],
      identifiedFindings: [],
      attackExample: displayMeta.example || FINDING_ATTACK_EXAMPLES[categoryKey] || `Example: verify the ${finding.title} path with a reproducible payload`
    };

    bucket.count += 1;
    if (getSeverityWeight(finding.severity) > getSeverityWeight(bucket.highestSeverity)) {
      bucket.highestSeverity = finding.severity;
      bucket.highestSeverityLabel = finding.severityLabel || SEVERITY_LABELS[finding.severity] || finding.severity;
    }

    if ((!bucket.description || bucket.description === finding.area) && finding.guide) {
      bucket.description = displayMeta.summary || finding.guide;
    }
    if (!bucket.remediation && finding.remediation) {
      bucket.remediation = displayMeta.remediation || finding.remediation;
    }
    if (!bucket.owaspLabel && finding.owaspLabel) {
      bucket.owaspLabel = finding.owaspLabel;
    }

    if (finding.evidence) {
      const trimmedEvidence = truncateText(finding.evidence, 220);
      if (trimmedEvidence && !bucket.evidences.includes(trimmedEvidence)) {
        bucket.evidences.push(trimmedEvidence);
      }
    }

    if (finding.title && !bucket.identifiedFindings.includes(finding.title)) {
      bucket.identifiedFindings.push(finding.title);
    }

    for (const item of finding.checklist || []) {
      if (item && !bucket.checklist.includes(item)) {
        bucket.checklist.push(item);
      }
    }

    groups.set(categoryKey, bucket);
  }

  return [...groups.values()]
    .map((bucket) => ({
      ...bucket,
      evidences: bucket.evidences.slice(0, 2),
      checklist: bucket.checklist.slice(0, 3),
      identifiedFindings: bucket.identifiedFindings,
      description: truncateText(bucket.description, 320),
      remediation: truncateText(bucket.remediation, 280)
    }))
    .sort(
      (a, b) =>
        getSeverityWeight(b.highestSeverity) - getSeverityWeight(a.highestSeverity) ||
        b.count - a.count ||
        a.title.localeCompare(b.title)
    );
}

function getChecklistCategoryKey(findingKey) {
  const key = String(findingKey || "");

  if (key === "missing-nosniff") {
    return "missing-x-content-type-options";
  }
  if (key === "server-banner-disclosure") {
    return "server-version-disclosure";
  }
  if (key === "verbose-error-disclosure") {
    return "stack-trace-disclosure";
  }
  if (key === "server-error-observed") {
    return "5xx-observed";
  }
  if (key === "directory-listing") {
    return "directory-indexing";
  }
  if (key === "js-secret-literal-exposure") {
    return "js-secret-literal";
  }

  if (key.startsWith("cookie-missing-httponly-")) {
    return "missing-httponly-cookie";
  }
  if (key.startsWith("cookie-missing-secure-")) {
    return "missing-secure-cookie";
  }
  if (key.startsWith("cookie-missing-samesite-")) {
    return "missing-samesite-cookie";
  }
  if (key.startsWith("cookie-samesite-none-without-secure-")) {
    return "samesite-none-without-secure-cookie";
  }
  if (key.startsWith("cookie-")) {
    return "auth";
  }

  return key;
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
  const isJsResponse =
    responseContentType.includes("javascript") ||
    responseContentType.includes("ecmascript") ||
    /\.m?js(?:[?#]|$)/i.test(responseUrl || requestUrl);
  const isSourceMapResponse = /\.m?js\.map(?:[?#]|$)|\.map(?:[?#]|$)/i.test(responseUrl || requestUrl);
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
  const sqlErrorObserved = SQL_ERROR_DISCLOSURE_REGEX.test(responseBody);
  const sqlmapCandidateParams = extractSqlmapCandidateParams(exchange);
  const hasSqlmapCandidateParams = sqlmapCandidateParams.some((item) =>
    ["query", "body", "json", "path"].includes(item.source)
  );
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

  if (isJsResponse && JS_SECRET_LITERAL_REGEX.test(responseBody)) {
    findings.push(
      buildFinding({
        key: "js-secret-literal-exposure",
        title: "JS 번들에 민감 키/토큰 문자열 노출 가능성",
        severity: "high",
        owasp: "A02",
        area: "JavaScript Response Body",
        evidence: `JS 응답에서 API key/token/secret 유사 literal이 보입니다. Snippet: ${findSnippet(
          responseBody,
          JS_SECRET_LITERAL_REGEX
        )}`,
        guide:
          "프론트엔드 JS 번들은 모든 사용자가 다운로드할 수 있으므로 여기에 비밀키, 장기 토큰, client secret이 포함되면 즉시 노출된 것으로 봐야 합니다. 공개 가능한 publishable key인지 서버 비밀키인지 구분이 필요합니다.",
        remediation:
          "비밀키와 장기 토큰은 서버 환경변수/비밀 저장소로 이동하고, 클라이언트에는 공개 가능한 키만 내려주세요. 이미 배포된 키는 회전하고, 번들/소스맵/CDN 캐시에 남은 값을 폐기해야 합니다.",
        checklist: [
          "해당 문자열이 공개 가능한 클라이언트 키인지 서버 비밀키인지 식별합니다.",
          "동일 키가 Git, CDN 캐시, 소스맵, 로그에도 남아 있는지 확인합니다.",
          "노출된 키는 폐기/회전하고 권한 범위와 사용 이력을 검토합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (isJsResponse && JS_DOM_XSS_FLOW_REGEX.test(responseBody)) {
    findings.push(
      buildFinding({
        key: "js-dom-xss-source-to-sink",
        title: "JS에서 DOM XSS 의심 흐름 감지",
        severity: "high",
        owasp: "A03",
        area: "JavaScript Response Body",
        evidence: `location/document/window 입력이 HTML 실행 sink로 이어지는 패턴이 보입니다. Snippet: ${findSnippet(
          responseBody,
          JS_DOM_XSS_FLOW_REGEX
        )}`,
        guide:
          "URL hash/search, document.referrer, window.name 같은 사용자 제어 입력이 innerHTML/document.write/eval류 sink에 연결되면 DOM 기반 XSS가 발생할 수 있습니다. 실제 실행 경로와 sanitization 여부 확인이 필요합니다.",
        remediation:
          "사용자 제어 입력을 HTML로 직접 삽입하지 말고 textContent, 안전한 DOM API, allowlist sanitizer를 사용하세요. URL 파라미터를 HTML/JS 컨텍스트에 넣는 구간은 컨텍스트별 인코딩을 적용해야 합니다.",
        checklist: [
          "해당 JS가 로드되는 페이지에서 URL hash/search 값을 조작해 DOM 변경을 확인합니다.",
          "입력값이 sanitizer를 통과하는지, 우회 가능한 HTML/이벤트 핸들러가 있는지 검증합니다.",
          "innerHTML/document.write/eval 사용 지점을 안전한 API로 교체 가능한지 점검합니다."
        ],
        confidence: "medium"
      })
    );
  } else if (isJsResponse && JS_DANGEROUS_SINK_REGEX.test(responseBody)) {
    findings.push(
      buildFinding({
        key: "js-dangerous-sink-usage",
        title: "JS 위험 실행/HTML sink 사용",
        severity: "medium",
        owasp: "A03",
        area: "JavaScript Response Body",
        evidence: `eval, Function, innerHTML, document.write 등 위험 sink가 보입니다. Snippet: ${findSnippet(
          responseBody,
          JS_DANGEROUS_SINK_REGEX
        )}`,
        guide:
          "위험 sink 자체가 곧 취약점은 아니지만, 사용자 입력과 결합되면 XSS나 코드 실행으로 이어집니다. 특히 CSP가 약하거나 누락된 페이지에서 악용 가능성이 커집니다.",
        remediation:
          "동적 코드 실행을 제거하고, HTML 삽입은 sanitizer와 안전한 DOM API로 제한하세요. 필요한 경우 CSP nonce/hash 기반 정책으로 인라인 실행을 줄이는 것도 병행해야 합니다.",
        checklist: [
          "해당 sink에 도달하는 데이터 출처가 URL, API 응답, postMessage, storage인지 추적합니다.",
          "사용자 입력이 escaping/sanitization 없이 전달되는 경로가 있는지 확인합니다.",
          "CSP가 위험 sink 악용을 제한할 수 있는 수준인지 함께 점검합니다."
        ],
        confidence: "medium"
      })
    );
  }

  if (isJsResponse && JS_POSTMESSAGE_WILDCARD_REGEX.test(responseBody)) {
    findings.push(
      buildFinding({
        key: "js-postmessage-wildcard-target",
        title: "postMessage 와일드카드 대상 사용",
        severity: "medium",
        owasp: "A01",
        area: "JavaScript Response Body",
        evidence: `postMessage targetOrigin이 '*'로 보입니다. Snippet: ${findSnippet(
          responseBody,
          JS_POSTMESSAGE_WILDCARD_REGEX
        )}`,
        guide:
          "민감 데이터가 포함된 메시지를 `*` 대상으로 보내면 의도하지 않은 창이나 iframe이 메시지를 받을 수 있습니다. 인증 토큰, 사용자 정보, 결제 상태 전달 코드에서 특히 위험합니다.",
        remediation:
          "targetOrigin을 정확한 origin allowlist로 제한하고, 수신 측에서도 event.origin과 event.source를 검증하세요. 메시지 payload에는 민감값을 넣지 않는 것이 기본입니다.",
        checklist: [
          "postMessage payload에 토큰, 사용자 식별자, 결제/인증 상태가 포함되는지 확인합니다.",
          "targetOrigin이 고정 allowlist인지, 현재 코드처럼 '*'인지 확인합니다.",
          "message 이벤트 수신부가 origin/source/schema 검증을 수행하는지 점검합니다."
        ],
        confidence: "medium"
      })
    );
  }

  if (
    (isJsResponse || isSourceMapResponse) &&
    JS_SOURCE_MAP_REGEX.test(`${requestUrl}\n${responseUrl}\n${responseBody}`)
  ) {
    findings.push(
      buildFinding({
        key: "js-source-map-exposure",
        title: "JS Source Map 노출 가능성",
        severity: "medium",
        owasp: "A05",
        area: "JavaScript Response Body/URL",
        evidence: `sourceMappingURL 또는 .map 파일 경로가 보입니다. Snippet: ${findSnippet(
          `${requestUrl}\n${responseUrl}\n${responseBody}`,
          JS_SOURCE_MAP_REGEX
        )}`,
        guide:
          "운영 환경에서 소스맵이 공개되면 원본 소스 구조, 내부 라우트, 주석, 상수, 숨겨진 API 경로가 노출될 수 있습니다. 키가 함께 포함된 경우 위험도가 더 커집니다.",
        remediation:
          "운영 배포에서는 소스맵 공개를 비활성화하거나 접근 제어된 저장소로 분리하세요. 이미 노출된 소스맵에 민감정보가 포함되어 있는지도 별도로 검색해야 합니다.",
        checklist: [
          ".map URL에 직접 접근 가능한지 확인합니다.",
          "소스맵 안에 API endpoint, feature flag, secret, 내부 주석이 포함되는지 검색합니다.",
          "CDN 캐시에 남은 소스맵을 무효화하고 배포 설정을 수정합니다."
        ],
        confidence: "high"
      })
    );
  }

  if (isJsResponse && JS_DEBUG_ARTIFACT_REGEX.test(responseBody)) {
    findings.push(
      buildFinding({
        key: "js-debug-artifact",
        title: "JS 디버그 코드 잔존",
        severity: "low",
        owasp: "A05",
        area: "JavaScript Response Body",
        evidence: `debugger 또는 console debug/log/trace 코드가 보입니다. Snippet: ${findSnippet(
          responseBody,
          JS_DEBUG_ARTIFACT_REGEX
        )}`,
        guide:
          "디버그 코드 자체는 보통 낮은 위험이지만, 로그에 토큰/개인정보/API 응답이 출력되거나 내부 흐름을 노출할 수 있습니다. 운영 번들 품질 관리 관점에서 제거하는 편이 좋습니다.",
        remediation:
          "운영 빌드에서 console/debugger 제거 플러그인을 적용하고, 민감 데이터 로깅 여부를 확인하세요. 에러 추적용 로그는 구조화·마스킹된 채널로 제한하는 것이 좋습니다.",
        checklist: [
          "console 출력에 사용자 정보, 토큰, API 응답 본문이 포함되는지 확인합니다.",
          "운영 빌드에서 debugger 문이 제거되는지 확인합니다.",
          "빌드 파이프라인의 minify/drop_console 설정을 검토합니다."
        ],
        confidence: "medium"
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

  if (sqlErrorObserved) {
    findings.push(
      buildFinding({
        key: "sqli-error-disclosure",
        title: "SQL 오류 메시지 노출로 Injection 가능성 의심",
        severity: "high",
        owasp: "A03",
        area: "Response Body",
        evidence: `응답 본문에서 DB/SQL 오류 패턴이 보입니다. Snippet: ${findSnippet(
          responseBody,
          SQL_ERROR_DISCLOSURE_REGEX
        )}`,
        guide:
          "SQL 문법 오류나 DB 드라이버 예외가 응답에 직접 보이면 입력값이 쿼리 처리에 영향을 주고 있을 가능성이 있습니다. 항상 SQL Injection은 아니지만, 파라미터가 동적 쿼리에 들어가는 강한 신호입니다.",
        remediation:
          "운영 응답에서 DB 오류를 숨기고, 해당 엔드포인트의 쿼리 구성을 prepared statement/parameter binding 기준으로 점검하세요. SQLMap과 수동 검증으로 응답 차이와 오류 재현 여부를 함께 확인하는 편이 좋습니다.",
        checklist: [
          "같은 요청에서 작은 따옴표, 숫자/문자 경계값, 인코딩 변형 입력으로 응답 차이를 비교합니다.",
          "서버 로그에서 실제 SQL 예외와 바인딩 실패 위치를 확인합니다.",
          "해당 엔드포인트를 SQLMap 후보로 올려 GET/POST 파라미터를 각각 점검합니다."
        ],
        confidence: "high"
      })
    );
  } else if (!requestContainsSqli && hasSqlmapCandidateParams && (isApiLikeExchange(exchange) || responseStatus >= 500)) {
    findings.push(
      buildFinding({
        key: "sqli-review-candidate",
        title: "SQL Injection 점검 권장 엔드포인트",
        severity: responseStatus >= 500 ? "medium" : "low",
        owasp: "A03",
        area: "Request URL/Body",
        evidence: `점검 가능한 파라미터가 있습니다. Params: ${
          sqlmapCandidateParams.map((item) => `${item.source}:${item.name}`).join(", ") || "none"
        }`,
        guide:
          "API 호출에서 쿼리/바디 파라미터가 식별되었고, 실제 서버 동작을 바꾸는 엔드포인트처럼 보입니다. 취약점 확정은 아니지만 SQLMap으로 자동 점검하기 좋은 후보입니다.",
        remediation:
          "이 엔드포인트를 SQLMap 후보로 올려 GET/POST/JSON 파라미터를 순차 점검하고, 서버 측에서는 ORM/raw query 구간이 파라미터 바인딩을 강제하는지 검토하세요.",
        checklist: [
          "식별된 파라미터 각각에 대해 응답 코드, 본문, 시간 차이를 비교합니다.",
          "GET이면 query, POST/PUT/PATCH면 body/json 기준으로 SQLMap을 실행합니다.",
          "로그인 세션이 필요한 엔드포인트라면 현재 세션 헤더/쿠키를 함께 넘겨 재검증합니다."
        ],
        confidence: responseStatus >= 500 ? "medium" : "low"
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

function getStoredAiSummaries() {
  const items = getStoredJson(LOCAL_AI_SUMMARIES_KEY, []);
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
          캡처와 HAR 분석 화면에 들어가기 전에 구글 계정으로 로그인하세요.
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
  const aiSummaryRecord = snapshot.aiSummaryMeta || {};
  const aiSummaryText = snapshot.aiSummary || run.ai_summary || "";
  const rawModalOwaspSummary = Array.isArray(snapshot.owaspSummary)
    ? snapshot.owaspSummary
    : Array.isArray(run.owasp_summary)
      ? run.owasp_summary
      : [];
  const rawModalEndpointSummary = Array.isArray(snapshot.endpointSummary)
    ? snapshot.endpointSummary
    : Array.isArray(run.endpoint_summary)
      ? run.endpoint_summary
      : [];
  const modalExchanges = getInspectionRunExchanges(run);
  const modalOwaspSummary =
    rawModalOwaspSummary.length > 0
      ? rawModalOwaspSummary
      : summarizeFindingsByOwasp(
          modalExchanges.flatMap((exchange) =>
            mergeSecurityFindings(
              exchange.securityFindings,
              analyzeSecurityFindings(exchange),
              exchange
            )
          )
        );
  const modalEndpointSummary =
    rawModalEndpointSummary.length > 0 ? rawModalEndpointSummary : summarizeEndpoints(modalExchanges).slice(0, 10);
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
              {modalOwaspSummary.length > 0 ? (
                modalOwaspSummary.map((item) => (
                  <span key={`${run.id}-${item.key}`} className="owasp-chip">
                    {item.label} ({item.count})
                  </span>
                ))
              ) : (
                <span className="empty-copy">저장된 OWASP 요약이 없습니다.</span>
              )}
            </div>
          </div>
          <div className="recent-card inspection-modal-wide">
            <strong>Endpoint Priority Snapshot</strong>
            <div className="endpoint-overview-list">
              {modalEndpointSummary.length > 0 ? (
                modalEndpointSummary.map((item) => (
                  <div key={`${run.id}-${item.endpoint}`} className="endpoint-card">
                    <span className="endpoint-title">{item.endpoint}</span>
                    <span>Score: {item.score}</span>
                    <span>Findings: {item.findings}</span>
                    <span>Highest: {item.highestSeverityLabel || item.highestSeverity}</span>
                  </div>
                ))
              ) : (
                <span className="empty-copy">저장된 엔드포인트 우선순위 스냅샷이 없습니다.</span>
              )}
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
          {aiSummaryText ? (
            <div className="recent-card inspection-modal-wide inspection-ai-summary-card">
              <strong>OpenAI Summary</strong>
              <span>
                {aiSummaryRecord.model ? `${aiSummaryRecord.model} · ` : ""}
                {formatDateTime(aiSummaryRecord.createdAt || run.ended_at || run.created_at)}
              </span>
              <pre>{aiSummaryText}</pre>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function MermaidModal({ code, onClose, onCopy }) {
  const [previewSvg, setPreviewSvg] = useState("");
  const [previewError, setPreviewError] = useState("");
  const [previewZoom, setPreviewZoom] = useState(1);
  const [previewLoading, setPreviewLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setPreviewZoom(1);

    async function renderMermaidPreview() {
      if (!code) {
        setPreviewSvg("");
        return;
      }

      try {
        setPreviewError("");
        setPreviewLoading(true);
        const mermaidModule = await import("mermaid");
        const mermaid = mermaidModule.default;

        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "strict",
          theme: "base",
          themeVariables: {
            primaryColor: "#e7f0ff",
            primaryTextColor: "#071426",
            primaryBorderColor: "#8fb4ff",
            lineColor: "#3a485b",
            secondaryColor: "#fff1d7",
            tertiaryColor: "#dcfce7",
            fontFamily: "KorPubDotum, sans-serif"
          }
        });
        const { svg } = await mermaid.render(`capture-flow-${Date.now()}`, code);
        if (!cancelled) {
          setPreviewSvg(svg);
        }
      } catch (error) {
        if (!cancelled) {
          setPreviewSvg("");
          setPreviewError(error instanceof Error ? error.message : "Mermaid preview render failed.");
        }
      } finally {
        if (!cancelled) {
          setPreviewLoading(false);
        }
      }
    }

    renderMermaidPreview();

    return () => {
      cancelled = true;
    };
  }, [code]);

  function handlePreviewWheel(event) {
    if (!event.metaKey && !event.altKey) {
      return;
    }

    event.preventDefault();
    const nextStep = event.deltaY > 0 ? -0.1 : 0.1;
    setPreviewZoom((current) => Math.min(2.5, Math.max(0.4, Number((current + nextStep).toFixed(2)))));
  }

  if (!code) {
    return null;
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-shell mermaid-modal-shell" onClick={(event) => event.stopPropagation()}>
        <div className="mermaid-modal-header">
          <strong>Mermaid Flow</strong>
          <button type="button" onClick={onCopy}>
            복사
          </button>
        </div>
        <div className="mermaid-modal-grid">
          <section className="mermaid-panel">
            <strong>Code</strong>
            <pre className="mermaid-modal-code">{code}</pre>
          </section>
          <section className="mermaid-panel">
            <strong>Preview</strong>
            <div
              className="mermaid-preview-box"
              onWheel={handlePreviewWheel}
              title="Cmd 또는 Option을 누른 상태로 휠을 움직이면 확대/축소됩니다."
            >
              <div className="mermaid-preview-zoom-chip">Zoom {Math.round(previewZoom * 100)}%</div>
              {previewLoading ? (
                <span className="mermaid-preview-loading">Mermaid preview loading...</span>
              ) : previewError ? (
                <span className="mermaid-preview-error">{previewError}</span>
              ) : (
                <div
                  className="mermaid-preview-viewport"
                  style={{ zoom: previewZoom }}
                  dangerouslySetInnerHTML={{ __html: previewSvg }}
                />
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function NoticeModal({ title, message, onClose }) {
  if (!message) {
    return null;
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-shell notice-modal-shell" onClick={(event) => event.stopPropagation()}>
        <div className="notice-modal-body">
          <strong>{title}</strong>
          <p>{message}</p>
          <button type="button" onClick={onClose}>
            확인
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const appShellRef = useRef(null);
  const activeRef = useRef(false);
  const autoStoppedSessionRef = useRef("");
  const savedInspectionSessionRef = useRef("");
  const summarizedSessionRef = useRef("");
  const loginFailurePopupKeyRef = useRef("");
  const capturePayloadSignatureRef = useRef("");
  const readOnlyDeployment = false;
  const [authUser, setAuthUser] = useState(() => getStoredAuthUser());
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => getStoredValue("http-analyzer-sidebar-collapsed") === "true"
  );
  const [activeSection, setActiveSection] = useState(() =>
    getStoredValue("http-analyzer-active-section", "overview")
  );
  const [captureMode, setCaptureMode] = useState(() =>
    getStoredValue("http-analyzer-capture-mode", "manual")
  );
  const [domain, setDomain] = useState(() => getStoredValue("http-analyzer-domain"));
  const [excludeInput, setExcludeInput] = useState(() =>
    getStoredValue("http-analyzer-exclude-patterns")
  );
  const [sessionValue, setSessionValue] = useState("");
  const [loginFailureModal, setLoginFailureModal] = useState("");
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
  const deferredExchanges = useDeferredValue(exchanges);
  const deferredErrors = useDeferredValue(errors);
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
  const [localAiSummaries, setLocalAiSummaries] = useState(() => getStoredAiSummaries());
  const [selectedHarHistoryKey, setSelectedHarHistoryKey] = useState("");
  const [recentHarAnalyses, setRecentHarAnalyses] = useState([]);
  const [recentCaptureEvents, setRecentCaptureEvents] = useState([]);
  const [recentInspectionRuns, setRecentInspectionRuns] = useState([]);
  const [recentCapturePage, setRecentCapturePage] = useState(1);
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
  const storedOpenAiSettings = getStoredJson(OPENAI_SETTINGS_KEY, {});
  const [openAiKey, setOpenAiKey] = useState(storedOpenAiSettings?.apiKey || "");
  const [openAiModel, setOpenAiModel] = useState(storedOpenAiSettings?.model || "gpt-4.1-mini");
  const [openAiPrompt, setOpenAiPrompt] = useState(
    storedOpenAiSettings?.prompt || DEFAULT_OPENAI_SUMMARY_PROMPT
  );
  const [aiSummary, setAiSummary] = useState("");
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false);
  const [aiSummaryError, setAiSummaryError] = useState("");
  const [sqlmapForm, setSqlmapForm] = useState({
    selectedExchangeId: "",
    url: "",
    method: "GET",
    query: "",
    data: "",
    headers: "",
    level: "1",
    risk: "1"
  });
  const [sqlmapLoading, setSqlmapLoading] = useState(false);
  const [sqlmapResult, setSqlmapResult] = useState(null);
  const [sqlmapError, setSqlmapError] = useState("");
  const [apiTestForm, setApiTestForm] = useState({
    url: "",
    method: "GET",
    headers: "{\n  \"Content-Type\": \"application/json\"\n}",
    body: ""
  });
  const [apiTestLoading, setApiTestLoading] = useState(false);
  const [apiTestResult, setApiTestResult] = useState(null);
  const [apiTestError, setApiTestError] = useState("");
  const mergedHarHistory = useMemo(
    () => [
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
    ],
    [localHarHistory, recentHarAnalyses]
  );

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    function reloadOnceForStaleChunk() {
      const lastAttempt = Number(window.sessionStorage.getItem(CHUNK_RELOAD_STORAGE_KEY) || 0);
      if (Date.now() - lastAttempt < 30000) {
        return;
      }

      window.sessionStorage.setItem(CHUNK_RELOAD_STORAGE_KEY, String(Date.now()));
      window.location.reload();
    }

    function handlePreloadError(event) {
      event.preventDefault();
      reloadOnceForStaleChunk();
    }

    function handleUnhandledRejection(event) {
      if (isDynamicImportError(event.reason)) {
        event.preventDefault();
        reloadOnceForStaleChunk();
      }
    }

    window.addEventListener("vite:preloadError", handlePreloadError);
    window.addEventListener("unhandledrejection", handleUnhandledRejection);

    return () => {
      window.removeEventListener("vite:preloadError", handlePreloadError);
      window.removeEventListener("unhandledrejection", handleUnhandledRejection);
    };
  }, []);

  const mergedInspectionRuns = useMemo(
    () => [
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
    ],
    [localInspectionRuns, recentInspectionRuns]
  );
  const domainHistoryRuns = useMemo(
    () => buildDomainHistoryRuns(mergedInspectionRuns),
    [mergedInspectionRuns]
  );
  const recentCapturePageSize = 5;
  const recentCapturePageCount = Math.max(1, Math.ceil(domainHistoryRuns.length / recentCapturePageSize));
  const pagedDomainHistoryRuns = useMemo(() => {
    const safePage = Math.min(recentCapturePage, recentCapturePageCount);
    const startIndex = (safePage - 1) * recentCapturePageSize;
    return domainHistoryRuns.slice(startIndex, startIndex + recentCapturePageSize);
  }, [domainHistoryRuns, recentCapturePage, recentCapturePageCount]);
  const mergedCaptureEvents = useMemo(
    () =>
      [
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
      ].filter((item) => !isAbortedErrorText(item.error_text)),
    [localCaptureEvents, recentCaptureEvents]
  );
  const normalizedHarHistory = useMemo(
    () =>
      mergedHarHistory.map((item) => ({
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
      })),
    [mergedHarHistory]
  );
  const selectedHarHistory =
    normalizedHarHistory.find((item) => item.historyKey === selectedHarHistoryKey) || null;

  function getAiSummaryRecordForRun(run) {
    if (!run) {
      return null;
    }

    const snapshotSummary = run.report_snapshot?.aiSummary || run.ai_summary || "";
    const snapshotMeta = run.report_snapshot?.aiSummaryMeta || {};
    if (snapshotSummary) {
      return {
        id: snapshotMeta.id || `snapshot-${run.id || run.capture_session_id || run.target_url}`,
        sessionId: snapshotMeta.sessionId || run.capture_session_id || "",
        targetUrl: snapshotMeta.targetUrl || run.target_url || "",
        createdAt: snapshotMeta.createdAt || run.ended_at || run.created_at || "",
        model: snapshotMeta.model || "",
        summary: snapshotSummary
      };
    }

    return (
      localAiSummaries.find(
        (item) =>
          (run.capture_session_id && item.sessionId === run.capture_session_id) ||
          (run.id && item.runId === run.id) ||
          (run.target_url && item.targetUrl === run.target_url)
      ) || null
    );
  }

  const liveExcludePatterns = useMemo(() => getCombinedExcludePatterns(excludeInput), [excludeInput]);
  const targetHost = useMemo(() => getHostFromUrl(domain), [domain]);
  const suppressionRules = useMemo(
    () => [...suppressedFindings, ...sessionSuppressedFindings],
    [suppressedFindings, sessionSuppressedFindings]
  );
  const scopedExchanges = useMemo(
    () => deferredExchanges.filter((exchange) => isSameTargetHostExchange(exchange, targetHost)),
    [deferredExchanges, targetHost]
  );

  const analyzedExchanges = useMemo(
    () =>
      scopedExchanges.map((exchange) => ({
        ...exchange,
        endpointKey: normalizeEndpoint(exchange.request?.url || exchange.response?.url),
        securityFindings: mergeSecurityFindings(
          exchange.securityFindings,
          analyzeSecurityFindings(exchange),
          exchange
        ).filter((finding) => !suppressionRules.some((rule) => matchesSuppressionRule(rule, finding, exchange)))
      })),
    [scopedExchanges, suppressionRules]
  );
  const allSecurityFindings = useMemo(
    () => analyzedExchanges.flatMap((exchange) => exchange.securityFindings),
    [analyzedExchanges]
  );
  const owaspSummary = useMemo(
    () => summarizeFindingsByOwasp(allSecurityFindings),
    [allSecurityFindings]
  );
  const endpointSummary = useMemo(() => summarizeEndpoints(analyzedExchanges), [analyzedExchanges]);
  const criticalAlerts = useMemo(
    () => allSecurityFindings.filter((finding) => finding.severity === "critical"),
    [allSecurityFindings]
  );
  const highAlerts = useMemo(
    () => allSecurityFindings.filter((finding) => finding.severity === "high"),
    [allSecurityFindings]
  );
  const periodStats = useMemo(() => buildPeriodStats(mergedInspectionRuns), [mergedInspectionRuns]);

  const exchangesWithDiffs = useMemo(() => {
    const previousByEndpoint = new Map();

    return analyzedExchanges.map((exchange) => {
      const previous = previousByEndpoint.get(exchange.endpointKey);
      previousByEndpoint.set(exchange.endpointKey, exchange);

      return {
        ...exchange,
        diffSummary: buildDiffSummary(exchange, previous)
      };
    });
  }, [analyzedExchanges]);

  const visibleExchanges = useMemo(
    () =>
      exchangesWithDiffs.filter((exchange) => {
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
      }),
    [exchangesWithDiffs, liveExcludePatterns, securityOnly]
  );
  const apiCapturedExchanges = useMemo(
    () =>
      exchangesWithDiffs.filter((exchange) => {
        if (!isApiLikeExchange(exchange)) {
          return false;
        }

        const requestUrl = exchange.request?.url || "";
        const responseUrl = exchange.response?.url || "";
        return !liveExcludePatterns.some(
          (pattern) =>
            (requestUrl && requestUrl.includes(pattern)) ||
            (responseUrl && responseUrl.includes(pattern))
        );
      }),
    [exchangesWithDiffs, liveExcludePatterns]
  );
  const visibleErrors = useMemo(
    () => deferredErrors.filter((item) => !isAbortedErrorText(item?.errorText)),
    [deferredErrors]
  );

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
          ["idle", "crawl-complete", "crawl-error", "browser-closed"].includes(data.stopReason) &&
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
        if (data.sessionValue) {
          setSessionValue(data.sessionValue);
        }
        if (nextActive || wasActive) {
          const nextExchanges = Array.isArray(data.exchanges) ? data.exchanges : [];
          const nextErrors = (Array.isArray(data.errors) ? data.errors : []).filter(
            (item) => !isAbortedErrorText(item?.errorText)
          );
          const lastExchange = nextExchanges[nextExchanges.length - 1];
          const lastError = nextErrors[nextErrors.length - 1];
          const nextSignature = [
            nextExchanges.length,
            lastExchange?.id || "",
            lastExchange?.response?.timestamp || "",
            nextErrors.length,
            lastError?.id || lastError?.timestamp || ""
          ].join("::");

          if (capturePayloadSignatureRef.current !== nextSignature) {
            capturePayloadSignatureRef.current = nextSignature;
            setExchanges(nextExchanges);
            setErrors(nextErrors);
          }
        }

        if (autoStopped) {
          autoStoppedSessionRef.current = data.sessionId;
          const autoStopMessage =
            data.stopReason === "crawl-complete"
              ? "크롤링이 완료되어 캡처가 자동 중지되었습니다. Recent Data를 갱신했습니다."
              : data.stopReason === "crawl-error"
                ? "크롤링 중 오류가 발생해 캡처가 자동 중지되었습니다. Recent Data를 갱신했습니다."
                : data.stopReason === "browser-closed"
                  ? "캡처 브라우저가 닫혀 캡처가 종료되었습니다. Recent Data를 갱신했습니다."
                  : "네트워크 활동이 없어 캡처가 자동 중지되었습니다. Recent Data를 갱신했습니다.";
          setStatusMessage(autoStopMessage);

          if (["crawl-complete", "idle", "crawl-error", "browser-closed"].includes(data.stopReason)) {
            const endedAt = data.stoppedAt || new Date().toISOString();
            const captureInput = {
              targetUrl: data.targetUrl,
              sessionId: data.sessionId,
              exchanges: data.exchanges || [],
              errors: data.errors || []
            };
            const snapshot = buildInspectionSnapshotFromCapture(captureInput, {
              startedAt: data.startedAt,
              endedAt
            });
            const localRun = await persistInspectionRunFromSnapshot(snapshot, captureInput, data.sessionId, {
              startedAt: data.startedAt,
              endedAt
            });
            const localEvents = buildLocalCaptureEventsFromExchanges(
              captureInput.exchanges || [],
              endedAt,
              data.sessionId,
              data.targetUrl
            );
            setLocalCaptureEvents((current) =>
              [...localEvents, ...current].filter((item) => !isAbortedErrorText(item.error_text)).slice(0, 400)
            );
            await flushCaptureArtifactsToBackend(localRun, localEvents);
          }

          const recentResponse = await fetch(`${API_BASE_URL}/api/recent-analyses`).catch(() => null);
          if (recentResponse?.ok) {
            const recentData = await recentResponse.json();
            setRecentHarAnalyses(Array.isArray(recentData.harAnalyses) ? recentData.harAnalyses : []);
            setRecentCaptureEvents(Array.isArray(recentData.captureEvents) ? recentData.captureEvents : []);
            setRecentInspectionRuns(
              Array.isArray(recentData.inspectionRuns) ? recentData.inspectionRuns : []
            );
          }

          if (["crawl-complete", "idle", "browser-closed"].includes(data.stopReason)) {
            await requestCaptureCompletionSummary(
              {
                targetUrl: data.targetUrl,
                sessionId: data.sessionId,
                exchanges: data.exchanges || [],
                errors: data.errors || []
              },
              data.sessionId
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
  }, [readOnlyDeployment, openAiKey, openAiModel, openAiPrompt]);

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
      if (activeRef.current) {
        return;
      }

      const pendingRuns = localInspectionRuns.filter((item) => item.pending_sync);
      const pendingEvents = localCaptureEvents.filter((item) => item.pending_sync);
      const pendingSummaries = localAiSummaries.filter((item) => item.pending_sync);

      if (pendingRuns.length === 0 && pendingEvents.length === 0 && pendingSummaries.length === 0) {
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

        for (const summary of pendingSummaries) {
          await syncAiSummaryRecord(summary, { refreshRecent: false });
        }
      } catch {
        return;
      }
    };

    syncLocalQueue();
    const timer = window.setInterval(syncLocalQueue, 15000);
    return () => window.clearInterval(timer);
  }, [localInspectionRuns, localCaptureEvents, localAiSummaries, readOnlyDeployment]);

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
    setStoredValue("http-analyzer-capture-mode", captureMode);
  }, [captureMode]);

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
    setStoredValue(
      OPENAI_SETTINGS_KEY,
      JSON.stringify({
        apiKey: openAiKey,
        model: openAiModel,
        prompt: openAiPrompt
      })
    );
  }, [openAiKey, openAiModel, openAiPrompt]);

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
    if (!captureSessionId && !active && exchanges.length === 0 && errors.length === 0) {
      setStoredValue(LOCAL_LIVE_CAPTURE_KEY, "");
      return;
    }

    setStoredValue(
      LOCAL_LIVE_CAPTURE_KEY,
      JSON.stringify({
        captureSessionId,
        captureMode,
        domain,
        startedAt: captureStartedAt,
        active,
        exchanges,
        errors,
        updatedAt: new Date().toISOString()
      })
    );
  }, [captureSessionId, captureMode, domain, captureStartedAt, active, exchanges, errors]);

  useEffect(() => {
    setStoredValue(LOCAL_AI_SUMMARIES_KEY, JSON.stringify(localAiSummaries));
  }, [localAiSummaries]);

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

  async function refreshRecentAnalysesOnce() {
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
  }

  async function syncAiSummaryRecord(summaryRecord, options = {}) {
    if (readOnlyDeployment || !summaryRecord?.summary) {
      return false;
    }

    const response = await fetch(`${API_BASE_URL}/api/inspection-runs/summary`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        capture_session_id: summaryRecord.sessionId || null,
        target_url: summaryRecord.targetUrl || "",
        summary: summaryRecord.summary,
        summary_meta: {
          id: summaryRecord.id,
          sessionId: summaryRecord.sessionId || "",
          targetUrl: summaryRecord.targetUrl || "",
          createdAt: summaryRecord.createdAt || "",
          source: summaryRecord.source || "",
          model: summaryRecord.model || "",
          totalExchanges: summaryRecord.totalExchanges || 0,
          totalErrors: summaryRecord.totalErrors || 0
        }
      })
    });

    if (!response.ok) {
      return false;
    }

    setLocalAiSummaries((current) => current.filter((item) => item.id !== summaryRecord.id));

    if (options.refreshRecent !== false) {
      await refreshRecentAnalysesOnce().catch(() => null);
    }

    return true;
  }

  function persistAiSummary(summaryText, captureInput = {}, context = {}) {
    const sessionId = context.sessionId || captureInput?.sessionId || captureSessionId || "";
    const targetUrl =
      context.targetUrl || captureInput?.targetUrl || domain || getStoredValue("http-analyzer-domain") || "";
    const createdAt = new Date().toISOString();
    const fallbackId = `summary-${Date.now()}`;
    const id = context.id || sessionId || fallbackId;
    const summaryRecord = {
      id,
      runId: context.runId || "",
      sessionId,
      targetUrl,
      createdAt,
      source: context.source || "manual",
      model: openAiModel.trim() || "gpt-4.1-mini",
      totalExchanges: Array.isArray(captureInput?.exchanges) ? captureInput.exchanges.length : 0,
      totalErrors: Array.isArray(captureInput?.errors) ? captureInput.errors.length : 0,
      pending_sync: !readOnlyDeployment,
      summary: summaryText
    };

    setLocalAiSummaries((current) =>
      [
        summaryRecord,
        ...current.filter(
          (item) =>
            item.id !== summaryRecord.id &&
            (!summaryRecord.sessionId || item.sessionId !== summaryRecord.sessionId)
        )
      ].slice(0, 50)
    );

    if (summaryRecord.sessionId || summaryRecord.runId) {
      setLocalInspectionRuns((current) =>
        current.map((run) => {
          const matchedBySession =
            summaryRecord.sessionId && run.capture_session_id === summaryRecord.sessionId;
          const matchedByRun = summaryRecord.runId && run.id === summaryRecord.runId;

          if (!matchedBySession && !matchedByRun) {
            return run;
          }

          return {
            ...run,
            ai_summary: summaryText,
            report_snapshot: {
              ...(run.report_snapshot || {}),
              aiSummary: summaryText,
              aiSummaryMeta: summaryRecord
            }
          };
        })
      );
    }

    void syncAiSummaryRecord(summaryRecord).catch(() => null);
  }

  async function requestOpenAiSummary(captureInput, summaryContext = {}) {
    if (!openAiKey.trim()) {
      setAiSummaryError("OpenAI API Key가 없어 Summary를 생성하지 않았습니다.");
      return "";
    }

    setAiSummaryLoading(true);
    setAiSummaryError("");

    try {
      const response = await fetch(`${API_BASE_URL}/api/openai/summary`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          apiKey: openAiKey.trim(),
          model: openAiModel.trim() || "gpt-4.1-mini",
          prompt: openAiPrompt,
          capture: captureInput
        })
      });
      const { data, rawText } = await readJsonSafely(response);

      if (!response.ok) {
        throw new Error(data?.error || rawText || "OpenAI Summary 생성에 실패했습니다.");
      }

      const summaryText = data?.summary || "(empty summary)";
      setAiSummary(summaryText);
      persistAiSummary(summaryText, captureInput, summaryContext);
      return summaryText;
    } catch (error) {
      setAiSummaryError(error instanceof Error ? error.message : "OpenAI Summary 생성에 실패했습니다.");
      return "";
    } finally {
      setAiSummaryLoading(false);
    }
  }

  async function requestCaptureCompletionSummary(captureInput, sessionId, summaryContext = {}) {
    const summaryKey =
      sessionId ||
      summaryContext.runId ||
      `${captureInput?.targetUrl || "capture"}-${captureInput?.exchanges?.length || 0}-${
        captureInput?.errors?.length || 0
      }`;

    if (summarizedSessionRef.current === summaryKey) {
      return;
    }

    summarizedSessionRef.current = summaryKey;
    await requestOpenAiSummary(captureInput, {
      ...summaryContext,
      sessionId: sessionId || "",
      source: "capture-complete"
    });
  }

  function buildInspectionSnapshotFromCapture(captureInput = {}, meta = {}) {
    const snapshotTargetUrl = captureInput.targetUrl || domain || getStoredValue("http-analyzer-domain") || "";
    const snapshotTargetHost = getHostFromUrl(snapshotTargetUrl);
    const rawExchanges = Array.isArray(captureInput.exchanges) ? captureInput.exchanges : [];
    const rawErrors = Array.isArray(captureInput.errors) ? captureInput.errors : [];
    const snapshotExcluded = getCombinedExcludePatterns(excludeInput);
    const snapshotExchanges = rawExchanges
      .filter((exchange) => isSameTargetHostExchange(exchange, snapshotTargetHost))
      .map((exchange) => ({
        ...exchange,
        endpointKey: normalizeEndpoint(exchange.request?.url || exchange.response?.url),
        securityFindings: analyzeSecurityFindings(exchange).filter(
          (finding) =>
            !suppressionRules.some((rule) => matchesSuppressionRule(rule, finding, exchange))
        )
      }))
      .filter((exchange) => {
        if (securityOnly && exchange.securityFindings.length === 0) {
          return false;
        }

        if (isImageLikeExchange(exchange)) {
          return false;
        }

        const requestUrl = exchange.request?.url || "";
        const responseUrl = exchange.response?.url || "";
        return !snapshotExcluded.some(
          (pattern) =>
            pattern &&
            ((requestUrl && requestUrl.includes(pattern)) ||
              (responseUrl && responseUrl.includes(pattern)))
        );
      });
    const snapshotFindings = snapshotExchanges.flatMap((exchange) => exchange.securityFindings);
    const snapshotCritical = snapshotFindings.filter((finding) => finding.severity === "critical");
    const snapshotHigh = snapshotFindings.filter((finding) => finding.severity === "high");
    const snapshotOwaspSummary = summarizeFindingsByOwasp(snapshotFindings);
    const snapshotEndpointSummary = summarizeEndpoints(snapshotExchanges);
    const snapshotErrors = rawErrors.filter((item) => !isAbortedErrorText(item?.errorText));

    return {
      exportedAt: meta.endedAt || new Date().toISOString(),
      inspector: authUser?.email || "-",
      domain: snapshotTargetUrl,
      excluded: snapshotExcluded,
      securityOnly,
      maskSensitive,
      totalErrors: snapshotErrors.length,
      totalFindings: snapshotFindings.length,
      criticalFindings: snapshotCritical.length,
      highFindings: snapshotHigh.length,
      conclusion: buildInspectionConclusion({
        totalFindings: snapshotFindings.length,
        criticalFindings: snapshotCritical.length,
        highFindings: snapshotHigh.length,
        totalErrors: snapshotErrors.length
      }),
      owaspSummary: snapshotOwaspSummary,
      endpointSummary: snapshotEndpointSummary,
      summary: {
        visiblePairs: snapshotExchanges.length,
        totalFindings: snapshotFindings.length
      },
      exchanges: snapshotExchanges.map((exchange) => ({
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

  async function persistInspectionRunFromSnapshot(snapshot, captureInput = {}, sessionId = "", meta = {}) {
    const runSessionId = sessionId || captureInput.sessionId || "";
    if (runSessionId && savedInspectionSessionRef.current === runSessionId) {
      return null;
    }

    if (runSessionId) {
      savedInspectionSessionRef.current = runSessionId;
    }

    const endedAt = meta.endedAt || snapshot.exportedAt || new Date().toISOString();
    const targetUrl = snapshot.domain || captureInput.targetUrl || domain || "unknown";
    const localRun = {
      id: `local-run-${Date.now()}`,
      created_at: endedAt,
      pending_sync: true,
      capture_session_id: runSessionId || null,
      target_url: targetUrl,
      started_at: meta.startedAt || captureStartedAt || null,
      ended_at: endedAt,
      total_exchanges: snapshot.summary?.visiblePairs ?? snapshot.exchanges?.length ?? 0,
      total_errors: snapshot.totalErrors ?? 0,
      total_findings: snapshot.totalFindings ?? 0,
      critical_findings: snapshot.criticalFindings ?? 0,
      high_findings: snapshot.highFindings ?? 0,
      security_only: Boolean(snapshot.securityOnly),
      mask_sensitive: Boolean(snapshot.maskSensitive),
      excluded_patterns: Array.isArray(snapshot.excluded) ? snapshot.excluded : [],
      owasp_summary: snapshot.owaspSummary || [],
      endpoint_summary: (snapshot.endpointSummary || []).slice(0, 10),
      report_snapshot: snapshot
    };

    setLocalInspectionRuns((current) => [localRun, ...current]);

    const inspectionResponse = await fetch(`${API_BASE_URL}/api/inspection-runs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        capture_session_id: localRun.capture_session_id,
        target_url: localRun.target_url,
        started_at: localRun.started_at,
        ended_at: localRun.ended_at,
        total_exchanges: localRun.total_exchanges,
        total_errors: localRun.total_errors,
        total_findings: localRun.total_findings,
        critical_findings: localRun.critical_findings,
        high_findings: localRun.high_findings,
        security_only: localRun.security_only,
        mask_sensitive: localRun.mask_sensitive,
        excluded_patterns: localRun.excluded_patterns,
        owasp_summary: localRun.owasp_summary,
        endpoint_summary: localRun.endpoint_summary,
        report_snapshot: snapshot
      })
    }).catch(() => null);

    if (inspectionResponse?.ok) {
      setLocalInspectionRuns((current) => current.filter((item) => item.id !== localRun.id));
    }

    return localRun;
  }

  function buildLocalCaptureEventsFromExchanges(rawExchanges = [], endedAt, sessionId, targetUrl) {
    return rawExchanges
      .slice()
      .reverse()
      .slice(0, 250)
      .map((exchange, index) => ({
        id: `local-event-${Date.now()}-${index}-${Math.random().toString(36).slice(2, 8)}`,
        created_at: exchange.timestamp || endedAt,
        pending_sync: true,
        capture_session_id: sessionId || null,
        target_url: targetUrl || "unknown",
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
  }

  async function flushCaptureArtifactsToBackend(localRun, localEvents) {
    if (!localRun) {
      return;
    }

    const inspectionResponse = await fetch(`${API_BASE_URL}/api/inspection-runs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        capture_session_id: localRun.capture_session_id ?? null,
        target_url: localRun.target_url,
        started_at: localRun.started_at ?? null,
        ended_at: localRun.ended_at ?? null,
        total_exchanges: localRun.total_exchanges ?? 0,
        total_errors: localRun.total_errors ?? 0,
        total_findings: localRun.total_findings ?? 0,
        critical_findings: localRun.critical_findings ?? 0,
        high_findings: localRun.high_findings ?? 0,
        security_only: Boolean(localRun.security_only),
        mask_sensitive: Boolean(localRun.mask_sensitive),
        excluded_patterns: Array.isArray(localRun.excluded_patterns) ? localRun.excluded_patterns : [],
        owasp_summary: Array.isArray(localRun.owasp_summary) ? localRun.owasp_summary : [],
        endpoint_summary: Array.isArray(localRun.endpoint_summary) ? localRun.endpoint_summary : [],
        report_snapshot: localRun.report_snapshot && typeof localRun.report_snapshot === "object" ? localRun.report_snapshot : {}
      })
    }).catch(() => null);

    if (inspectionResponse?.ok) {
      setLocalInspectionRuns((current) => current.filter((item) => item.id !== localRun.id));
    }

    if (Array.isArray(localEvents) && localEvents.length > 0) {
      const eventsResponse = await fetch(`${API_BASE_URL}/api/capture-events/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          events: localEvents.map((item) => ({
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
      }).catch(() => null);

      if (eventsResponse?.ok) {
        const syncedIds = new Set(localEvents.map((item) => item.id));
        setLocalCaptureEvents((current) => current.filter((item) => !syncedIds.has(item.id)));
      }
    }
  }

  async function runSqlmapScan(event) {
    event.preventDefault();
    setSqlmapLoading(true);
    setSqlmapError("");
    setSqlmapResult(null);

    try {
      if (!sqlmapForm.selectedExchangeId) {
        throw new Error("Captured Candidates에서 스캔할 요청을 먼저 선택하세요.");
      }

      const method = String(sqlmapForm.method || "GET").toUpperCase();
      const scanUrl = method === "GET" ? buildSqlmapGetUrl(sqlmapForm.url, sqlmapForm.query) : sqlmapForm.url;
      const response = await fetch(`${API_BASE_URL}/api/sqlmap/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...sqlmapForm,
          method,
          url: scanUrl,
          data: method === "GET" ? "" : sqlmapForm.data
        })
      });
      const { data, rawText } = await readJsonSafely(response);

      if (!response.ok) {
        throw new Error(data?.error || data?.installHint || rawText || "SQLMap scan failed.");
      }

      setSqlmapResult(data);
    } catch (error) {
      setSqlmapError(error instanceof Error ? error.message : "SQLMap scan failed.");
    } finally {
      setSqlmapLoading(false);
    }
  }

  function parseApiHeaders(input) {
    const trimmed = String(input || "").trim();
    if (!trimmed) {
      return {};
    }

    if (trimmed.startsWith("{")) {
      return JSON.parse(trimmed);
    }

    return Object.fromEntries(
      trimmed
        .split(/\n+/)
        .map((line) => line.trim())
        .filter((line) => line.includes(":"))
        .map((line) => {
          const separatorIndex = line.indexOf(":");
          return [line.slice(0, separatorIndex).trim(), line.slice(separatorIndex + 1).trim()];
        })
    );
  }

  async function runApiTest(event) {
    event.preventDefault();

    if (readOnlyDeployment) {
      setApiTestError("배포 사이트에서는 API Test를 실행할 수 없습니다. 로컬 앱을 사용해주세요.");
      return;
    }

    setApiTestLoading(true);
    setApiTestError("");
    setApiTestResult(null);

    try {
      const method = String(apiTestForm.method || "GET").toUpperCase();
      const headers = parseApiHeaders(apiTestForm.headers);
      const response = await fetch(`${API_BASE_URL}/api/replay-request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          method,
          url: apiTestForm.url,
          headers,
          body: ["GET", "HEAD", "DELETE"].includes(method) ? "" : apiTestForm.body
        })
      });
      const { data, rawText } = await readJsonSafely(response);

      if (!response.ok) {
        throw new Error(data?.error || rawText || "API 테스트 요청에 실패했습니다.");
      }

      setApiTestResult(data?.response || null);
    } catch (error) {
      setApiTestError(error instanceof Error ? error.message : "API 테스트 요청에 실패했습니다.");
    } finally {
      setApiTestLoading(false);
    }
  }

  function loadApiTestFromExchange(exchange) {
    setApiTestForm({
      url: exchange.request?.url || exchange.response?.url || "",
      method: exchange.request?.method || "GET",
      headers: prettyJson(exchange.request?.headers || {}),
      body: exchange.request?.postData || ""
    });
  }

  function buildSqlmapGetUrl(url, query) {
    const trimmedUrl = String(url || "").trim();
    const trimmedQuery = String(query || "").trim().replace(/^\?/, "");

    if (!trimmedQuery) {
      return trimmedUrl;
    }

    try {
      const nextUrl = new URL(trimmedUrl);
      nextUrl.search = trimmedQuery;
      return nextUrl.toString();
    } catch {
      const [baseUrl] = trimmedUrl.split("?");
      return `${baseUrl}?${trimmedQuery}`;
    }
  }

  function stripUrlQuery(url) {
    try {
      const nextUrl = new URL(url);
      nextUrl.search = "";
      return nextUrl.toString();
    } catch {
      return String(url || "").split("?")[0];
    }
  }

  function changeSqlmapMethod(nextMethod) {
    const method = String(nextMethod || "GET").toUpperCase();

    setSqlmapForm((current) => {
      const currentQuery = current.query || getQueryFromUrl(current.url);

      if (method === "GET") {
        return {
          ...current,
          method,
          url: buildSqlmapGetUrl(current.url, currentQuery),
          query: currentQuery,
          data: current.data
        };
      }

      return {
        ...current,
        method,
        url: stripUrlQuery(current.url),
        query: currentQuery,
        data: current.data || currentQuery
      };
    });
  }

  function getQueryFromUrl(url) {
    try {
      return new URL(url).search.replace(/^\?/, "");
    } catch {
      return String(url || "").split("?")[1] || "";
    }
  }

  function loadSqlmapFromExchange(exchange) {
    const requestUrl = exchange.request?.url || exchange.response?.url || "";
    const method = exchange.request?.method || "GET";

    setSqlmapForm({
      selectedExchangeId: exchange.id,
      url: method === "GET" ? requestUrl : stripUrlQuery(requestUrl),
      method,
      query: getQueryFromUrl(requestUrl),
      data: exchange.request?.postData || (method === "GET" ? "" : getQueryFromUrl(requestUrl)),
      headers: Object.entries(exchange.request?.headers || {})
        .map(([key, value]) => `${key}: ${String(value)}`)
        .join("\n"),
      level: sqlmapForm.level,
      risk: sqlmapForm.risk
    });
    setSqlmapResult(null);
    setSqlmapError("");
  }

  function openSqlmapFromFinding(exchange) {
    loadSqlmapFromExchange(exchange);
    setActiveSection("sqlmap");
  }

  async function startCapture(event) {
    event.preventDefault();
    if (readOnlyDeployment) {
      setStatusMessage("배포 사이트에서는 캡처를 실행할 수 없습니다. 로컬 앱을 사용해주세요.");
      return;
    }

    setSubmitting(true);
    setStatusMessage("");
    setLoginFailureModal("");
    loginFailurePopupKeyRef.current = "";

    try {
      if (!domain.trim()) {
        throw new Error("Domain을 입력해주세요.");
      }

      if (captureMode === "session" && !sessionValue.trim()) {
        throw new Error("세션 입력 모드에서는 Session 값을 입력해야 합니다.");
      }

      const excludePatterns = excludeInput
        ? getCombinedExcludePatterns(excludeInput)
        : [...FIXED_EXCLUDE_PATTERNS];

      const response = await fetch(`${API_BASE_URL}/api/capture/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain,
          excludePatterns,
          sessionValue: captureMode === "session" ? sessionValue.trim() : "",
          captureMode
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
      if (result.sessionValue) {
        setSessionValue(result.sessionValue);
      }
      activeRef.current = true;
      autoStoppedSessionRef.current = "";
      savedInspectionSessionRef.current = "";
      summarizedSessionRef.current = "";
      capturePayloadSignatureRef.current = "";
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
      const localEvents = buildLocalCaptureEventsFromExchanges(
        analyzedExchanges,
        endedAt,
        captureSessionId || null,
        domain || getStoredValue("http-analyzer-domain") || "unknown"
      );

      setLocalInspectionRuns((current) => [localRun, ...current]);
      setLocalCaptureEvents((current) =>
        [...localEvents, ...current].filter((item) => !isAbortedErrorText(item.error_text)).slice(0, 40)
      );
      setErrors((current) => current.filter((item) => !isAbortedErrorText(item.errorText)));

      await fetch(`${API_BASE_URL}/api/capture/stop`, { method: "POST" });
      await flushCaptureArtifactsToBackend(localRun, localEvents);
      await requestCaptureCompletionSummary(
        {
          targetUrl: domain || getStoredValue("http-analyzer-domain") || "",
          exchanges: analyzedExchanges,
          errors
        },
        captureSessionId || "",
        { runId: localRun.id }
      );
      setStatusMessage("");
      setActive(false);
      activeRef.current = false;
      capturePayloadSignatureRef.current = "";
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
    const reportAiSummary = reportInput.aiSummary || "";
    const reportAiSummaryMeta = reportInput.aiSummaryMeta || {};
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
    .ai-summary{margin-top:16px;padding:16px;border-radius:16px;background:#fff;border:1px solid #d8e0ea;box-shadow:0 12px 32px rgba(15,23,42,.08)}
    .ai-summary h2{margin:0 0 8px;font-size:20px;color:#172033}
    .ai-summary p{margin:0 0 12px;color:#64748b;font-size:13px}
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
    ${
      reportAiSummary
        ? `<section class="ai-summary">
            <h2>OpenAI Summary</h2>
            <p>${escapeHtml(
              `${reportAiSummaryMeta.model ? `${reportAiSummaryMeta.model} · ` : ""}${formatDateTime(
                reportAiSummaryMeta.createdAt || reportExportedAt
              )}`
            )}</p>
            <pre>${escapeHtml(reportAiSummary)}</pre>
          </section>`
        : ""
    }
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
      aiSummary,
      aiSummaryMeta:
        getAiSummaryRecordForRun({
          capture_session_id: captureSessionId,
          target_url: domain || getStoredValue("http-analyzer-domain") || ""
        }) || null,
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
    loadInspectionRunIntoWorkspace(run, { showStatus: false });
    const summaryRecord = getAiSummaryRecordForRun(run);
    setInspectionModalRun(
      summaryRecord
        ? {
            ...run,
            ai_summary: summaryRecord.summary,
            report_snapshot: {
              ...(run.report_snapshot || {}),
              aiSummary: summaryRecord.summary,
              aiSummaryMeta: summaryRecord
            }
          }
        : run
    );
  }

  function buildExchangeFromCaptureEvent(event) {
    const requestUrl = event.request_url || event.target_url || "";
    return {
      id: `recent-event-${event.id || requestUrl || Date.now()}`,
      timestamp: event.request_timestamp || event.created_at || "",
      endpointKey: normalizeEndpoint(requestUrl),
      request: requestUrl
        ? {
            method: event.request_method || "GET",
            url: requestUrl,
            resourceType: event.request_resource_type || "request",
            headers: event.request_headers || {},
            postData: event.request_body || ""
          }
        : null,
      response:
        event.response_status || event.response_url || event.response_body_preview
          ? {
              timestamp: event.response_timestamp || event.created_at || "",
              url: event.response_url || requestUrl,
              status: event.response_status || null,
              statusText: event.response_status_text || "",
              headers: event.response_headers || {},
              bodyPreview: event.response_body_preview || ""
            }
          : null
    };
  }

  function getInspectionRunExchanges(run) {
    if (run.domainKey && Array.isArray(run.report_snapshot?.exchanges) && run.report_snapshot.exchanges.length > 0) {
      return run.report_snapshot.exchanges;
    }

    const domainRuns =
      Array.isArray(run.runs) && run.runs.length > 0
        ? run.runs
        : run.domainKey
          ? mergedInspectionRuns
              .filter((historyRun) => getRunDomainKey(historyRun) === run.domainKey)
              .sort((a, b) => getRunTimeValue(b) - getRunTimeValue(a))
          : [];

    if (domainRuns.length > 0) {
      return domainRuns.flatMap((historyRun, runIndex) =>
        getInspectionRunExchanges(historyRun).map((exchange, exchangeIndex) => {
          const exchangeWithSource = {
            ...exchange,
            id: `domain-history-${run.domainKey || historyRun.target_url || "run"}-${runIndex}-${exchange.id || exchangeIndex}`,
            sourceRunId: historyRun.id || historyRun.capture_session_id || "",
            sourceRunEndedAt: historyRun.ended_at || historyRun.created_at || ""
          };

          return {
            ...exchangeWithSource,
            securityFindings: mergeSecurityFindings(
              exchange.securityFindings,
              analyzeSecurityFindings(exchangeWithSource),
              exchangeWithSource
            )
          };
        })
      );
    }

    const snapshot = run.report_snapshot && typeof run.report_snapshot === "object" ? run.report_snapshot : {};

    if (Array.isArray(snapshot.exchanges) && snapshot.exchanges.length > 0) {
      return snapshot.exchanges.map((exchange, index) => ({
        ...exchange,
        id: exchange.id || `snapshot-exchange-${run.id || run.capture_session_id || index}-${index}`,
        endpointKey: exchange.endpointKey || exchange.endpoint || normalizeEndpoint(exchange.request?.url || exchange.response?.url)
      }));
    }

    return mergedCaptureEvents
      .filter((event) =>
        run.capture_session_id
          ? event.capture_session_id === run.capture_session_id
          : event.target_url === run.target_url
      )
      .map(buildExchangeFromCaptureEvent);
  }

  function loadInspectionRunIntoWorkspace(run, options = {}) {
    const snapshot = getInspectionReportSnapshot(run);
    const nextDomain = snapshot.domain || run.target_url || "";
    const nextExcluded = Array.isArray(snapshot.excluded)
      ? snapshot.excluded
      : Array.isArray(run.excluded_patterns)
        ? run.excluded_patterns
        : [];
    const userExcluded = nextExcluded.filter((pattern) => !FIXED_EXCLUDE_PATTERNS.includes(pattern));
    const nextExchanges = getInspectionRunExchanges(run);
    const summaryRecord = getAiSummaryRecordForRun(run);

    setDomain(nextDomain);
    setExcludeInput(userExcluded.join(", "));
    setSecurityOnly(Boolean(snapshot.securityOnly ?? run.security_only));
    setMaskSensitive(Boolean(snapshot.maskSensitive ?? run.mask_sensitive ?? true));
    setExchanges(nextExchanges);
    setErrors([]);
    setFocusedFindingExchangeId("");
    setActive(false);
    activeRef.current = false;
    setCaptureSessionId(run.capture_session_id || "");
    setCaptureStartedAt(run.started_at || "");

    if (summaryRecord?.summary) {
      setAiSummary(summaryRecord.summary);
      setAiSummaryError("");
    }

    if (options.showStatus !== false) {
      setStatusMessage(
        `${run.domainKey || nextDomain || "선택한 점검"} 전체 스캔 이력 ${run.scanCount || 1}건을 현재 분석 화면에 불러왔습니다. Overview, Findings, SQLMap, API Test에 반영됩니다.`
      );
    }
  }

  function getInspectionReportSnapshot(run) {
    const baseSnapshot =
      run.report_snapshot && Object.keys(run.report_snapshot).length > 0
        ? run.report_snapshot
        : {
            domain: run.target_url,
            excluded: run.excluded_patterns || [],
            securityOnly: run.security_only,
            maskSensitive: run.mask_sensitive,
            inspector: authUser?.email || "-",
            exportedAt: run.ended_at || run.created_at,
            conclusion: buildInspectionConclusion({
              totalFindings: run.total_findings,
              criticalFindings: run.critical_findings,
              highFindings: run.high_findings,
              totalErrors: run.total_errors
            }),
            owaspSummary: run.owasp_summary || [],
            endpointSummary: run.endpoint_summary || [],
            exchanges: []
          };
    const summaryRecord = getAiSummaryRecordForRun(run);

    if (!summaryRecord?.summary) {
      return baseSnapshot;
    }

    return {
      ...baseSnapshot,
      aiSummary: summaryRecord.summary,
      aiSummaryMeta: summaryRecord
    };
  }

  const findingEntries = visibleExchanges.flatMap((exchange) =>
    (exchange.securityFindings || []).map((finding) => ({ exchange, finding }))
  );
  const displayedFindingEntries = focusedFindingExchangeId
    ? findingEntries.filter(({ exchange }) => exchange.id === focusedFindingExchangeId)
    : findingEntries;
  const checklistRows = useMemo(
    () => buildChecklistRowsFromFindings(allSecurityFindings),
    [allSecurityFindings]
  );
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
      : captureMeta.stopReason === "browser-closed"
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

  const captureChecklistItems = [
    {
      key: "sqli",
      title: "SQL Injection",
      description:
        "쿼리 문자열, 폼 바디, JSON payload, path 파라미터가 SQL 실행에 영향을 줄 수 있는지 점검합니다. 정상 입력과 공격 입력의 응답 본문, 상태 코드, 응답 시간 차이를 비교하고 prepared statement가 일관되게 적용되는지 확인합니다.",
      example: "예: id=1' OR '1'='1, q=test' UNION SELECT NULL--, SLEEP(5)"
    },
    {
      key: "xss",
      title: "Cross-Site Scripting (XSS)",
      description:
        "신뢰할 수 없는 입력이 HTML, DOM, JavaScript, 템플릿에 컨텍스트별 인코딩 없이 반영되는지 확인합니다. innerHTML, document.write, eval 같은 위험 sink에 도달 가능한지와 CSP가 실제로 실행을 제한하는지도 함께 봅니다.",
      example: "예: <script>alert(1)</script>, \"><img src=x onerror=alert(1)>"
    },
    {
      key: "idor",
      title: "IDOR / Authorization Bypass",
      description:
        "객체 ID, 계정 번호, 주문 번호, 문서 키만 바꿔도 다른 사용자의 데이터에 접근 가능한지 확인합니다. 서버가 클라이언트 식별자를 신뢰하지 않고 소유권 및 권한 검사를 수행하는지 검증합니다.",
      example: "예: /api/orders/1001 -> /api/orders/1002 변경 시 다른 사용자의 주문이 반환되는지 확인"
    },
    {
      key: "auth",
      title: "Authentication / Session Management",
      description:
        "로그인, 로그아웃, 토큰 갱신, 쿠키 속성, 세션 무효화 동작을 점검합니다. 보호된 엔드포인트가 인증 없는 접근을 차단하는지, 로그아웃 후 활성 세션이나 토큰이 실제로 폐기되는지 확인합니다.",
      example: "예: 로그아웃 후 기존 SESSIONID가 계속 동작하거나 /api/member/profile 이 무인증으로 응답"
    },
    {
      key: "cors",
      title: "CORS / Cross-Origin Policy",
      description:
        "교차 출처 접근이 신뢰된 Origin으로만 제한되는지, 인증된 cross-origin 응답 읽기가 가능한지 점검합니다. Origin 반사 동작, wildcard 규칙, preflight 응답, credential 사용 여부를 악성 Origin 기준으로 테스트합니다.",
      example: "예: Origin: https://evil.example 이 반사되고 Access-Control-Allow-Credentials: true 가 함께 응답"
    },
    {
      key: "path-traversal",
      title: "Path Traversal / File Access",
      description:
        "파일명, 경로, 템플릿, 다운로드 파라미터가 의도된 디렉터리 경계를 벗어날 수 있는지 테스트합니다. 인코딩된 traversal payload, 슬래시 변형, 중첩 경로 입력을 포함해 민감 파일 읽기/덮어쓰기가 가능한지 확인합니다.",
      example: "예: ../../etc/passwd, ..%2f..%2fapp.env"
    },
    {
      key: "cmdi",
      title: "Command Injection",
      description:
        "셸 명령이나 시스템 유틸리티를 호출하는 기능을 식별하고, 사용자 입력이 그 명령에 직접 이어붙는지 확인합니다. 구분자, 서브셸 문법, 환경변수 확장, 파일 기반 명령 인자가 임의 실행을 유발할 수 있는지 점검합니다.",
      example: "예: 127.0.0.1; id, test && whoami"
    },
    {
      key: "open-redirect",
      title: "Open Redirect",
      description:
        "next, redirect, returnUrl, continue, destination 파라미터가 임의 외부 URL 이동을 허용하는지 점검합니다. 로그인, 로그아웃, 비밀번호 재설정, 결제 완료 흐름에서 악용 가능한지도 함께 확인합니다.",
      example: "예: /login?next=https://evil.example/phish"
    },
    {
      key: "secret",
      title: "Sensitive Data Exposure",
      description:
        "URL, 요청 바디, 응답 payload, 헤더, JavaScript 번들 안에서 secret, 자격증명, 개인정보, 내부 엔드포인트, 환경 정보가 노출되는지 확인합니다. 이런 값이 브라우저 캐시, 로그, source map에도 남는지 함께 검토합니다.",
      example: "예: access_token=..., Authorization: Bearer ..., source map에 내부 API 경로 노출"
    }
  ];
  const fallbackChecklistRows = useMemo(
    () =>
      captureChecklistItems.map((item) => ({
        key: item.key,
        title: item.title,
        highestSeverity: "medium",
        highestSeverityLabel: "Medium",
        owaspLabel: "Manual Review",
        description: item.description,
        remediation: "연관된 요청/응답 흐름을 수동으로 검증하고, 실제로 확인되면 관련 백엔드 로직이나 헤더 설정 수정 우선순위를 높이세요.",
        confidence: "수동 검증이 필요한 기본 점검 항목",
        count: 0,
        evidences: ["아직 매핑된 captured finding은 없습니다. 새로 캡처한 트래픽에 대해 이 행을 기준으로 수동 점검하세요."],
        checklist: [],
        attackExample: item.example
      })),
    [captureChecklistItems]
  );
  const renderedChecklistRows = checklistRows.length > 0 ? checklistRows : fallbackChecklistRows;
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
      key: "checklist",
      icon: "checklist",
      label: "Vulnerability Checklist",
      description: "One-row-per-vulnerability review board",
      count:
        allSecurityFindings.length > 0
          ? new Set(allSecurityFindings.map((finding) => getChecklistCategoryKey(finding.key))).size
          : captureChecklistItems.length
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
      description: "스캔 도메인 목록",
      count: domainHistoryRuns.length
    },
    {
      key: "sqlmap",
      icon: "sqlmap",
      label: "SQLMap",
      description: "SQL Injection 자동 점검",
      count: sqlmapResult ? 1 : 0
    },
    {
      key: "api-test",
      icon: "api",
      label: "API Test",
      description: "API 요청 테스트",
      count: apiCapturedExchanges.length
    },
    {
      key: "settings",
      icon: "settings",
      label: "Settings",
      description: "OpenAI Summary 설정",
      count: openAiKey ? 1 : 0
    }
  ].filter((item) => !readOnlyDeployment || !["capture", "har", "sqlmap", "api-test"].includes(item.key));

  function navigateToSection(sectionKey) {
    if (sectionKey !== "findings") {
      setFocusedFindingExchangeId("");
    }

    if (sectionKey === "findings" && activeSection !== "capture") {
      setFocusedFindingExchangeId("");
    }

    setActiveSection(sectionKey);

    if (sectionKey === "recent") {
      setRecentLoading(true);
      refreshRecentAnalysesOnce().finally(() => setRecentLoading(false));
    }
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

  useEffect(() => {
    setRecentCapturePage((current) => Math.min(current, recentCapturePageCount));
  }, [recentCapturePageCount]);

  if (!authUser) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <main ref={appShellRef} className="page-shell">
      <div className={`app-layout ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
        <aside className="sidebar-card">
          <div className="sidebar-brand">
            <div className="sidebar-brand-row">
              <div>
                <h1 className="page-title sidebar-title">HTTP Analyzer</h1>
                <p className="sidebar-subtitle">TECHNICAL ANALYZER</p>
              </div>
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
                  <div className="capture-mode-row">
                    <button
                      type="button"
                      className={captureMode === "manual" ? "capture-mode-chip active" : "capture-mode-chip"}
                      onClick={() => setCaptureMode("manual")}
                    >
                      새창 수동 캡처
                    </button>
                    <button
                      type="button"
                      className={captureMode === "session" ? "capture-mode-chip active" : "capture-mode-chip"}
                      onClick={() => setCaptureMode("session")}
                    >
                      세션 입력 캡처
                    </button>
                  </div>
                  <div
                    className={`capture-primary-row ${
                      captureMode === "session" ? "capture-primary-row-session" : "capture-primary-row-manual"
                    }`}
                  >
                    <label className="field-label field-card">
                      <span>Domain:</span>
                      <input
                        type="text"
                        placeholder="도메인 입력"
                        value={domain}
                        onChange={(event) => setDomain(event.target.value)}
                      />
                    </label>
                    {captureMode === "session" ? (
                      <label className="field-label field-card session-field">
                        <span>Session:</span>
                        <input
                          type="password"
                          autoComplete="off"
                          placeholder="세션 쿠키 값 입력 예: SESSIONID=...; token=..."
                          value={sessionValue}
                          onChange={(event) => setSessionValue(event.target.value)}
                        />
                      </label>
                    ) : null}
                  </div>
                  <div className="capture-filter-row">
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
                  <p className="field-hint">
                    {captureMode === "manual"
                      ? "새창이 열리면 직접 로그인하거나 이동하세요. 로그인 후 발생하는 요청/응답을 그대로 캡처합니다."
                      : "Session 값을 넣고 바로 인증된 상태로 스캔합니다. 이미지 요청은 항상 제외됩니다."}
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
                {aiSummaryLoading || aiSummaryError || aiSummary ? (
                  <div className="capture-ai-summary">
                    <div>
                      <strong>OpenAI Summary</strong>
                      <span>
                        {aiSummaryLoading
                          ? "캡처 결과를 분석 중입니다."
                          : aiSummary
                            ? "최근 캡처 완료 후 생성된 요약입니다."
                            : "Summary 생성 상태"}
                      </span>
                    </div>
                    {aiSummaryError ? <div className="error-strip">{aiSummaryError}</div> : null}
                    {aiSummary ? <pre>{aiSummary}</pre> : null}
                  </div>
                ) : null}
              </div>
            ) : activeSection === "overview" ||
              activeSection === "findings" ||
              activeSection === "har" ||
              activeSection === "recent" ||
              activeSection === "sqlmap" ||
              activeSection === "api-test" ||
              activeSection === "checklist" ||
              activeSection === "settings" ? null : (
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

            {statusMessage ? (
              <p
                className={`status ${
                  statusMessage === "크롤링이 완료되어 캡처가 자동 중지되었습니다. Recent Data를 갱신했습니다."
                    ? "auto-stop-status"
                    : ""
                }`}
              >
                {statusMessage}
              </p>
            ) : null}
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
                  {periodStats
                    .filter((item) => item.key === "30d")
                    .map((item) => (
                      <div key={item.key} className="stats-card stats-card-inline">
                        <strong>{item.label}</strong>
                        <div className="stats-inline-row">
                          <span>도메인 {item.domainCount}개</span>
                          <span>점검 {item.runCount}회</span>
                          <span>요청 {item.totalExchanges}건</span>
                          <span>Finding {item.totalFindings}건</span>
                          <span>Critical {item.criticalFindings} / High {item.highFindings}</span>
                        </div>
                      </div>
                    ))}
                </div>
                <div className="recent-capture-panel section-panel">
                  <div className="recent-section-header">
                    <strong>Recent Capture Events</strong>
                    <span>스캔한 도메인 목록만 표시하며 페이지당 5개씩 보여줍니다. 불러오기는 해당 도메인의 전체 스캔 이력을 복원합니다.</span>
                  </div>
                  <div className="inspection-run-table">
                    {domainHistoryRuns.length === 0 ? (
                      <span className="empty-copy">
                        {recentLoading ? "스캔한 도메인을 불러오는 중..." : "저장된 스캔 도메인이 없습니다."}
                      </span>
                    ) : (
                      pagedDomainHistoryRuns.map((item) => {
                        const summaryRecord = getAiSummaryRecordForRun(item);

                        return (
                          <div key={item.domainKey || item.id} className="inspection-run-item">
                            <div className="inspection-run-row">
                              <div className="inspection-run-main">
                                <strong>{item.domainKey || item.target_url || "-"}</strong>
                                <div className="inspection-run-meta">
                                  <span>최근 스캔 {formatDateTime(item.ended_at || item.created_at)}</span>
                                  <span>스캔 {item.scanCount || 1}회</span>
                                  <span>
                                    {item.historySource === "local"
                                      ? item.pending_sync
                                        ? "로컬(대기)"
                                        : "로컬"
                                      : "DB"}
                                  </span>
                                  <span>세션 {item.capture_session_id || "-"}</span>
                                </div>
                              </div>
                              <div className="inspection-run-metrics">
                                <span>최근 요청 {item.total_exchanges}건</span>
                                <span>전체 요청 {item.aggregate_total_exchanges ?? item.total_exchanges}건</span>
                                <span>Finding {item.aggregate_total_findings ?? item.total_findings}건</span>
                              </div>
                              <div className="inspection-run-risk">
                                <span className="risk-chip risk-critical">Critical {item.aggregate_critical_findings ?? item.critical_findings}</span>
                                <span className="risk-chip risk-high">High {item.aggregate_high_findings ?? item.high_findings}</span>
                              </div>
                              <div className="inspection-run-actions">
                                <button type="button" onClick={() => loadInspectionRunIntoWorkspace(item)}>
                                  불러오기
                                </button>
                                <button type="button" onClick={() => openInspectionRun(item)}>
                                  상세 보기
                                </button>
                                <button
                                  type="button"
                                  onClick={() => downloadHtmlReport(getInspectionReportSnapshot(item))}
                                >
                                  HTML 재다운로드
                                </button>
                                <button
                                  type="button"
                                  onClick={() => downloadPdfReport(getInspectionReportSnapshot(item))}
                                >
                                  PDF 재다운로드
                                </button>
                              </div>
                            </div>
                            {summaryRecord?.summary ? (
                              <details className="inspection-summary-details">
                                <summary>
                                  OpenAI Summary · {formatDateTime(summaryRecord.createdAt)}
                                </summary>
                                <pre>{summaryRecord.summary}</pre>
                              </details>
                            ) : null}
                          </div>
                        );
                      })
                    )}
                  </div>
                  {recentCapturePageCount > 1 ? (
                    <div className="recent-pagination">
                      {Array.from({ length: recentCapturePageCount }, (_value, index) => {
                        const page = index + 1;

                        return (
                          <button
                            key={`recent-capture-page-${page}`}
                            type="button"
                            className={recentCapturePage === page ? "active" : ""}
                            onClick={() => setRecentCapturePage(page)}
                          >
                            {page}
                          </button>
                        );
                      })}
                    </div>
                  ) : null}
                </div>
              </article>
            </section>
          ) : null}

          {activeSection === "sqlmap" ? (
            <section className="pair-list">
              <article className="panel stacked-panel">
                <div className="tool-panel section-panel">
                  <strong>SQLMap Injection Scan</strong>
                  <p className="tool-copy">
                    Captured Candidates에서 선택한 요청만 SQL Injection 가능성을 점검합니다. 서버에 `sqlmap`이 설치되어 있어야 실행됩니다.
                  </p>
                  <form className="tool-form" onSubmit={runSqlmapScan}>
                    <div className="tool-note">
                      {sqlmapForm.selectedExchangeId
                        ? "선택된 캡처 요청만 스캔합니다. Target URL과 Body는 선택된 요청 기준으로 조정됩니다."
                        : "아래 Captured Candidates에서 스캔할 요청을 먼저 선택하세요."}
                    </div>
                    <label className="field-label field-card">
                      <span>Target URL</span>
                      <input
                        type="text"
                        placeholder="https://target.example/api?id=1"
                        value={sqlmapForm.url}
                        readOnly
                      />
                    </label>
                    <div className="tool-grid-3">
                      <label className="field-label field-card">
                        <span>Method</span>
                        <select
                          value={sqlmapForm.method}
                          onChange={(event) => changeSqlmapMethod(event.target.value)}
                        >
                          <option value="GET">GET</option>
                          <option value="POST">POST</option>
                          <option value="PUT">PUT</option>
                          <option value="PATCH">PATCH</option>
                        </select>
                      </label>
                      <label className="field-label field-card">
                        <span>Level</span>
                        <input
                          type="number"
                          min="1"
                          max="5"
                          value={sqlmapForm.level}
                          onChange={(event) =>
                            setSqlmapForm((current) => ({ ...current, level: event.target.value }))
                          }
                        />
                      </label>
                      <label className="field-label field-card">
                        <span>Risk</span>
                        <input
                          type="number"
                          min="1"
                          max="3"
                          value={sqlmapForm.risk}
                          onChange={(event) =>
                            setSqlmapForm((current) => ({ ...current, risk: event.target.value }))
                          }
                        />
                      </label>
                    </div>
                    {sqlmapForm.method === "GET" ? (
                      <label className="field-label field-card">
                        <span>Query Parameters</span>
                        <textarea
                          rows={4}
                          placeholder="id=1&name=test"
                          value={sqlmapForm.query}
                          onChange={(event) =>
                            setSqlmapForm((current) => ({ ...current, query: event.target.value }))
                          }
                        />
                      </label>
                    ) : (
                      <label className="field-label field-card">
                        <span>{sqlmapForm.method} Body / Data</span>
                        <textarea
                          rows={5}
                          placeholder="id=1&name=test"
                          value={sqlmapForm.data}
                          onChange={(event) =>
                            setSqlmapForm((current) => ({ ...current, data: event.target.value }))
                          }
                        />
                      </label>
                    )}
                    <label className="field-label field-card">
                      <span>Headers</span>
                      <textarea
                        rows={5}
                        placeholder={'Cookie: SESSIONID=...\nAuthorization: Bearer ...'}
                        value={sqlmapForm.headers}
                        onChange={(event) =>
                          setSqlmapForm((current) => ({ ...current, headers: event.target.value }))
                        }
                      />
                    </label>
                    <div className="action-row">
                      <button
                        type="submit"
                        disabled={sqlmapLoading || !sqlmapForm.selectedExchangeId || !sqlmapForm.url.trim()}
                      >
                        {sqlmapLoading ? "SQLMap 실행 중..." : "SQLMap Scan"}
                      </button>
                    </div>
                  </form>
                  {sqlmapError ? <div className="error-strip">{sqlmapError}</div> : null}
                  {visibleExchanges.length > 0 ? (
                    <div className="candidate-list">
                      <strong>Captured Candidates</strong>
                      {visibleExchanges.slice(0, 12).map((exchange) => {
                        const candidateParams = extractSqlmapCandidateParams(exchange);

                        return (
                          <button
                            key={exchange.id}
                            type="button"
                            className={`candidate-row ${
                              sqlmapForm.selectedExchangeId === exchange.id ? "active" : ""
                            }`}
                            onClick={() => loadSqlmapFromExchange(exchange)}
                          >
                            <span className="candidate-method">{exchange.request?.method || "GET"}</span>
                            <div className="candidate-main">
                              <strong>{exchange.request?.url || exchange.response?.url || "-"}</strong>
                              <small>
                                Params:{" "}
                                {candidateParams.length > 0
                                  ? candidateParams
                                      .map((item) => `${item.source}:${item.name}`)
                                      .join(", ")
                                  : "식별된 파라미터 없음"}
                              </small>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  ) : null}
                  {sqlmapResult ? (
                    <div className="tool-result">
                      <strong>SQLMap Result</strong>
                      <span>
                        {formatDateTime(sqlmapResult.startedAt)} ~ {formatDateTime(sqlmapResult.endedAt)}
                      </span>
                      <pre>{[sqlmapResult.stdout, sqlmapResult.stderr].filter(Boolean).join("\n\n")}</pre>
                    </div>
                  ) : null}
                </div>
              </article>
            </section>
          ) : null}

          {activeSection === "api-test" ? (
            <section className="pair-list">
              <article className="panel stacked-panel">
                <div className="tool-panel section-panel">
                  <strong>API Request Test</strong>
                  <p className="tool-copy">
                    캡처된 요청을 불러오거나 직접 API 요청을 구성해 응답 상태, 헤더, 바디를 확인합니다.
                  </p>
                  <form className="tool-form" onSubmit={runApiTest}>
                    <div className="tool-grid-3">
                      <label className="field-label field-card">
                        <span>Method</span>
                        <select
                          value={apiTestForm.method}
                          onChange={(event) =>
                            setApiTestForm((current) => ({ ...current, method: event.target.value }))
                          }
                        >
                          <option value="GET">GET</option>
                          <option value="POST">POST</option>
                          <option value="PUT">PUT</option>
                          <option value="PATCH">PATCH</option>
                          <option value="DELETE">DELETE</option>
                          <option value="HEAD">HEAD</option>
                        </select>
                      </label>
                      <label className="field-label field-card tool-grid-span-2">
                        <span>URL</span>
                        <input
                          type="text"
                          placeholder="https://api.example.com/resource"
                          value={apiTestForm.url}
                          onChange={(event) =>
                            setApiTestForm((current) => ({ ...current, url: event.target.value }))
                          }
                        />
                      </label>
                    </div>
                    <label className="field-label field-card">
                      <span>Headers</span>
                      <textarea
                        rows={6}
                        placeholder={'{\n  "Authorization": "Bearer ..."\n}\n\n또는\nAuthorization: Bearer ...'}
                        value={apiTestForm.headers}
                        onChange={(event) =>
                          setApiTestForm((current) => ({ ...current, headers: event.target.value }))
                        }
                      />
                    </label>
                    {!["GET", "HEAD", "DELETE"].includes(apiTestForm.method) ? (
                      <label className="field-label field-card">
                        <span>Body</span>
                        <textarea
                          rows={8}
                          placeholder='{"id":1,"name":"test"}'
                          value={apiTestForm.body}
                          onChange={(event) =>
                            setApiTestForm((current) => ({ ...current, body: event.target.value }))
                          }
                        />
                      </label>
                    ) : (
                      <div className="tool-note">
                        {apiTestForm.method} 요청은 Body 없이 URL과 Headers만 전송합니다.
                      </div>
                    )}
                    <div className="action-row">
                      <button type="submit" disabled={apiTestLoading || !apiTestForm.url.trim()}>
                        {apiTestLoading ? "API 요청 중..." : "API Test"}
                      </button>
                    </div>
                  </form>
                  {apiTestError ? <div className="error-strip">{apiTestError}</div> : null}
                  {apiTestResult ? (
                    <div className="api-test-result-grid">
                      <div className="tool-result">
                        <strong>Request</strong>
                        <span>
                          {apiTestForm.method} {apiTestForm.url || "-"}
                        </span>
                        <CodeBlock
                          sections={[
                            { label: "Headers", content: apiTestForm.headers || "(empty)" },
                            {
                              label: "Body",
                              content: ["GET", "HEAD", "DELETE"].includes(apiTestForm.method)
                                ? "(not sent)"
                                : apiTestForm.body || "(empty)"
                            }
                          ]}
                          maskSensitive={maskSensitive}
                        />
                      </div>
                      <div className="tool-result">
                        <strong>Response</strong>
                        <span>
                          {apiTestResult.status} {apiTestResult.statusText || ""}
                        </span>
                        <CodeBlock
                          sections={[
                            { label: "Headers", content: prettyJson(apiTestResult.headers) },
                            { label: "Body", content: apiTestResult.body || "(empty)" }
                          ]}
                          maskSensitive={maskSensitive}
                        />
                      </div>
                    </div>
                  ) : null}
                  {apiCapturedExchanges.length > 0 ? (
                    <div className="candidate-list">
                      <strong>Captured Requests ({apiCapturedExchanges.length})</strong>
                      {apiCapturedExchanges.map((exchange) => (
                        <button
                          key={exchange.id}
                          type="button"
                          className="candidate-row"
                          onClick={() => loadApiTestFromExchange(exchange)}
                        >
                          <span className="candidate-method">{exchange.request?.method || "GET"}</span>
                          <div className="candidate-main">
                            <strong>{exchange.request?.url || exchange.response?.url || "-"}</strong>
                            <small>
                              {exchange.request?.resourceType || "request"} ·{" "}
                              {exchange.response?.status || "pending"}
                            </small>
                          </div>
                        </button>
                      ))}
                    </div>
                  ) : null}
                </div>
              </article>
            </section>
          ) : null}

          {activeSection === "settings" ? (
            <section className="pair-list">
              <article className="panel stacked-panel">
                <div className="tool-panel section-panel">
                  <strong>OpenAI Summary Settings</strong>
                  <p className="tool-copy">
                    캡처가 자동 완료되거나 `캡처 중지`로 종료되면 아래 설정으로 HTTP Summary를 자동 생성합니다. API Key는 이 브라우저의 localStorage에만 보관하고 서버/DB에는 저장하지 않습니다.
                  </p>
                  <div className="tool-grid-2">
                    <label className="field-label field-card">
                      <span>OPENAI KEY</span>
                      <input
                        type="password"
                        autoComplete="off"
                        placeholder="sk-..."
                        value={openAiKey}
                        onChange={(event) => setOpenAiKey(event.target.value)}
                      />
                    </label>
                    <label className="field-label field-card">
                      <span>MODEL</span>
                      <input
                        type="text"
                        placeholder="gpt-4.1-mini"
                        value={openAiModel}
                        onChange={(event) => setOpenAiModel(event.target.value)}
                      />
                    </label>
                  </div>
                  <label className="field-label field-card">
                    <span>PROMPT</span>
                    <textarea
                      rows={12}
                      value={openAiPrompt}
                      onChange={(event) => setOpenAiPrompt(event.target.value)}
                    />
                  </label>
                  <div className="action-row">
                    <button
                      type="button"
                      disabled={aiSummaryLoading || !openAiKey.trim()}
                      onClick={() =>
                        requestOpenAiSummary(
                          {
                            targetUrl: domain || "",
                            exchanges: analyzedExchanges,
                            errors
                          },
                          {
                            sessionId: captureSessionId || "",
                            source: "manual"
                          }
                        )
                      }
                    >
                      {aiSummaryLoading ? "Summary 생성 중..." : "현재 데이터로 Summary 생성"}
                    </button>
                    <button type="button" onClick={() => setOpenAiPrompt(DEFAULT_OPENAI_SUMMARY_PROMPT)}>
                      기본 프롬프트 복원
                    </button>
                  </div>
                  {aiSummaryError ? <div className="error-strip">{aiSummaryError}</div> : null}
                  {aiSummary ? (
                    <div className="tool-result">
                      <strong>OpenAI Summary</strong>
                      <pre>{aiSummary}</pre>
                    </div>
                  ) : null}
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
                              {isSqlmapRelevantFinding(finding) ? (
                                <button type="button" onClick={() => openSqlmapFromFinding(exchange)}>
                                  SQLMap에서 열기
                                </button>
                              ) : null}
                              <button
                                type="button"
                                className="tooltip-button"
                                data-tooltip="현재 브라우저 세션에서만 이 finding을 숨깁니다. 새로고침/새 캡처 후에는 다시 보일 수 있습니다."
                                title="현재 브라우저 세션에서만 이 finding을 숨깁니다."
                                aria-label="세션 오탐: 현재 브라우저 세션에서만 숨김"
                                onClick={() => suppressFindingByScope("session", finding, exchange)}
                              >
                                세션 오탐
                              </button>
                              <button
                                type="button"
                                className="tooltip-button"
                                data-tooltip="같은 엔드포인트에서 발생한 동일 finding을 앞으로 숨깁니다. 예: /api/users 단위"
                                title="같은 엔드포인트에서 발생한 동일 finding을 숨깁니다."
                                aria-label="엔드포인트 오탐: 같은 엔드포인트의 동일 finding 숨김"
                                onClick={() => suppressFindingByScope("endpoint", finding, exchange)}
                              >
                                엔드포인트 오탐
                              </button>
                              <button
                                type="button"
                                className="tooltip-button"
                                data-tooltip="같은 호스트에서 발생한 동일 finding을 숨깁니다. 예: api.example.com 전체"
                                title="같은 호스트에서 발생한 동일 finding을 숨깁니다."
                                aria-label="호스트 오탐: 같은 호스트의 동일 finding 숨김"
                                onClick={() => suppressFindingByScope("host", finding, exchange)}
                              >
                                호스트 오탐
                              </button>
                              <button
                                type="button"
                                className="tooltip-button"
                                data-tooltip="모든 요청에서 동일 finding 유형을 숨깁니다. 가장 넓은 범위라 신중하게 사용하세요."
                                title="모든 요청에서 동일 finding 유형을 숨깁니다."
                                aria-label="전역 오탐: 모든 요청에서 동일 finding 유형 숨김"
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
                      아직 캡처된 요청이 없습니다. Domain을 입력하고 캡처를 시작해보세요.
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
                                    {" / "}Low {securityFindings.filter((item) => item.severity === "low").length}
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

          {activeSection === "checklist" ? (
            <section className="pair-list">
              <article className="panel stacked-panel capture-checklist-panel">
                <div className="capture-checklist-head">
                  <strong>Vulnerability Checklist</strong>
                  <span>
                    {checklistRows.length > 0
                      ? `현재 Findings를 기준으로 ${checklistRows.length}개의 취약점 유형을 묶어 표시합니다.`
                      : "일반적인 웹 취약점 범주를 기준으로 수동 점검용 행을 표시합니다."}
                  </span>
                </div>
                <div className="capture-checklist-rows">
                  {renderedChecklistRows.map((item) => (
                    <article key={item.key} className="capture-checklist-row">
                      <div className="capture-checklist-row-head">
                        <div className="capture-checklist-row-title">
                          <strong>{item.title}</strong>
                          <div className="capture-checklist-row-meta">
                            <span className={`severity-chip severity-chip-${item.highestSeverity}`}>
                              {item.highestSeverityLabel}
                            </span>
                            <span className="security-summary-pill">{item.owaspLabel}</span>
                            <span className="security-summary-pill">
                              {item.count > 0 ? `Finding ${item.count}건` : "수동 점검"}
                            </span>
                          </div>
                        </div>
                        <span className="capture-checklist-row-confidence">{item.confidence}</span>
                      </div>
                      <div className="capture-checklist-row-line">
                        <div className="capture-checklist-row-cell cell-summary">
                          <span className="capture-checklist-row-label">설명</span>
                          <p>{item.description || "저장된 설명이 없습니다."}</p>
                        </div>
                        <div className="capture-checklist-row-cell cell-evidence">
                          <span className="capture-checklist-row-label">근거</span>
                          <ul>
                            {((item.evidences || []).length > 0 ? item.evidences : ["저장된 근거가 없습니다."]).map((evidence) => (
                              <li key={evidence}>{evidence}</li>
                            ))}
                          </ul>
                        </div>
                        <div className="capture-checklist-row-cell cell-example">
                          <span className="capture-checklist-row-label">공격 예시</span>
                          <code>{item.attackExample}</code>
                        </div>
                        <div className="capture-checklist-row-cell cell-remediation">
                          <span className="capture-checklist-row-label">권장 조치</span>
                          <p>{item.remediation || "동작을 재현한 뒤 관련 코드 또는 설정 수정 우선순위를 정리하세요."}</p>
                        </div>
                      </div>
                      {(item.checklist || []).length > 0 ? (
                        <div className="capture-checklist-row-footer">
                          {(item.checklist || []).map((check) => (
                            <span key={check} className="security-summary-pill">
                              {check}
                            </span>
                          ))}
                        </div>
                      ) : null}
                      {(item.identifiedFindings || []).length > 0 ? (
                        <div className="capture-checklist-row-identified">
                          <span className="capture-checklist-row-label">식별된 Findings</span>
                          <div className="capture-checklist-row-footer">
                            {(item.identifiedFindings || []).map((title) => (
                              <span key={title} className="security-summary-pill">
                                {title}
                              </span>
                            ))}
                          </div>
                        </div>
                      ) : null}
                    </article>
                  ))}
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
      <NoticeModal
        title="로그인 실패"
        message={loginFailureModal}
        onClose={() => setLoginFailureModal("")}
      />
    </main>
  );
}
