import { useEffect, useState } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:4000";
const TOKEN_REGEX = new RegExp(
  `("(?:\\\\.|[^"])*":)|("(?:\\\\.|[^"])*")|('(?:\\\\.|[^'])*')|(<!--.*?-->)|(<!DOCTYPE[^>]*>)|(</?[\\w:-]+[^>]*>)|\\b\\d+(?:\\.\\d+)?\\b|\\btrue\\b|\\bfalse\\b|\\bnull\\b|[{}\\[\\](),:]`,
  "g"
);
const SECURITY_REGEX =
  /\b(authorization|cookie|set-cookie|token|bearer|csrf|password|secret|session|jwt|api[-_ ]?key)\b/i;
const SECURITY_REASON_REGEX =
  /\b(authorization|cookie|set-cookie|token|bearer|csrf|password|secret|session|jwt|api[-_ ]?key)\b/gi;

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

function CodeBlock({ sections }) {
  const lines = sections.flatMap((section) => {
    const contentLines = (section.content || "(empty)").split("\n");
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

function getSecurityReasons(exchange) {
  const text = [
    exchange.request?.url || "",
    prettyJson(exchange.request?.headers),
    exchange.request?.postData || "",
    exchange.response?.url || "",
    prettyJson(exchange.response?.headers),
    exchange.response?.bodyPreview || ""
  ].join("\n");

  const matches = text.match(SECURITY_REASON_REGEX) || [];
  return [...new Set(matches.map((value) => value.toLowerCase()))];
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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

function ReplayModal({
  modalState,
  setModalState,
  replayResponse,
  replayLoading,
  replayError,
  onReplay
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
            />
          </section>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [domain, setDomain] = useState(
    () => window.localStorage.getItem("http-analyzer-domain") || ""
  );
  const [excludeInput, setExcludeInput] = useState(
    () => window.localStorage.getItem("http-analyzer-exclude-patterns") || ""
  );
  const [securityOnly, setSecurityOnly] = useState(
    () => window.localStorage.getItem("http-analyzer-security-only") === "true"
  );
  const [statusMessage, setStatusMessage] = useState("");
  const [active, setActive] = useState(false);
  const [exchanges, setExchanges] = useState([]);
  const [errors, setErrors] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [modalState, setModalState] = useState(null);
  const [replayResponse, setReplayResponse] = useState(null);
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayError, setReplayError] = useState("");

  const liveExcludePatterns = excludeInput
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  const visibleExchanges = exchanges.filter((exchange) => {
    const requestText = [
      exchange.request?.url || "",
      prettyJson(exchange.request?.headers),
      exchange.request?.postData || ""
    ].join("\n");
    const responseText = [
      exchange.response?.url || "",
      prettyJson(exchange.response?.headers),
      exchange.response?.bodyPreview || ""
    ].join("\n");

    if (securityOnly && !SECURITY_REGEX.test(`${requestText}\n${responseText}`)) {
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

  useEffect(() => {
    const timer = window.setInterval(async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/capture/status`);
        if (!response.ok) return;
        const data = await response.json();
        setActive(Boolean(data.active));
        setExchanges(data.exchanges || []);
        setErrors(data.errors || []);
      } catch {
        return;
      }
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    window.localStorage.setItem("http-analyzer-domain", domain);
  }, [domain]);

  useEffect(() => {
    window.localStorage.setItem("http-analyzer-exclude-patterns", excludeInput);
  }, [excludeInput]);

  useEffect(() => {
    window.localStorage.setItem("http-analyzer-security-only", String(securityOnly));
  }, [securityOnly]);

  async function startCapture(event) {
    event.preventDefault();
    setSubmitting(true);
    setStatusMessage("");

    try {
      const excludePatterns = excludeInput
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);

      const response = await fetch(`${API_BASE_URL}/api/capture/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, excludePatterns })
      });

      const { data, rawText } = await readJsonSafely(response);
      if (!response.ok) {
        throw new Error(data?.error || rawText || "캡처 시작에 실패했습니다.");
      }

      const result = data || {};

      setStatusMessage("");
      setExchanges([]);
      setErrors([]);
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function stopCapture() {
    setSubmitting(true);
    setStatusMessage("");

    try {
      await fetch(`${API_BASE_URL}/api/capture/stop`, { method: "POST" });
      setStatusMessage("");
      setActive(false);
    } catch (error) {
      setStatusMessage(error.message);
    } finally {
      setSubmitting(false);
    }
  }

  function downloadHtmlReport() {
    const sections = visibleExchanges
      .map((exchange, index) => {
        const requestTitle = exchange.request
          ? `${exchange.request.method} ${exchange.request.url}`
          : "(request unavailable)";
        const requestMeta = exchange.request
          ? `${exchange.request.resourceType} · ${exchange.timestamp}`
          : exchange.timestamp;
        const responseTitle = exchange.response
          ? `${exchange.response.status} ${exchange.response.url}`
          : "(pending response)";
        const responseMeta = exchange.response
          ? `${exchange.response.statusText} · ${exchange.response.timestamp}`
          : "";

        return `
          <section class="pair-card">
            <div class="pair-index">#${index + 1}</div>
            <div class="pair-grid">
              <article class="box request">
                <div class="chip request-chip">REQUEST</div>
                <h3>${escapeHtml(requestTitle)}</h3>
                <p class="meta">${escapeHtml(requestMeta)}</p>
                <pre>${escapeHtml(`Headers\n${prettyJson(exchange.request?.headers)}\n\nBody\n${
                  exchange.request?.postData || "(empty)"
                }`)}</pre>
              </article>
              <article class="box response">
                <div class="chip response-chip">RESPONSE</div>
                <h3>${escapeHtml(responseTitle)}</h3>
                <p class="meta">${escapeHtml(responseMeta)}</p>
                <pre>${escapeHtml(`Headers\n${prettyJson(exchange.response?.headers)}\n\nBody Preview\n${
                  exchange.response?.bodyPreview || "(binary, empty, or pending)"
                }`)}</pre>
              </article>
            </div>
          </section>
        `;
      })
      .join("");

    const html = `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HTTP Analyzer Report</title>
  <style>
    body{margin:0;padding:24px;background:#eef2f6;color:#172033;font-family:"KoPubDotum","KoPub돋움체",sans-serif}
    .wrap{max-width:1400px;margin:0 auto}
    .hero{padding:20px 24px;border-radius:16px;background:#fff;border:1px solid #d8e0ea;box-shadow:0 12px 32px rgba(15,23,42,.08)}
    .hero h1{margin:0 0 8px;font-size:28px}
    .hero p{margin:4px 0;color:#475569}
    .pair-card{margin-top:16px;padding:16px;border-radius:16px;background:#fff;border:1px solid #d8e0ea;box-shadow:0 10px 24px rgba(15,23,42,.06)}
    .pair-index{margin-bottom:10px;font-weight:700;color:#64748b}
    .pair-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
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
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>HTTP Analyzer Report</h1>
      <p><strong>Domain:</strong> ${escapeHtml(domain || "-")}</p>
      <p><strong>Excluded:</strong> ${escapeHtml(excludeInput || "-")}</p>
      <p><strong>Security Check:</strong> ${securityOnly ? "ON" : "OFF"}</p>
      <p><strong>Visible Pairs:</strong> ${visibleExchanges.length}</p>
    </section>
    ${sections}
  </div>
</body>
</html>`;

    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const blobUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = blobUrl;
    anchor.download = `http-analyzer-report-${Date.now()}.html`;
    anchor.click();
    URL.revokeObjectURL(blobUrl);
  }

  function openReplayModal(exchange) {
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

  return (
    <main className="page-shell">
      <section className="hero-card filter-shell">
        <div className="topbar">
          <div>
            <h1 className="page-title">HTTP Analyzer</h1>
          </div>
          <div className="topbar-badges">
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
          </div>
        </div>

        <form className="capture-form filter-bar" onSubmit={startCapture}>
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
              placeholder="제외 패턴 입력"
              value={excludeInput}
              onChange={(event) => setExcludeInput(event.target.value)}
            />
          </label>
          <div className="action-row action-card">
            <button type="submit" disabled={submitting || active}>
              {submitting ? "처리 중..." : "캡처 시작"}
            </button>
            <button type="button" disabled={submitting || !active} onClick={stopCapture}>
              캡처 중지
            </button>
            <button type="button" disabled={visibleExchanges.length === 0} onClick={downloadHtmlReport}>
              HTML 출력
            </button>
          </div>
        </form>

        {statusMessage ? <p className="status">{statusMessage}</p> : null}
        {errors.length > 0 ? (
          <div className="error-strip">{errors[errors.length - 1]?.errorText}</div>
        ) : null}
      </section>

      <section className="pair-list">
        <article className="panel">
          <div className="entry-list">
            {visibleExchanges
              .slice()
              .reverse()
              .map((exchange) => (
                <article key={exchange.id} className="exchange-card">
                  {getSecurityReasons(exchange).length > 0 ? (
                    <div className="security-reason-bar">
                      <strong>Security Check Reason:</strong>
                      <span>{getSecurityReasons(exchange).join(", ")}</span>
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
                        <span className="url-line">{exchange.request.url}</span>
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
                    />
                  </button>

                  <div className="exchange-column">
                    <div className="entry-title-row">
                      <span className="panel-chip response-chip">RESPONSE</span>
                      <strong>
                        {exchange.response ? String(exchange.response.status) : "(pending response)"}
                      </strong>
                      {exchange.response?.url ? (
                        <span className="url-line">{exchange.response.url}</span>
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
                    />
                  </div>
                </article>
              ))}
          </div>
        </article>
      </section>

      <ReplayModal
        modalState={modalState}
        setModalState={setModalState}
        replayResponse={replayResponse}
        replayLoading={replayLoading}
        replayError={replayError}
        onReplay={replayRequest}
      />
    </main>
  );
}
