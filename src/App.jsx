import { useEffect, useState } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:4000";
const TOKEN_REGEX = new RegExp(
  `("(?:\\\\.|[^"])*":)|("(?:\\\\.|[^"])*")|('(?:\\\\.|[^'])*')|(<!--.*?-->)|(<!DOCTYPE[^>]*>)|(</?[\\w:-]+[^>]*>)|\\b\\d+(?:\\.\\d+)?\\b|\\btrue\\b|\\bfalse\\b|\\bnull\\b|[{}\\[\\](),:]`,
  "g"
);
const SECURITY_REGEX =
  /\b(authorization|cookie|set-cookie|token|bearer|csrf|password|secret|session|jwt|api[-_ ]?key)\b/i;

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
    () => window.localStorage.getItem("http-viewer-domain") || ""
  );
  const [excludeInput, setExcludeInput] = useState(
    () => window.localStorage.getItem("http-viewer-exclude-patterns") || ""
  );
  const [securityOnly, setSecurityOnly] = useState(
    () => window.localStorage.getItem("http-viewer-security-only") === "true"
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
    window.localStorage.setItem("http-viewer-domain", domain);
  }, [domain]);

  useEffect(() => {
    window.localStorage.setItem("http-viewer-exclude-patterns", excludeInput);
  }, [excludeInput]);

  useEffect(() => {
    window.localStorage.setItem("http-viewer-security-only", String(securityOnly));
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
            <h1 className="page-title">HTTP Capture Console</h1>
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
            <span>URL</span>
            <input
              type="text"
              placeholder="도메인 입력"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
            />
          </label>
          <label className="field-label field-card">
            <span>Excluded</span>
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
          </div>
        </form>

        {statusMessage ? <p className="status">{statusMessage}</p> : null}
        {errors.length > 0 ? (
          <div className="error-strip">{errors[errors.length - 1]?.errorText}</div>
        ) : null}
      </section>

      <section className="pair-list">
        <article className="panel">
          <div className="panel-header">
            <span>{visibleExchanges.length}</span>
          </div>
          <div className="entry-list">
            {visibleExchanges
              .slice()
              .reverse()
              .map((exchange) => (
                <article key={exchange.id} className="exchange-card">
                  <button
                    type="button"
                    className="exchange-column interactive-column"
                    onClick={() => openReplayModal(exchange)}
                  >
                    <div className="entry-title-row">
                      <span className="panel-chip request-chip">REQUEST</span>
                      <strong>
                        {exchange.request
                          ? `${exchange.request.method} ${exchange.request.url}`
                          : "(request unavailable)"}
                      </strong>
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
                        {exchange.response
                          ? `${exchange.response.status} ${exchange.response.url}`
                          : "(pending response)"}
                      </strong>
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
