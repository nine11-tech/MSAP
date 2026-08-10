import { useEffect, useMemo, useState } from "react";
import {
  getFindingSourceReferences,
  getSourceLines,
} from "../api/msap";
import type {
  FindingSourceReference,
  SourceDocument,
  SourceLineRange,
} from "../api/types";
import { EmptyState, ErrorMessage, LoadingState, errorMessage } from "./Common";

function referenceText(reference: FindingSourceReference) {
  const prefix = reference.representation_type.startsWith("JADX")
    ? "JADX"
    : reference.representation_type;
  const location = reference.source_lines_available
    ? `#L${reference.start_line}-L${reference.end_line}`
    : reference.start_offset !== null
      ? `#offset-${reference.start_offset}`
      : "";
  return `${prefix}:${reference.logical_path}${location}`;
}

function excerptLines(reference: FindingSourceReference) {
  const configuredStart = Number(reference.locator.excerpt_start_line);
  const start = Number.isFinite(configuredStart)
    ? configuredStart
    : reference.start_line || 1;
  return reference.excerpt.split("\n").map((text, index) => ({
    number: start + index,
    text,
  }));
}

export function CodeEvidenceViewer({
  reference,
}: {
  reference: FindingSourceReference;
}) {
  const [open, setOpen] = useState(false);
  const [range, setRange] = useState<SourceLineRange | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const preview = useMemo(() => excerptLines(reference), [reference]);

  async function openCode() {
    if (!reference.source_document || reference.start_line === null) return;
    setOpen(true);
    if (range) return;
    const excerptStart = Number(reference.locator.excerpt_start_line);
    const excerptEnd = Number(reference.locator.excerpt_end_line);
    const start = Number.isFinite(excerptStart)
      ? Math.max(1, excerptStart - 12)
      : Math.max(1, reference.start_line - 16);
    const end = Number.isFinite(excerptEnd)
      ? excerptEnd + 30
      : (reference.end_line || reference.start_line) + 40;
    const boundedEnd = reference.source_document_line_count
      ? Math.min(reference.source_document_line_count, end)
      : end;
    setLoading(true);
    setError("");
    try {
      setRange(
        await getSourceLines(
          reference.source_document,
          start,
          Math.min(start + 199, boundedEnd),
        ),
      );
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  async function copyReference() {
    await navigator.clipboard.writeText(referenceText(reference));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  const shownLines = open && range ? range.lines : preview;
  return (
    <article className={`source-evidence-card ${reference.is_primary ? "primary" : ""}`}>
      <header>
        <div>
          <span className="source-representation">
            {reference.representation_label}
          </span>
          {reference.is_primary ? <span className="source-primary">Primary</span> : null}
        </div>
        <span className="source-confidence">{reference.confidence} confidence</span>
      </header>
      <dl className="source-reference-meta">
        <div><dt>Path</dt><dd className="mono">{reference.logical_path}</dd></div>
        {reference.class_name ? <div><dt>Class</dt><dd>{reference.class_name}</dd></div> : null}
        {reference.method_name ? <div><dt>Method</dt><dd>{reference.method_name}</dd></div> : null}
        {reference.symbol_name ? <div><dt>Symbol</dt><dd>{reference.symbol_name}</dd></div> : null}
        <div>
          <dt>Location</dt>
          <dd>
            {reference.source_lines_available
              ? `Lines ${reference.start_line}–${reference.end_line}`
              : reference.start_offset !== null
                ? `Offset ${reference.start_offset}`
                : "Source lines not applicable"}
          </dd>
        </div>
        {reference.source_document_sha256 ? (
          <div><dt>Document SHA-256</dt><dd className="mono">{reference.source_document_sha256.slice(0, 16)}…</dd></div>
        ) : null}
      </dl>

      {reference.source_lines_available ? (
        <>
          {loading ? <LoadingState label="Loading bounded source range…" /> : null}
          {error ? <ErrorMessage message={error} /> : null}
          {!loading && shownLines.length ? (
            <div className="code-evidence-panel" role="region" aria-label="Read-only source evidence">
              {shownLines.map((line) => {
                const highlighted =
                  reference.start_line !== null &&
                  reference.end_line !== null &&
                  line.number >= reference.start_line &&
                  line.number <= reference.end_line;
                return (
                  <div className={highlighted ? "code-line evidence-line" : "code-line"} key={line.number}>
                    <span className="line-number">{line.number}</span>
                    <code>{line.text || " "}</code>
                  </div>
                );
              })}
            </div>
          ) : null}
          <p className="source-provenance">{reference.provenance}</p>
        </>
      ) : (
        <p className="source-unavailable">
          <strong>Source lines not applicable.</strong> {reference.unavailable_reason}
        </p>
      )}

      <div className="inline-actions source-actions">
        {reference.source_lines_available ? (
          <button className="button button-secondary" onClick={() => void openCode()}>
            {open ? "Code range open" : "Open in Code"}
          </button>
        ) : null}
        <button className="button button-secondary" onClick={() => void copyReference()}>
          {copied ? "Reference copied" : "Copy Reference"}
        </button>
      </div>
    </article>
  );
}

export function FindingSourceEvidence({ findingId }: { findingId: number }) {
  const [references, setReferences] = useState<FindingSourceReference[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getFindingSourceReferences(findingId)
      .then((data) => {
        if (!cancelled) setReferences(data);
      })
      .catch((requestError) => {
        if (!cancelled) setError(errorMessage(requestError));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [findingId]);

  return (
    <section className="finding-source-section">
      <h3>Source Evidence</h3>
      {loading ? <LoadingState label="Loading source provenance…" /> : null}
      {error ? <ErrorMessage message={error} /> : null}
      {!loading && !error && !references.length ? (
        <EmptyState message="No source-provenance reference was recorded." />
      ) : null}
      <div className="source-evidence-stack">
        {references.map((reference) => (
          <CodeEvidenceViewer reference={reference} key={reference.id} />
        ))}
      </div>
    </section>
  );
}

export function AuditSourceBrowser({ documents }: { documents: SourceDocument[] }) {
  const [selected, setSelected] = useState<SourceDocument | null>(documents[0] || null);
  const [range, setRange] = useState<SourceLineRange | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setSelected((current) => current || documents[0] || null);
  }, [documents]);

  useEffect(() => {
    if (!selected || !selected.line_count) {
      setRange(null);
      return;
    }
    let cancelled = false;
    setRange(null);
    setError("");
    getSourceLines(selected.id, 1, Math.min(200, selected.line_count))
      .then((data) => { if (!cancelled) setRange(data); })
      .catch((requestError) => { if (!cancelled) setError(errorMessage(requestError)); });
    return () => { cancelled = true; };
  }, [selected]);

  if (!documents.length) {
    return <EmptyState message="No decoded or decompiled source documents are indexed for this audit." />;
  }
  return (
    <div className="source-browser">
      <nav className="source-document-list" aria-label="Indexed source documents">
        {documents.map((document) => (
          <button
            className={selected?.id === document.id ? "active" : ""}
            key={document.id}
            onClick={() => setSelected(document)}
          >
            <strong>{document.display_path || document.logical_path}</strong>
            <span>{document.representation_label} · {document.line_count} lines</span>
          </button>
        ))}
      </nav>
      <section className="source-browser-viewer">
        {selected ? (
          <header>
            <div><span className="source-representation">{selected.representation_label}</span><strong className="mono">{selected.logical_path}</strong></div>
            <span className="mono">{selected.sha256.slice(0, 16)}…</span>
          </header>
        ) : null}
        {error ? <ErrorMessage message={error} /> : null}
        {selected && !range && !error ? <LoadingState label="Loading first 200 lines…" /> : null}
        {range ? (
          <div className="code-evidence-panel audit-source-code">
            {range.lines.map((line) => (
              <div className="code-line" key={line.number}>
                <span className="line-number">{line.number}</span><code>{line.text || " "}</code>
              </div>
            ))}
          </div>
        ) : null}
        {selected && selected.line_count > 200 ? <p className="muted">Showing the first bounded 200-line range.</p> : null}
      </section>
    </div>
  );
}
