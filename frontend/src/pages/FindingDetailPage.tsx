import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import { FindingStatusBadge, RiskBadge, SeverityBadge } from "../components/Badges";
import { formatDateTime, humanize, shortType } from "../components/format";
import { Card, JsonBlock, Loaded, ScrollX, buttonClass, inputClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ApiError } from "../services/api";
import { getFinding, updateFindingStatus } from "../services/findings";
import { FINDING_STATUSES, type FindingDetail, type FindingStatus, type RiskBreakdown } from "../types/api";

const FACTORS = ["severity", "exposure", "impact", "confidence"] as const;

function RiskExplanation({ breakdown }: { breakdown: RiskBreakdown }) {
  return (
    <ScrollX>
    <table className="w-full text-left text-sm">
      <thead className="text-slate-600">
        <tr>
          <th className="py-1 pr-3 font-medium">Factor</th>
          <th className="py-1 pr-3 font-medium">Level</th>
          <th className="py-1 pr-3 text-right font-medium">Points</th>
          <th className="py-1 font-medium">Why</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-100">
        {FACTORS.map((name) => {
          const factor = breakdown[name];
          return (
            <tr key={name}>
              <td className="py-1.5 pr-3">{humanize(name)}</td>
              <td className="py-1.5 pr-3">{humanize(factor.level)}</td>
              <td className="py-1.5 pr-3 text-right tabular-nums">
                {factor.points > 0 ? `+${factor.points}` : factor.points}
              </td>
              <td className="py-1.5 text-slate-600">{factor.reason ?? "From the rule"}</td>
            </tr>
          );
        })}
        <tr className="font-semibold">
          <td className="whitespace-nowrap py-1.5 pr-3" colSpan={2}>
            Risk score · {breakdown.priority}
          </td>
          <td className="py-1.5 pr-3 text-right tabular-nums">{breakdown.score}</td>
          <td className="py-1.5 text-xs font-normal text-slate-500">
            Out of 100 (scoring model version {breakdown.model_version})
          </td>
        </tr>
      </tbody>
    </table>
    </ScrollX>
  );
}

function describeTriageError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return "Your role cannot change findings.";
    if (error.status === 422) return "Check the note: a false positive needs a reason, at most 500 characters.";
  }
  return "Could not save the status. Please try again.";
}

function TriageForm({ finding, onSaved }: { finding: FindingDetail; onSaved: (f: FindingDetail) => void }) {
  const [status, setStatus] = useState<FindingStatus>(finding.status);
  const [note, setNote] = useState(finding.status_note ?? "");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaved(false);
    if (status === "FALSE_POSITIVE" && !note.trim()) {
      setError("Explain why this is a false positive.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      onSaved(await updateFindingStatus(finding.id, status, note));
      setSaved(true);
    } catch (caught) {
      setError(describeTriageError(caught));
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <div>
        <label htmlFor="triage-status" className="block text-sm font-medium">
          Status
        </label>
        <select
          id="triage-status"
          value={status}
          onChange={(event) => setStatus(event.target.value as FindingStatus)}
          className={`${inputClass} mt-1 w-full`}
        >
          {FINDING_STATUSES.map((value) => (
            <option key={value} value={value}>
              {humanize(value)}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="triage-note" className="block text-sm font-medium">
          Note {status === "FALSE_POSITIVE" ? "(required)" : "(optional)"}
        </label>
        <textarea
          id="triage-note"
          value={note}
          maxLength={500}
          rows={3}
          onChange={(event) => setNote(event.target.value)}
          className={`${inputClass} mt-1 w-full`}
        />
      </div>
      {error && (
        <p role="alert" className="text-sm text-red-700">
          {error}
        </p>
      )}
      {saved && (
        <p role="status" className="text-sm text-emerald-700">
          Saved.
        </p>
      )}
      <button type="submit" disabled={saving} className={buttonClass}>
        Save status
      </button>
      <p className="text-xs text-slate-500">
        A later scan reopens a resolved finding if the problem is still there. Acknowledged and
        false-positive decisions are kept.
      </p>
    </form>
  );
}

function Detail({ finding, onChange }: { finding: FindingDetail; onChange: (f: FindingDetail) => void }) {
  const { state } = useAuth();
  const canTriage =
    state.status === "authenticated" && (state.user.role === "ANALYST" || state.user.role === "ADMIN");
  const rule = finding.rule;

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm">
          <Link to="/findings" className="underline">
            Findings
          </Link>{" "}
          / {finding.rule_id}
        </p>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">{finding.title}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RiskBadge score={finding.risk_score} />
          <SeverityBadge severity={finding.severity} />
          <FindingStatusBadge status={finding.status} />
          <span className="text-sm text-slate-600">{humanize(finding.category)}</span>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card title="Resource">
            <dl className="grid grid-cols-[8rem_1fr] gap-y-1 text-sm">
              <dt className="text-slate-600">Name</dt>
              <dd>{finding.resource_name ?? "—"}</dd>
              <dt className="text-slate-600">ID</dt>
              <dd className="break-all font-mono text-xs">
                <Link to={`/resources/${finding.resource_uuid}`} className="underline">
                  {finding.resource_id}
                </Link>
              </dd>
              <dt className="text-slate-600">Type</dt>
              <dd>{shortType(finding.resource_type)}</dd>
              <dt className="text-slate-600">Region</dt>
              <dd>{finding.region}</dd>
            </dl>
          </Card>

          {rule && (
            <Card title="Why it matters">
              <p className="text-sm text-slate-800">{rule.rationale}</p>
              <p className="mt-2 text-sm text-slate-600">{rule.description}</p>
            </Card>
          )}

          <Card title="Evidence">
            <p className="mb-2 text-xs text-slate-500">
              Taken from the configuration read by the scan. Nothing here is guessed.
            </p>
            <JsonBlock value={finding.evidence} />
          </Card>

          <Card title="Risk explanation">
            {finding.risk_breakdown ? (
              <RiskExplanation breakdown={finding.risk_breakdown} />
            ) : (
              <p className="text-sm text-slate-600">Not scored yet. The next scan that detects it will score it.</p>
            )}
          </Card>

          {rule && (
            <Card title="Remediation">
              <p className="whitespace-pre-line text-sm text-slate-800">{rule.remediation}</p>
              {rule.references.length > 0 && (
                <ul className="mt-3 list-disc pl-5 text-sm">
                  {rule.references
                    .filter((reference) => reference.url.startsWith("https://"))
                    .map((reference) => (
                      <li key={reference.url}>
                        <a href={reference.url} target="_blank" rel="noopener noreferrer" className="underline">
                          {reference.title}
                        </a>
                      </li>
                    ))}
                </ul>
              )}
            </Card>
          )}
        </div>

        <div className="space-y-6">
          <Card title="Triage">
            {finding.status_note && (
              <p className="mb-3 text-sm">
                <span className="text-slate-600">Last note: </span>
                {finding.status_note}
                <span className="block text-xs text-slate-500">
                  {finding.status_updated_by_id ? "By an analyst" : "By a scan"},{" "}
                  {formatDateTime(finding.status_updated_at)}
                </span>
              </p>
            )}
            {canTriage ? (
              <TriageForm key={finding.id} finding={finding} onSaved={onChange} />
            ) : (
              <p className="text-sm text-slate-600">Viewers can read findings; analysts and admins can triage them.</p>
            )}
          </Card>

          {rule && (
            <Card title="Detection rule">
              <p className="text-sm font-medium">
                {rule.id}: {rule.title}
              </p>
              {rule.severity_note && <p className="mt-2 text-sm text-slate-600">{rule.severity_note}</p>}
              {rule.limitations && (
                <p className="mt-2 text-sm text-slate-600">
                  <span className="font-medium text-slate-700">Not checked: </span>
                  {rule.limitations}
                </p>
              )}
            </Card>
          )}

          <Card title="Scan history">
            <dl className="grid grid-cols-[7rem_1fr] gap-y-1 text-sm">
              <dt className="text-slate-600">First detected</dt>
              <dd>
                {finding.first_scan_id ? (
                  <Link to={`/scans/${finding.first_scan_id}`} className="underline">
                    {formatDateTime(finding.first_detected)}
                  </Link>
                ) : (
                  formatDateTime(finding.first_detected)
                )}
              </dd>
              <dt className="text-slate-600">Last detected</dt>
              <dd>
                {finding.last_scan_id ? (
                  <Link to={`/scans/${finding.last_scan_id}`} className="underline">
                    {formatDateTime(finding.last_detected)}
                  </Link>
                ) : (
                  formatDateTime(finding.last_detected)
                )}
              </dd>
              {finding.resolved_at && (
                <>
                  <dt className="text-slate-600">Resolved</dt>
                  <dd>{formatDateTime(finding.resolved_at)}</dd>
                </>
              )}
            </dl>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function FindingDetailPage() {
  const { findingId = "" } = useParams();
  const { state, reload, setState } = useApi(() => getFinding(findingId), findingId);
  return (
    <section>
      <Loaded state={state} what="finding" onRetry={reload}>
        {(finding) => <Detail finding={finding} onChange={(data) => setState({ kind: "loaded", data })} />}
      </Loaded>
    </section>
  );
}
