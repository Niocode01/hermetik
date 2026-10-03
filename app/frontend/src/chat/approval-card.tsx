// Tasks 13+14 — Tarjeta de aprobación inline + reglas `always` auditables.
//
// - ApprovalCard: muestra comando redactado+recortado (displayCommand), tool,
//   cuenta atrás del timeout y 4 botones (once/session/always/deny).
// - AlwaysRulesSection (Task 14): lista decisiones `always` guardadas en la
//   bóveda (VaultPayload.alwaysApprovals) con botón Revocar cada una.

import { useState } from "react";
import {
  approvalButtons,
  approvalSecondsLeft,
  displayCommand,
  isApprovalTimedOut,
  scopeKeyForApproval,
  type AlwaysApprovalRule,
  type PendingApproval,
} from "./approvals";
import type { ApprovalChoice } from "../gateway/types";
import { useI18n } from "../i18n";

export interface ApprovalCardProps {
  approval: PendingApproval;
  busyChoice?: ApprovalChoice | null;
  error?: string;
  onRespond: (runId: string, choice: ApprovalChoice, scopeKey: string) => void;
}

export function ApprovalCard({ approval, busyChoice = null, error = "", onRespond }: ApprovalCardProps) {
  const { t } = useI18n();
  const [now, setNow] = useState(() => Date.now());
  const timedOut = isApprovalTimedOut(approval, now);
  const left = approvalSecondsLeft(approval, now);
  const scopeKey = scopeKeyForApproval(approval);

  // Tictac ligero para la cuenta atrás (1/s); se detiene al responder.
  const tick = () => setNow(Date.now());

  return (
    <article aria-label={`${t("approval.pending")}: ${approval.tool ?? t("approval.fallbackTool")}`} className="approval">
      <p className="approval-title">
        {t("approval.title")}
        {approval.tool && (
          <>
            {" "}· <code>{approval.tool}</code>
          </>
        )}
      </p>
      <pre className="approval-command">
        {displayCommand(approval.command)}
      </pre>
      {approval.description && <p className="approval-desc">{approval.description}</p>}
      <p role="status" className={`approval-status${timedOut ? " timed-out" : ""}`}>
        {timedOut ? (
          <>{t("approval.timedOut")}</>
        ) : (
          <>{t("approval.left")}~{left}{t("approval.leftSuffix")} <button className="btn btn-sm" onClick={tick} aria-label={t("approval.refresh")}>↻</button></>
        )}
      </p>
      <div className="approval-buttons">
        {approvalButtons().map(({ choice }) => (
          <button
            key={choice}
            className="btn btn-sm"
            disabled={busyChoice !== null}
            onClick={() => onRespond(approval.runId, choice, scopeKey)}
          >
            {busyChoice === choice ? t("approval.sending") : t(`approval.${choice}` as "approval.once" | "approval.session" | "approval.always" | "approval.deny")}
          </button>
        ))}
      </div>
      {error && (
        <p role="alert" className="voice-error">
          Error: {error}
        </p>
      )}
    </article>
  );
}

export interface AlwaysRulesSectionProps {
  rules: AlwaysApprovalRule[];
  onRevoke: (id: string) => void;
}

export function AlwaysRulesSection({ rules, onRevoke }: AlwaysRulesSectionProps) {
  const { t } = useI18n();
  if (rules.length === 0) return null;
  return (
    <section aria-label={t("approval.alwaysSection")} className="always-rules">
      <h3>{t("approval.alwaysTitle")} ({rules.length})</h3>
      <p>
        {t("approval.alwaysCopy")} <em>{t("approval.always")}</em>{t("approval.alwaysCopy2")}
      </p>
      <ul>
        {rules.map((r) => (
          <li key={r.id}>
            <code>{r.patternKey}</code>
            {r.tool && (
              <>
                {" "}· <code>{r.tool}</code>
              </>
            )}{" "}
            <button className="btn btn-sm" onClick={() => onRevoke(r.id)}>{t("approval.revoke")}</button>
          </li>
        ))}
      </ul>
    </section>
  );
}
