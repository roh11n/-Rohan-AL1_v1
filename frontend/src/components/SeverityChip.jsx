export const SeverityChip = ({ label, testId }) => {
  const cls = {
    Critical: "tg-sev-critical",
    High: "tg-sev-high",
    Medium: "tg-sev-medium",
    Low: "tg-sev-low",
    Benign: "tg-sev-info",
  }[label] || "tg-sev-info";
  return (
    <span className={`tg-sev ${cls}`} data-testid={testId}>
      {label}
    </span>
  );
};

export const StatusChip = ({ status, testId }) => {
  const cls = {
    OPEN: "tg-status-open",
    INVESTIGATING: "tg-status-investigating",
    PENDING_APPROVAL: "tg-status-pending",
    ESCALATED: "tg-status-escalated",
    RESOLVED: "tg-status-resolved",
    CLOSED: "tg-status-closed",
    PUSHED: "tg-status-resolved",
    APPROVED: "tg-status-resolved",
    REJECTED: "tg-status-escalated",
    MERGED: "tg-status-pending",
  }[status] || "tg-status";
  return (
    <span data-testid={testId} className={`tg-status ${cls}`}>
      {status?.replace(/_/g, " ")}
    </span>
  );
};
