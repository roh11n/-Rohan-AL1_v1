// MITRE ATT&CK grid: 14 tactic columns × techniques from data
const TACTICS = [
  ["TA0043", "Reconnaissance"],
  ["TA0042", "Resource Dev"],
  ["TA0001", "Initial Access"],
  ["TA0002", "Execution"],
  ["TA0003", "Persistence"],
  ["TA0004", "Priv Escalation"],
  ["TA0005", "Defense Evasion"],
  ["TA0006", "Credential Access"],
  ["TA0007", "Discovery"],
  ["TA0008", "Lateral Movement"],
  ["TA0009", "Collection"],
  ["TA0011", "C2"],
  ["TA0010", "Exfiltration"],
  ["TA0040", "Impact"],
];

export const MitreMatrix = ({ techniques = [] }) => {
  const byTactic = {};
  techniques.forEach((t) => {
    const k = t.tactic_id || t.tactic_name;
    byTactic[k] = byTactic[k] || [];
    byTactic[k].push(t);
  });

  return (
    <div className="w-full overflow-x-auto" data-testid="mitre-matrix">
      <div className="grid gap-1 min-w-[1100px]" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(90px, 1fr))` }}>
        {TACTICS.map(([id, name]) => (
          <div key={id} className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 px-1 pb-2 border-b border-[#1F1F1F]">
            {name}
          </div>
        ))}
        {TACTICS.map(([id]) => {
          const hits = byTactic[id] || [];
          if (hits.length === 0) {
            return (
              <div key={id + "-empty"} className="mitre-cell text-neutral-700">
                <span className="tech-id">—</span>
              </div>
            );
          }
          return hits.map((h, i) => (
            <div key={id + i} className="mitre-cell hit" title={h.evidence_keyword || ""}>
              <span className="tech-id text-[10px]">{h.technique_id}</span>
              <span className="text-neutral-100 text-[10px] leading-tight">{h.technique_name}</span>
            </div>
          ));
        })}
      </div>
    </div>
  );
};
