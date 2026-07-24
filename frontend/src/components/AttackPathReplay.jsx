import { useEffect, useState, useRef } from "react";
import { Play, Pause, SkipBack, SkipForward, RotateCcw } from "lucide-react";

const PHASE_COLORS = {
  "Reconnaissance": "#38BDF8",
  "Initial Access": "#FF8A00",
  "Execution": "#FF003C",
  "Defense Evasion": "#A855F7",
  "Discovery": "#FACC15",
  "Command & Control": "#FF8A00",
  "Privilege Escalation": "#FF8A00",
  "Persistence": "#F472B6",
  "Lateral Movement": "#F472B6",
  "Collection": "#38BDF8",
  "Exfiltration": "#FF003C",
  "Impact": "#FF003C",
  "Analysis": "#00F0FF",
};

export const AttackPathReplay = ({ steps = [] }) => {
  const [idx, setIdx] = useState(0);
  const [playing, setPlaying] = useState(false);
  const timerRef = useRef(null);

  useEffect(() => {
    if (!playing) { clearInterval(timerRef.current); return; }
    timerRef.current = setInterval(() => {
      setIdx((i) => {
        if (i + 1 >= steps.length) { setPlaying(false); return i; }
        return i + 1;
      });
    }, 2400);
    return () => clearInterval(timerRef.current);
  }, [playing, steps.length]);

  if (!steps || steps.length === 0) {
    return (
      <div className="tactical-panel p-8 text-center text-neutral-500 font-mono text-sm" data-testid="attack-path-empty">
        Run AI Investigation to generate the attack story.
      </div>
    );
  }

  const step = steps[idx];
  const color = PHASE_COLORS[step.phase] || "#00F0FF";
  const progress = ((idx + 1) / steps.length) * 100;

  return (
    <div className="space-y-5" data-testid="attack-path-tab">
      {/* Player */}
      <div className="tactical-panel p-6" data-testid="attack-replay-player">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">STEP</div>
            <div className="font-display text-2xl">
              <span className="text-cyan-400">{String(idx + 1).padStart(2, "0")}</span>
              <span className="text-neutral-600 mx-1">/</span>
              <span className="text-neutral-500">{String(steps.length).padStart(2, "0")}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button data-testid="replay-restart" onClick={() => { setIdx(0); setPlaying(false); }}
              className="border border-[#1F1F1F] hover:border-cyan-500 hover:text-cyan-400 p-2 text-neutral-400">
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
            <button data-testid="replay-prev" onClick={() => setIdx((i) => Math.max(0, i - 1))} disabled={idx === 0}
              className="border border-[#1F1F1F] hover:border-cyan-500 hover:text-cyan-400 p-2 text-neutral-400 disabled:opacity-40">
              <SkipBack className="w-3.5 h-3.5" />
            </button>
            <button data-testid="replay-play" onClick={() => setPlaying((p) => !p)}
              className="bg-cyan-400 hover:bg-cyan-300 text-black px-4 py-2 text-xs font-mono uppercase tracking-widest font-bold inline-flex items-center gap-2">
              {playing ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              {playing ? "Pause" : idx + 1 >= steps.length ? "Restart" : "Play"}
            </button>
            <button data-testid="replay-next" onClick={() => setIdx((i) => Math.min(steps.length - 1, i + 1))} disabled={idx + 1 >= steps.length}
              className="border border-[#1F1F1F] hover:border-cyan-500 hover:text-cyan-400 p-2 text-neutral-400 disabled:opacity-40">
              <SkipForward className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Progress bar */}
        <div className="h-1 bg-[#0A0A0A] mb-6 relative">
          <div className="h-1 transition-all duration-500" style={{ width: `${progress}%`, background: color }} />
        </div>

        {/* Step card */}
        <div key={idx} className="fade-in-up" data-testid={`replay-step-${idx}`}>
          <div className="flex items-center gap-3 mb-2">
            <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest border"
              style={{ borderColor: color, color: color, background: `${color}18` }}>{step.phase}</span>
            {step.technique && (
              <span className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">ATT&CK · {step.technique}</span>
            )}
            <span className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 ml-auto">
              Severity <span style={{ color }}>{step.severity}</span>
            </span>
          </div>
          <h3 className="font-display text-2xl lg:text-3xl mb-4 leading-tight" data-testid="replay-headline">{step.headline}</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
            <ActorCard label="Actor" value={step.actor} color={color} />
            <ActorCard label="Action" value={step.action} color="#9CA3AF" />
            <ActorCard label="Target" value={step.target} color={color} />
          </div>
          <div className="border-l-2 pl-3 py-1 text-sm text-neutral-300" style={{ borderColor: color }}>
            <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-1">Evidence</div>
            {step.evidence}
          </div>
        </div>
      </div>

      {/* Chapter list */}
      <div className="tactical-panel p-3" data-testid="attack-chapter-list">
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-2 px-1">// CHAPTERS</div>
        <div className="flex flex-wrap gap-2">
          {steps.map((s, i) => {
            const c = PHASE_COLORS[s.phase] || "#00F0FF";
            const active = i === idx;
            return (
              <button key={i} onClick={() => { setIdx(i); setPlaying(false); }} data-testid={`chapter-${i}`}
                className={`text-left border p-2 min-w-[180px] transition-all ${active ? "" : "opacity-60 hover:opacity-100"}`}
                style={{ borderColor: active ? c : "#1F1F1F", background: active ? `${c}12` : "transparent" }}>
                <div className="text-[9px] font-mono uppercase tracking-widest" style={{ color: c }}>{String(i + 1).padStart(2, "0")} · {s.phase}</div>
                <div className="text-xs text-neutral-200 font-mono line-clamp-1 mt-0.5">{s.headline}</div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};

const ActorCard = ({ label, value, color }) => (
  <div className="tactical-panel p-3">
    <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">{label}</div>
    <div className="font-mono text-sm mt-1 break-words" style={{ color }}>{value || "—"}</div>
  </div>
);
