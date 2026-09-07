import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

export const RiskGauge = ({ score = 0, size = 160 }) => {
  const s = Math.max(0, Math.min(100, Number(score) || 0));
  const data = [{ name: "risk", value: s }, { name: "rest", value: 100 - s }];
  const color = s >= 85 ? "#FF003C" : s >= 65 ? "#FF8A00" : s >= 40 ? "#FACC15" : "#38BDF8";
  return (
    <div className="relative" style={{ width: size, height: size / 2 + 20 }} data-testid="risk-gauge">
      <ResponsiveContainer width="100%" height={size + 20}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="100%"
            startAngle={180}
            endAngle={0}
            innerRadius={size * 0.36}
            outerRadius={size * 0.48}
            paddingAngle={0}
            dataKey="value"
            stroke="none"
          >
            <Cell fill={color} />
            <Cell fill="#171717" />
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-end pb-1">
        <span className="font-display text-3xl font-bold" style={{ color }}>{s}</span>
        <span className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">Risk / 100</span>
      </div>
    </div>
  );
};
