interface StatusRowProps {
  label: string;
  value: string;
  healthy: boolean;
}

export default function StatusRow({ label, value, healthy }: StatusRowProps) {
  return (
    <div className="flex items-center justify-between py-3">
      <dt className="text-sm text-slate-600">{label}</dt>
      <dd
        className={`rounded px-2 py-0.5 text-sm font-medium ${
          healthy ? "bg-emerald-100 text-emerald-800" : "bg-red-100 text-red-800"
        }`}
      >
        {value}
      </dd>
    </div>
  );
}
