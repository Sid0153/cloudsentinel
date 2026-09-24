/**
 * A horizontal bar chart for one series of counts (e.g. open findings per severity).
 *
 * One hue for every bar: the bars compare magnitude, and the category is named by its text
 * label, so colour carries no meaning of its own. Every bar shows its value, and the list is
 * plain text, so it doubles as the table view for screen readers.
 */
const BAR_COLOR = "#2a78d6"; // validated single-series hue (dataviz reference palette, slot 1)

export interface BarItem {
  key: string;
  label: string;
  value: number;
}

export default function BarList({ items, unit, label }: {
  items: BarItem[];
  unit: string;
  label: string;
}) {
  const max = Math.max(1, ...items.map((item) => item.value));
  return (
    <ul aria-label={label} className="space-y-2">
      {items.map((item) => {
        const width = item.value === 0 ? 0 : Math.max(2, (item.value / max) * 100);
        return (
          <li
            key={item.key}
            className="grid grid-cols-[8.5rem_1fr_2.5rem] items-center gap-3 text-sm"
            title={`${item.label}: ${item.value} ${unit}`}
          >
            <span className="truncate text-slate-700">{item.label}</span>
            <span className="h-3 rounded-sm bg-slate-100" aria-hidden="true">
              <span
                className="block h-3 rounded-r"
                style={{ width: `${width}%`, backgroundColor: BAR_COLOR }}
              />
            </span>
            <span className="text-right font-medium tabular-nums text-slate-900">{item.value}</span>
          </li>
        );
      })}
    </ul>
  );
}
