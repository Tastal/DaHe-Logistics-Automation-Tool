import { useId, useRef } from "react";

type PartName = "year" | "month" | "day" | "hour" | "minute" | "second";
type Parts = Record<PartName, string>;

interface PartSpec {
  name: PartName;
  label: string;
  length: number;
  min: number;
  max: number;
}

const EMPTY: Parts = { year: "", month: "", day: "", hour: "", minute: "", second: "" };
const SPECS: PartSpec[] = [
  { name: "year", label: "年", length: 4, min: 2000, max: 2099 },
  { name: "month", label: "月", length: 2, min: 1, max: 12 },
  { name: "day", label: "日", length: 2, min: 1, max: 31 },
  { name: "hour", label: "时", length: 2, min: 0, max: 23 },
  { name: "minute", label: "分", length: 2, min: 0, max: 59 },
  { name: "second", label: "秒", length: 2, min: 0, max: 59 },
];

function parse(value: string): Parts | null {
  if (value.startsWith("partial:")) {
    const values = value.slice("partial:".length).split("|");
    if (values.length !== SPECS.length) return null;
    return Object.fromEntries(SPECS.map((spec, index) => [spec.name, values[index] ?? ""])) as Parts;
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value);
  if (!match) return null;
  const [, year, month, day, hour, minute, second = "00"] = match;
  return { year, month, day, hour, minute, second };
}

function prefilled(value: string, prefillDate?: string): Parts {
  const parsed = value ? parse(value) : null;
  if (parsed) return parsed;
  const date = /^(\d{4})-(\d{2})-(\d{2})$/.exec(prefillDate ?? "");
  if (!date) return { ...EMPTY };
  return { ...EMPTY, year: date[1], month: date[2], day: date[3] };
}

function valid(parts: Parts, includeSeconds: boolean): boolean {
  const required = includeSeconds ? SPECS : SPECS.slice(0, 5);
  if (required.some((spec) => parts[spec.name].length !== spec.length)) return false;
  const year = Number(parts.year);
  const month = Number(parts.month);
  const day = Number(parts.day);
  const hour = Number(parts.hour);
  const minute = Number(parts.minute);
  const second = includeSeconds ? Number(parts.second) : 0;
  const candidate = new Date(year, month - 1, day, hour, minute, second);
  return candidate.getFullYear() === year
    && candidate.getMonth() === month - 1
    && candidate.getDate() === day
    && candidate.getHours() === hour
    && candidate.getMinutes() === minute
    && candidate.getSeconds() === second;
}

function partInvalid(parts: Parts, spec: PartSpec): boolean {
  const raw = parts[spec.name];
  if (!raw) return false;
  const numeric = Number(raw);
  if (!Number.isInteger(numeric) || numeric < spec.min || numeric > spec.max) return true;
  if (spec.name !== "day" || raw.length !== 2) return false;
  if (parts.year.length !== 4 || parts.month.length !== 2) return false;
  const year = Number(parts.year);
  const month = Number(parts.month);
  if (month < 1 || month > 12) return false;
  return numeric > new Date(year, month, 0).getDate();
}

function serialize(parts: Parts, includeSeconds: boolean): string {
  if (!valid(parts, includeSeconds)) {
    return `partial:${SPECS.map((spec) => parts[spec.name]).join("|")}`;
  }
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}${includeSeconds ? `:${parts.second}` : ""}`;
}

function pastedParts(text: string, includeSeconds: boolean): Parts | null {
  const digits = text.replace(/\D/g, "");
  const required = includeSeconds ? 14 : 12;
  if (digits.length !== required) return null;
  const parts: Parts = {
    year: digits.slice(0, 4),
    month: digits.slice(4, 6),
    day: digits.slice(6, 8),
    hour: digits.slice(8, 10),
    minute: digits.slice(10, 12),
    second: includeSeconds ? digits.slice(12, 14) : "00",
  };
  return valid(parts, includeSeconds) ? parts : null;
}

function shouldCompleteSingleDigit(spec: PartSpec, raw: string): boolean {
  if (spec.length !== 2 || raw.length !== 1) return false;
  return Number(raw) > Math.floor(spec.max / 10);
}

export function ChineseDateTimeInput({
  value,
  includeSeconds,
  prefillDate,
  onChange,
}: {
  value: string;
  includeSeconds: boolean;
  prefillDate?: string;
  onChange: (value: string) => void;
}) {
  const inputs = useRef<Array<HTMLInputElement | null>>([]);
  const id = useId();
  const parts = prefilled(value, prefillDate);
  const visibleSpecs = includeSeconds ? SPECS : SPECS.slice(0, 5);

  const commit = (next: Parts) => {
    const normalized = includeSeconds ? next : { ...next, second: "00" };
    onChange(serialize(normalized, includeSeconds));
  };

  const completeField = (spec: PartSpec, index: number, moveNext: boolean, currentValue?: string) => {
    const raw = currentValue ?? parts[spec.name];
    if (raw.length === 1 && spec.length === 2) {
      const padded = raw.padStart(2, "0");
      commit({ ...parts, [spec.name]: padded });
    }
    if (moveNext) inputs.current[index + 1]?.focus();
  };

  return (
    <div
      className="segmented-datetime"
      role="group"
      aria-label={includeSeconds ? "年月日时分秒" : "年月日时分"}
      onPaste={(event) => {
        const pasted = pastedParts(event.clipboardData.getData("text"), includeSeconds);
        if (!pasted) return;
        event.preventDefault();
        commit(pasted);
        inputs.current[visibleSpecs.length - 1]?.focus();
      }}
    >
      {visibleSpecs.map((spec, index) => {
        const separator = index === 0 ? null : index <= 2 ? "/" : index === 3 ? null : ":";
        return (
          <div className="segmented-datetime-part" key={spec.name}>
            {separator ? <span className="segmented-datetime-separator" aria-hidden="true">{separator}</span> : null}
            <label htmlFor={`${id}-${spec.name}`}>
              <span className="sr-only">{spec.label}</span>
              <input
                ref={(node) => { inputs.current[index] = node; }}
                id={`${id}-${spec.name}`}
                inputMode="numeric"
                aria-label={spec.label}
                aria-invalid={partInvalid(parts, spec)}
                value={parts[spec.name]}
                maxLength={spec.length}
                placeholder={spec.name === "year" ? "年" : spec.label}
                onBlur={(event) => completeField(spec, index, false, event.currentTarget.value)}
                onChange={(event) => {
                  const digits = event.target.value.replace(/\D/g, "").slice(0, spec.length);
                  commit({ ...parts, [spec.name]: digits });
                  if (digits.length === spec.length || shouldCompleteSingleDigit(spec, digits)) {
                    const completed = digits.length === 1 ? digits.padStart(2, "0") : digits;
                    commit({ ...parts, [spec.name]: completed });
                    inputs.current[index + 1]?.focus();
                  }
                }}
                onKeyDown={(event) => {
                  if (event.key === "Backspace" && parts[spec.name] === "" && index > 0) {
                    event.preventDefault();
                    inputs.current[index - 1]?.focus();
                    return;
                  }
                  if (event.key === "Enter" || event.key === "/" || event.key === ":") {
                    event.preventDefault();
                    completeField(spec, index, true, event.currentTarget.value);
                    return;
                  }
                  if (event.key !== "ArrowUp" && event.key !== "ArrowDown") return;
                  event.preventDefault();
                  const current = Number(parts[spec.name] || spec.min);
                  const delta = event.key === "ArrowUp" ? 1 : -1;
                  const nextValue = Math.min(spec.max, Math.max(spec.min, current + delta));
                  commit({ ...parts, [spec.name]: String(nextValue).padStart(spec.length, "0") });
                }}
              />
            </label>
          </div>
        );
      })}
    </div>
  );
}
