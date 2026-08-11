import { CalendarDays, ChevronLeft, ChevronRight } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

const WEEKDAYS = ["一", "二", "三", "四", "五", "六", "日"];

function parseDate(value: string): Date {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(year, month - 1, day);
}

function isoDate(value: Date): string {
  const year = value.getFullYear();
  const month = String(value.getMonth() + 1).padStart(2, "0");
  const day = String(value.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function chineseDate(value: string): string {
  const date = parseDate(value);
  return `${date.getFullYear()}年${date.getMonth() + 1}月${date.getDate()}日`;
}

export function ChineseDatePicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [month, setMonth] = useState(() => {
    const selected = parseDate(value);
    return new Date(selected.getFullYear(), selected.getMonth(), 1);
  });
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    window.addEventListener("pointerdown", close);
    return () => window.removeEventListener("pointerdown", close);
  }, [open]);

  const days = useMemo(() => {
    const firstWeekday = (month.getDay() + 6) % 7;
    const start = new Date(month.getFullYear(), month.getMonth(), 1 - firstWeekday);
    return Array.from({ length: 42 }, (_, index) => {
      const date = new Date(start);
      date.setDate(start.getDate() + index);
      return date;
    });
  }, [month]);

  return (
    <div className="chinese-date-picker" ref={root}>
      <button
        className="business-date-button"
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => {
          if (!open) {
            const selected = parseDate(value);
            setMonth(new Date(selected.getFullYear(), selected.getMonth(), 1));
          }
          setOpen((current) => !current);
        }}
      >
        <CalendarDays aria-hidden="true" size={17} />
        {chineseDate(value)}
      </button>
      {open ? (
        <div className="chinese-calendar" role="dialog" aria-label="选择业务日">
          <div className="chinese-calendar-header">
            <strong>{month.getFullYear()}年{month.getMonth() + 1}月</strong>
            <div>
              <button type="button" aria-label="上个月" onClick={() => setMonth((current) => new Date(current.getFullYear(), current.getMonth() - 1, 1))}><ChevronLeft aria-hidden="true" size={18} /></button>
              <button type="button" aria-label="下个月" onClick={() => setMonth((current) => new Date(current.getFullYear(), current.getMonth() + 1, 1))}><ChevronRight aria-hidden="true" size={18} /></button>
            </div>
          </div>
          <div className="chinese-calendar-weekdays" aria-hidden="true">
            {WEEKDAYS.map((day) => <span key={day}>周{day}</span>)}
          </div>
          <div className="chinese-calendar-days">
            {days.map((date) => {
              const candidate = isoDate(date);
              const outside = date.getMonth() !== month.getMonth();
              return (
                <button
                  type="button"
                  key={candidate}
                  className={outside ? "outside" : undefined}
                  aria-pressed={candidate === value}
                  onClick={() => {
                    onChange(candidate);
                    setMonth(new Date(date.getFullYear(), date.getMonth(), 1));
                    setOpen(false);
                  }}
                >
                  {date.getDate()}
                </button>
              );
            })}
          </div>
          <button className="chinese-calendar-today" type="button" onClick={() => { onChange(isoDate(new Date())); setOpen(false); }}>今天</button>
        </div>
      ) : null}
    </div>
  );
}
