export function businessDateForShanghaiClock(now: Date): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    hourCycle: "h23",
  }).formatToParts(now);
  const value = (type: Intl.DateTimeFormatPartTypes) => (
    parts.find((part) => part.type === type)?.value ?? "00"
  );
  const businessDate = new Date(Date.UTC(
    Number(value("year")),
    Number(value("month")) - 1,
    Number(value("day")),
  ));
  if (Number(value("hour")) < 14) businessDate.setUTCDate(businessDate.getUTCDate() - 1);
  return businessDate.toISOString().slice(0, 10);
}

export function selectInitialBusinessDate(stored: string | null, current: string): string {
  return stored && /^\d{4}-\d{2}-\d{2}$/.test(stored) && stored <= current ? stored : current;
}
