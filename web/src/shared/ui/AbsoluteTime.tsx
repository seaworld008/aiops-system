import { useState } from "react";

type AbsoluteTimeProps = {
  value: string;
};

export function AbsoluteTime({ value }: AbsoluteTimeProps) {
  const [renderedAt] = useState(() => Date.now());
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return <span>时间不可用</span>;
  }
  const absolute = new Intl.DateTimeFormat(undefined, {
    dateStyle: "full",
    timeStyle: "long",
  }).format(date);
  const relative = relativeTime(date.getTime() - renderedAt);
  return (
    <time
      role="time"
      dateTime={date.toISOString()}
      title={absolute}
      aria-label={`${relative}；${absolute}`}
    >
      {relative}
    </time>
  );
}

function relativeTime(milliseconds: number): string {
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const absolute = Math.abs(milliseconds);
  if (absolute < 60_000) {
    return formatter.format(Math.round(milliseconds / 1_000), "second");
  }
  if (absolute < 3_600_000) {
    return formatter.format(Math.round(milliseconds / 60_000), "minute");
  }
  if (absolute < 86_400_000) {
    return formatter.format(Math.round(milliseconds / 3_600_000), "hour");
  }
  return formatter.format(Math.round(milliseconds / 86_400_000), "day");
}
