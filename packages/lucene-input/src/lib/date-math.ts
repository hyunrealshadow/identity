import type { LuceneFieldType } from './types';

export type ZonedDateParts = {
  year: number;
  month: number;
  day: number;
  weekday: number;
  hour: number;
  minute: number;
  second: number;
  millisecond: number;
};

const WEEKDAY_MAP: Record<string, number> = {
  Sun: 0,
  Mon: 1,
  Tue: 2,
  Wed: 3,
  Thu: 4,
  Fri: 5,
  Sat: 6
};

export function getDatePartsInTimeZone(date: Date, timeZone?: string): ZonedDateParts {
  if (!timeZone) {
    return {
      year: date.getFullYear(),
      month: date.getMonth() + 1,
      day: date.getDate(),
      weekday: date.getDay(),
      hour: date.getHours(),
      minute: date.getMinutes(),
      second: date.getSeconds(),
      millisecond: date.getMilliseconds()
    };
  }

  try {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23'
    });
    const parts = formatter.formatToParts(date);
    const get = (type: string) => parts.find((p) => p.type === type)?.value;
    const weekdayLabel = get('weekday') ?? 'Mon';
    const hourVal = Number(get('hour') ?? date.getUTCHours());
    return {
      year: Number(get('year')),
      month: Number(get('month')),
      day: Number(get('day')),
      weekday: WEEKDAY_MAP[weekdayLabel] ?? date.getUTCDay(),
      hour: hourVal === 24 ? 0 : hourVal,
      minute: Number(get('minute')),
      second: Number(get('second')),
      millisecond: date.getMilliseconds()
    };
  } catch {
    return getDatePartsInTimeZone(date);
  }
}

export function fromZonedDateParts(parts: ZonedDateParts, timeZone?: string): Date {
  if (!timeZone) {
    return new Date(
      parts.year,
      parts.month - 1,
      parts.day,
      parts.hour,
      parts.minute,
      parts.second,
      parts.millisecond
    );
  }

  const targetUtcMs = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second,
    parts.millisecond
  );
  let guess = new Date(targetUtcMs);
  for (let pass = 0; pass < 2; pass += 1) {
    const actual = getDatePartsInTimeZone(guess, timeZone);
    const actualUtcMs = Date.UTC(
      actual.year,
      actual.month - 1,
      actual.day,
      actual.hour,
      actual.minute,
      actual.second,
      actual.millisecond
    );
    const diff = targetUtcMs - actualUtcMs;
    if (diff === 0) {
      break;
    }
    guess = new Date(guess.getTime() + diff);
  }
  return guess;
}

export function isDateMathValue(value: string): boolean {
  return /^now(?:[+-]\d+(?:ms|s|m|h|d|w|M|y))*(?:\/(?:s|m|h|d|w|M|y))?$/.test(value);
}

export function evaluateDateMath(value: string, referenceDate = new Date(), timeZone?: string): Date | null {
  const match = /^now((?:[+-]\d+(?:ms|s|m|h|d|w|M|y))*)(?:\/(s|m|h|d|w|M|y))?$/.exec(value);
  if (!match) {
    return null;
  }

  let date = new Date(referenceDate.getTime());
  const offsetPart = match[1];
  const roundUnit = match[2];

  for (const step of offsetPart.matchAll(/([+-])(\d+)(ms|s|m|h|d|w|M|y)/g)) {
    const direction = step[1];
    const amount = Number(step[2]);
    const mathUnit = step[3];
    date = addDateMath(date, direction === '-' ? -amount : amount, mathUnit, timeZone);
  }

  if (roundUnit) {
    date = roundDateMath(date, roundUnit, timeZone);
  }

  return date;
}

export function formatDateMathValue(
  date: Date,
  fieldType: Extract<LuceneFieldType, 'date' | 'datetime'>,
  options: { quoteDatetime?: boolean; timeZone?: string } = {}
): string {
  const dateText = formatDateValue(date, options.timeZone);
  if (fieldType === 'date') {
    return dateText;
  }

  const parts = getDatePartsInTimeZone(date, options.timeZone);
  const datetime = `${dateText} ${padDatePart(parts.hour)}:${padDatePart(parts.minute)}:${padDatePart(parts.second)}`;
  return options.quoteDatetime === false ? datetime : `"${datetime}"`;
}

export function formatDateValue(date: Date, timeZone?: string): string {
  const parts = getDatePartsInTimeZone(date, timeZone);
  return `${parts.year}-${padDatePart(parts.month)}-${padDatePart(parts.day)}`;
}

function addDateMath(date: Date, amount: number, unit: string, timeZone?: string): Date {
  if (!timeZone) {
    const next = new Date(date.getTime());
    if (unit === 'ms') {
      next.setMilliseconds(next.getMilliseconds() + amount);
    } else if (unit === 's') {
      next.setSeconds(next.getSeconds() + amount);
    } else if (unit === 'm') {
      next.setMinutes(next.getMinutes() + amount);
    } else if (unit === 'h') {
      next.setHours(next.getHours() + amount);
    } else if (unit === 'd') {
      next.setDate(next.getDate() + amount);
    } else if (unit === 'w') {
      next.setDate(next.getDate() + amount * 7);
    } else if (unit === 'M') {
      next.setMonth(next.getMonth() + amount);
    } else if (unit === 'y') {
      next.setFullYear(next.getFullYear() + amount);
    }
    return next;
  }

  if (unit === 'ms') {
    return new Date(date.getTime() + amount);
  }
  if (unit === 's') {
    return new Date(date.getTime() + amount * 1000);
  }
  if (unit === 'm') {
    return new Date(date.getTime() + amount * 60_000);
  }
  if (unit === 'h') {
    return new Date(date.getTime() + amount * 3_600_000);
  }

  const parts = getDatePartsInTimeZone(date, timeZone);
  const base = new Date(
    Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second, parts.millisecond)
  );
  if (unit === 'd') {
    base.setUTCDate(base.getUTCDate() + amount);
  } else if (unit === 'w') {
    base.setUTCDate(base.getUTCDate() + amount * 7);
  } else if (unit === 'M') {
    base.setUTCMonth(base.getUTCMonth() + amount);
  } else if (unit === 'y') {
    base.setUTCFullYear(base.getUTCFullYear() + amount);
  }
  return fromZonedDateParts(
    {
      year: base.getUTCFullYear(),
      month: base.getUTCMonth() + 1,
      day: base.getUTCDate(),
      weekday: base.getUTCDay(),
      hour: base.getUTCHours(),
      minute: base.getUTCMinutes(),
      second: base.getUTCSeconds(),
      millisecond: base.getUTCMilliseconds()
    },
    timeZone
  );
}

function roundDateMath(date: Date, unit: string, timeZone?: string): Date {
  if (!timeZone) {
    const next = new Date(date.getTime());
    if (unit === 'y') {
      next.setMonth(0, 1);
      next.setHours(0, 0, 0, 0);
    } else if (unit === 'M') {
      next.setDate(1);
      next.setHours(0, 0, 0, 0);
    } else if (unit === 'w') {
      const day = next.getDay();
      const mondayOffset = day === 0 ? -6 : 1 - day;
      next.setDate(next.getDate() + mondayOffset);
      next.setHours(0, 0, 0, 0);
    } else if (unit === 'd') {
      next.setHours(0, 0, 0, 0);
    } else if (unit === 'h') {
      next.setMinutes(0, 0, 0);
    } else if (unit === 'm') {
      next.setSeconds(0, 0);
    } else if (unit === 's') {
      next.setMilliseconds(0);
    }
    return next;
  }

  const parts = getDatePartsInTimeZone(date, timeZone);
  const nextParts: ZonedDateParts = { ...parts };
  if (unit === 'y') {
    nextParts.month = 1;
    nextParts.day = 1;
    nextParts.hour = 0;
    nextParts.minute = 0;
    nextParts.second = 0;
    nextParts.millisecond = 0;
  } else if (unit === 'M') {
    nextParts.day = 1;
    nextParts.hour = 0;
    nextParts.minute = 0;
    nextParts.second = 0;
    nextParts.millisecond = 0;
  } else if (unit === 'w') {
    const mondayOffset = parts.weekday === 0 ? -6 : 1 - parts.weekday;
    const base = new Date(Date.UTC(parts.year, parts.month - 1, parts.day + mondayOffset));
    nextParts.year = base.getUTCFullYear();
    nextParts.month = base.getUTCMonth() + 1;
    nextParts.day = base.getUTCDate();
    nextParts.hour = 0;
    nextParts.minute = 0;
    nextParts.second = 0;
    nextParts.millisecond = 0;
  } else if (unit === 'd') {
    nextParts.hour = 0;
    nextParts.minute = 0;
    nextParts.second = 0;
    nextParts.millisecond = 0;
  } else if (unit === 'h') {
    nextParts.minute = 0;
    nextParts.second = 0;
    nextParts.millisecond = 0;
  } else if (unit === 'm') {
    nextParts.second = 0;
    nextParts.millisecond = 0;
  } else if (unit === 's') {
    nextParts.millisecond = 0;
  }
  return fromZonedDateParts(nextParts, timeZone);
}

function padDatePart(value: string | number): string {
  return String(value).padStart(2, '0');
}
