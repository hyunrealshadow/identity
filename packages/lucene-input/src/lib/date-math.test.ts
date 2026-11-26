import { describe, expect, it } from 'vitest';
import { evaluateDateMath, formatDateMathValue, isDateMathValue } from './date-math';

describe('date math', () => {
  const reference = new Date(2026, 4, 15, 10, 30, 45, 500);

  it('recognizes supported date math values', () => {
    expect(isDateMathValue('now')).toBe(true);
    expect(isDateMathValue('now-5m')).toBe(true);
    expect(isDateMathValue('now-7d/d')).toBe(true);
    expect(isDateMathValue('now-1d+2h/d')).toBe(true);
    expect(isDateMathValue('today')).toBe(false);
  });

  it('evaluates date math with rounding', () => {
    expect(formatDateMathValue(evaluateDateMath('now/d', reference)!, 'datetime', { quoteDatetime: false })).toBe(
      '2026-05-15 00:00:00'
    );
    expect(formatDateMathValue(evaluateDateMath('now-5m', reference)!, 'datetime', { quoteDatetime: false })).toBe(
      '2026-05-15 10:25:45'
    );
    expect(formatDateMathValue(evaluateDateMath('now-7d/d', reference)!, 'date')).toBe('2026-05-08');
    expect(formatDateMathValue(evaluateDateMath('now-1d+2h/d', reference)!, 'datetime', { quoteDatetime: false })).toBe(
      '2026-05-14 00:00:00'
    );
    expect(formatDateMathValue(evaluateDateMath('now-1d+2h', reference)!, 'datetime', { quoteDatetime: false })).toBe(
      '2026-05-14 12:30:45'
    );
  });

  it('evaluates and formats date math in an explicit IANA timeZone', () => {
    const utcInstant = new Date('2026-11-20T17:15:30.000Z');
    // 17:15 UTC is 2026-11-21 01:15:30 in Asia/Shanghai (+08:00)
    const shanghaiMidnight = evaluateDateMath('now/d', utcInstant, 'Asia/Shanghai')!;
    expect(shanghaiMidnight.toISOString()).toBe('2026-11-20T16:00:00.000Z');
    expect(
      formatDateMathValue(shanghaiMidnight, 'datetime', {
        quoteDatetime: false,
        timeZone: 'Asia/Shanghai'
      })
    ).toBe('2026-11-21 00:00:00');
    expect(formatDateMathValue(utcInstant, 'date', { timeZone: 'UTC' })).toBe('2026-11-20');
    expect(formatDateMathValue(utcInstant, 'date', { timeZone: 'Asia/Shanghai' })).toBe('2026-11-21');
  });

  it('rejects overflowing amounts and clamps calendar month-end dates', () => {
    const jan31 = new Date('2024-01-31T12:00:00Z');
    expect(evaluateDateMath('now+1M', jan31, 'UTC')?.toISOString()).toBe('2024-02-29T12:00:00.000Z');
    expect(evaluateDateMath('now-999999999y', jan31, 'UTC')).toBeNull();
    expect(isDateMathValue('now-999999999y')).toBe(false);
    // Elapsed durations skip timezone wall-clock shifts (America/New_York spring forward on 2024-03-10 02:00->03:00).
    const beforeDst = new Date('2024-03-10T06:30:00Z');
    expect(evaluateDateMath('now+1h', beforeDst, 'America/New_York')?.toISOString()).toBe('2024-03-10T07:30:00.000Z');
  });
});
