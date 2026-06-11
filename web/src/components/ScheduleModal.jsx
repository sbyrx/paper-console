import React, { useMemo, useRef, useState } from 'react';
import { describeCron, validateCronExpression, cronFiresSubHourly } from '../utils';
import CloseButton from './CloseButton';
import PrimaryButton from './PrimaryButton';

const FREQUENCY_OPTIONS = [
  { id: 'daily', label: 'Every day' },
  { id: 'weekdays', label: 'Weekdays (Mon\u2013Fri)' },
  { id: 'weekends', label: 'Weekends' },
  { id: 'days', label: 'Specific days\u2026' },
  { id: 'monthly', label: 'Once a month' },
  { id: 'cron', label: 'Advanced (cron expression)' },
];

// Cron weekday numbers: 0 = Sunday. Shown Monday-first.
const DAY_OPTIONS = [
  { value: 1, label: 'Mon' },
  { value: 2, label: 'Tue' },
  { value: 3, label: 'Wed' },
  { value: 4, label: 'Thu' },
  { value: 5, label: 'Fri' },
  { value: 6, label: 'Sat' },
  { value: 0, label: 'Sun' },
];

const hhmmToCronParts = (hhmm) => {
  const [hour, minute] = String(hhmm || '').split(':');
  if (hour === undefined || minute === undefined) return null;
  return { minute: Number(minute), hour: Number(hour) };
};

const ScheduleModal = ({ position, channel, onClose, onUpdate, timeFormat, timezone }) => {
  const modalMouseDownTarget = useRef(null);
  const [frequency, setFrequency] = useState('daily');
  const [time, setTime] = useState('08:00');
  const [selectedDays, setSelectedDays] = useState([1, 2, 3, 4, 5]);
  const [monthDay, setMonthDay] = useState(1);
  const [cronInput, setCronInput] = useState('');
  const [error, setError] = useState('');

  // Existing rules; legacy HH:MM entries are shown as their cron equivalent.
  const scheduleRules = useMemo(() => {
    if (channel?.schedule_rules?.length) {
      return channel.schedule_rules.map((rule) => ({
        expression: String(rule.expression || '').trim(),
        enabled: rule.enabled !== false,
      }));
    }

    return (channel?.schedule || [])
      .map((hhmm) => {
        const parts = hhmmToCronParts(hhmm);
        if (!parts || Number.isNaN(parts.minute) || Number.isNaN(parts.hour)) return null;
        return { expression: `${parts.minute} ${parts.hour} * * *`, enabled: true };
      })
      .filter(Boolean);
  }, [channel]);

  if (position === null) return null;

  const buildExpression = () => {
    if (frequency === 'cron') {
      return cronInput.trim();
    }

    const parts = hhmmToCronParts(time);
    if (!parts || Number.isNaN(parts.minute) || Number.isNaN(parts.hour)) return '';
    const { minute, hour } = parts;

    switch (frequency) {
      case 'daily':
        return `${minute} ${hour} * * *`;
      case 'weekdays':
        return `${minute} ${hour} * * 1-5`;
      case 'weekends':
        return `${minute} ${hour} * * 0,6`;
      case 'days': {
        if (!selectedDays.length) return '';
        const days = [...selectedDays].sort((a, b) => a - b).join(',');
        return `${minute} ${hour} * * ${days}`;
      }
      case 'monthly':
        return `${minute} ${hour} ${monthDay} * *`;
      default:
        return '';
    }
  };

  const pendingExpression = buildExpression();
  const pendingIsValid = pendingExpression !== '' && validateCronExpression(pendingExpression);
  const pendingPreview = pendingIsValid ? describeCron(pendingExpression, timeFormat) : '';

  const commitRules = (rules) => {
    onUpdate({ rules });
  };

  const handleAdd = (e) => {
    e.preventDefault();
    setError('');

    if (frequency === 'days' && selectedDays.length === 0) {
      setError('Pick at least one day of the week.');
      return;
    }

    if (!pendingExpression) {
      setError(
        frequency === 'cron'
          ? 'Enter a cron expression, e.g. "30 8 * * 1-5" for weekdays at 8:30 AM.'
          : 'Pick a time for this schedule.'
      );
      return;
    }

    if (!pendingIsValid) {
      const fieldCount = pendingExpression.split(/\s+/).length;
      setError(
        fieldCount !== 5
          ? `Cron expressions need exactly 5 fields (minute hour day month weekday). Found ${fieldCount}.`
          : 'That cron expression is not valid. Double-check each field.'
      );
      return;
    }

    if (scheduleRules.some((rule) => rule.expression === pendingExpression)) {
      setError('This channel already has that exact schedule.');
      return;
    }

    commitRules([...scheduleRules, { expression: pendingExpression, enabled: true }]);
    if (frequency === 'cron') setCronInput('');
  };

  const toggleDay = (value) => {
    setError('');
    setSelectedDays((prev) =>
      prev.includes(value) ? prev.filter((d) => d !== value) : [...prev, value]
    );
  };

  return (
    <div
      className='fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4'
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          modalMouseDownTarget.current = 'backdrop';
        }
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && modalMouseDownTarget.current === 'backdrop') {
          onClose();
        }
        modalMouseDownTarget.current = null;
      }}>
      <div className='border-4 rounded-xl p-4 sm:p-6 max-w-lg w-full shadow-lg max-h-[90vh] overflow-y-auto' style={{ backgroundColor: 'var(--color-bg-card)', borderColor: 'var(--color-border-main)' }} onClick={(e) => e.stopPropagation()}>
        <div className='flex justify-between items-center mb-6'>
          <h3 className='text-xl font-bold text-black'>Schedule Channel {position}</h3>
          <CloseButton onClick={onClose} />
        </div>

        <div className='space-y-4'>
          <div className='text-sm text-gray-600'>
            Print this channel automatically.
            {timezone ? (
              <> Times follow your device timezone (<span className='font-mono text-black'>{timezone}</span>).</>
            ) : (
              <> Times follow the timezone from General Settings.</>
            )}
          </div>

          <div className='space-y-2 max-h-[220px] overflow-y-auto'>
            {scheduleRules.map((rule, idx) => (
              <div key={`${rule.expression}-${idx}`} className='flex items-center justify-between gap-3 p-3 rounded-lg border-2 border-gray-300 hover:border-black' style={{ backgroundColor: 'var(--color-bg-card)' }}>
                <div className='flex-1 min-w-0'>
                  <div className='text-black'>{describeCron(rule.expression, timeFormat)}</div>
                  <div className='text-[11px] font-mono text-gray-400 mt-0.5'>{rule.expression}</div>
                </div>
                <button
                  onClick={() => {
                    const newRules = [...scheduleRules];
                    newRules.splice(idx, 1);
                    commitRules(newRules);
                  }}
                  className='text-red-600 hover:text-red-700 px-2 font-bold cursor-pointer hover-shimmer'
                  aria-label={`Remove schedule: ${describeCron(rule.expression, timeFormat)}`}>
                  &times;
                </button>
              </div>
            ))}
            {scheduleRules.length === 0 && (
              <div className='text-gray-500 text-center py-4 italic'>No schedules yet.</div>
            )}
          </div>

          <form onSubmit={handleAdd} className='pt-4 border-t-2 border-gray-300 space-y-3'>
            <div className='grid grid-cols-1 sm:grid-cols-2 gap-3'>
              <div>
                <label className='text-xs text-gray-500 font-semibold'>How often</label>
                <select
                  value={frequency}
                  onChange={(e) => {
                    setFrequency(e.target.value);
                    setError('');
                  }}
                  className='mt-1 w-full border-2 border-gray-300 rounded-lg px-3 py-2 text-black focus:outline-none focus:border-black cursor-pointer'
                  style={{ backgroundColor: 'var(--color-bg-card)' }}>
                  {FREQUENCY_OPTIONS.map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              {frequency !== 'cron' && (
                <div>
                  <label className='text-xs text-gray-500 font-semibold'>At what time</label>
                  <input
                    type='time'
                    value={time}
                    required
                    onChange={(e) => {
                      setTime(e.target.value);
                      setError('');
                    }}
                    className='mt-1 w-full border-2 border-gray-300 rounded-lg px-3 py-2 text-black focus:outline-none focus:border-black'
                    style={{ backgroundColor: 'var(--color-bg-card)' }}
                  />
                </div>
              )}
            </div>

            {frequency === 'days' && (
              <div>
                <label className='text-xs text-gray-500 font-semibold'>On these days</label>
                <div className='mt-1 flex flex-wrap gap-1.5'>
                  {DAY_OPTIONS.map((day) => {
                    const active = selectedDays.includes(day.value);
                    return (
                      <button
                        key={day.value}
                        type='button'
                        onClick={() => toggleDay(day.value)}
                        className={`px-3 py-1.5 rounded-lg border-2 text-sm font-semibold cursor-pointer transition-all ${
                          active ? 'border-black text-black' : 'border-gray-300 text-gray-400 hover:border-black hover:text-black'
                        }`}
                        style={active ? { backgroundColor: 'var(--color-brass-10)', borderColor: 'var(--color-brass)', color: 'var(--color-brass)' } : { backgroundColor: 'var(--color-bg-card)' }}
                        aria-pressed={active}>
                        {day.label}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {frequency === 'monthly' && (
              <div>
                <label className='text-xs text-gray-500 font-semibold'>On day of month</label>
                <input
                  type='number'
                  min='1'
                  max='31'
                  value={monthDay}
                  onChange={(e) => {
                    const value = Math.min(31, Math.max(1, Number(e.target.value) || 1));
                    setMonthDay(value);
                    setError('');
                  }}
                  className='mt-1 w-24 border-2 border-gray-300 rounded-lg px-3 py-2 text-black focus:outline-none focus:border-black'
                  style={{ backgroundColor: 'var(--color-bg-card)' }}
                />
                <span className='ml-2 text-xs text-gray-500'>(months without this day are skipped)</span>
              </div>
            )}

            {frequency === 'cron' && (
              <div className='space-y-2'>
                <label className='text-xs text-gray-500 font-semibold'>Cron expression</label>
                <input
                  value={cronInput}
                  onChange={(e) => {
                    setCronInput(e.target.value);
                    setError('');
                  }}
                  placeholder='30 8 * * 1-5'
                  className='w-full border-2 border-gray-300 rounded-lg px-3 py-2 text-black focus:outline-none focus:border-black font-mono'
                  style={{ backgroundColor: 'var(--color-bg-card)' }}
                />
                <pre className='font-mono text-[11px] text-gray-500 overflow-x-auto leading-tight'>
{`\u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 minute  (0-59)
\u2502 \u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 hour    (0-23)
\u2502 \u2502 \u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500 day     (1-31)
\u2502 \u2502 \u2502 \u250C\u2500\u2500\u2500\u2500\u2500 month   (1-12)
\u2502 \u2502 \u2502 \u2502 \u250C\u2500\u2500\u2500 weekday (0-6, Sun=0)
* * * * *`}
                </pre>
                <div className='text-xs text-gray-500'>
                  Need help? Try{' '}
                  <a href='https://crontab.guru/' target='_blank' rel='noopener noreferrer' className='underline text-blue-600 hover:text-blue-800'>
                    crontab.guru
                  </a>
                </div>
              </div>
            )}

            {pendingIsValid && (
              <div className='text-sm text-gray-700 italic px-1'>
                Will print: <span className='font-semibold not-italic'>{pendingPreview}</span>
              </div>
            )}
            {frequency === 'cron' && cronInput.trim() && !pendingIsValid && (
              <div className='text-xs text-gray-500 italic px-1'>Keep typing&hellip; that expression isn&apos;t valid yet.</div>
            )}
            {pendingIsValid && cronFiresSubHourly(pendingExpression) && (
              <div className='p-2.5 rounded-lg border-2 border-amber-400 bg-amber-50 text-xs text-amber-800'>
                Heads up: this schedule prints more than once an hour and can use a lot of paper.
              </div>
            )}

            {error && (
              <div className='p-2.5 rounded-lg border-2 border-red-400 bg-red-50 text-xs text-red-700'>{error}</div>
            )}

            <PrimaryButton type='submit' disabled={!pendingIsValid}>
              Add Schedule
            </PrimaryButton>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ScheduleModal;
