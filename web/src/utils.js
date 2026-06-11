import cronstrue from 'cronstrue';

export const formatTimeForDisplay = (time24, timeFormat = '12h') => {
  if (!time24) return '';
  if (timeFormat === '24h') return time24;

  const [hours, minutes] = time24.split(':');
  const h = parseInt(hours, 10);
  const ampm = h >= 12 ? 'PM' : 'AM';
  const h12 = h % 12 || 12;
  return `${h12}:${minutes} ${ampm}`;
};

export const normalizePrintWebhookEndpointPath = (value) => {
  const slug = String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');

  return slug;
};

export const generatePrintWebhookToken = () => {
  const bytes = new Uint8Array(18);

  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
    let binary = '';
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  return `pc1_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
};

// Cron schedule helpers. Rules are 5-field cron expressions evaluated in the
// device timezone; descriptions are always computed client-side at render
// time so they follow the current 12h/24h clock preference.

export const validateCronExpression = (expression) => {
  const trimmed = String(expression || '').trim();
  if (trimmed.split(/\s+/).length !== 5) return false;
  try {
    cronstrue.toString(trimmed);
    return true;
  } catch {
    return false;
  }
};

export const describeCron = (expression, timeFormat = '12h') => {
  const trimmed = String(expression || '').trim();
  if (!trimmed) return '';
  try {
    return cronstrue.toString(trimmed, {
      use24HourTimeFormat: timeFormat === '24h',
      verbose: false,
    });
  } catch {
    return `Custom schedule (${trimmed})`;
  }
};

// True when an expression can fire more than once per hour (paper-burner).
export const cronFiresSubHourly = (expression) => {
  const parts = String(expression || '').trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const minute = parts[0];
  return minute.includes('*') || minute.includes(',') || minute.includes('-');
};

export const channelScheduleRuleCount = (channel) =>
  (channel?.schedule_rules?.length || 0) + (channel?.schedule?.length || 0);
