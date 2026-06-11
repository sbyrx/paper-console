# Scheduling System

Each channel can have one or more schedule rules that control when it prints automatically. Rules use standard 5-field cron expressions and are always evaluated in the device timezone (`settings.timezone` from General Settings).

## Rule Format

A schedule rule is stored on the channel as:

| Field | Type | Description |
|---|---|---|
| `expression` | string | 5-field cron expression, e.g. `30 14 * * *` |
| `enabled` | bool | Whether this rule is active (default `true`) |

Example channel config:

```json
"schedule_rules": [
  { "expression": "30 14 * * *", "enabled": true },
  { "expression": "0 9 * * 1-5", "enabled": true }
]
```

Human-readable descriptions are computed at render time (server-side via `humanize_cron()` for printed receipts, client-side via `cronstrue` in the web UI) so they always follow the current 12h/24h clock preference. They are not stored.

## Cron Expression Format

```
┌─────────── minute  (0-59)
│ ┌───────── hour    (0-23)
│ │ ┌─────── day     (1-31)
│ │ │ ┌───── month   (1-12)
│ │ │ │ ┌─── weekday (0-6, Sun=0)
* * * * *
```

Common patterns:

| Expression | Meaning |
|---|---|
| `30 14 * * *` | Every day at 14:30 |
| `0 9 * * 1-5` | Weekdays at 09:00 |
| `0 9 * * 0,6` | Weekends at 09:00 |
| `0 8 1 * *` | Day 1 of each month at 08:00 |
| `0 8,12,18 * * *` | Three times daily |

## Timezone Handling

All rules run in the device timezone (`settings.timezone`). Per-rule timezones are **not** supported. A leading `CRON_TZ=`/`TZ=` token in a pasted expression is tolerated but ignored (stripped on save) so expressions copied from other systems don't hard-fail.

## Scheduler Loop

The scheduler (`scheduler_loop()` in `app/main.py`) ticks every 10 seconds but evaluates each minute exactly once. `current_datetime()` already returns local time in the configured timezone, so cron expressions are matched against local wall-clock minutes with `croniter.match()`. A channel prints at most once per matched minute, even when multiple rules overlap. Invalid rules are skipped with a warning and never break the loop.

## Weather Prefetch Integration

Weather modules on scheduled channels are pre-warmed 2-4 minutes before each scheduled print (`_run_weather_prefetch_cycle()`), because on-the-dot weather API calls can be slow or time out. Upcoming fire times are computed from the cron rules with `next_fire_times()` in `app/schedule_utils.py`, so prefetch works for cron rules exactly as it did for legacy HH:MM schedules. The per-module hash offset that spreads API calls across the warm-up window is unchanged.

## API

`POST /api/channels/{position}/schedule` accepts two payload shapes:

**Current**:
```json
{ "rules": [ { "expression": "30 9 * * *", "enabled": true } ] }
```

**Legacy** (HH:MM list, converted to cron rules on save):
```json
["09:30", "14:45"]
```

Invalid expressions are rejected with HTTP 400 and a user-facing message. Saving always writes `schedule_rules` and clears the legacy `schedule` list. The response includes a `schedule_preview` array of human-readable rule descriptions.

## Backend Utilities (`app/schedule_utils.py`)

| Function | Purpose |
|---|---|
| `validate_cron_expression()` | Validates and normalizes a cron expression (raises `ValueError`) |
| `strip_cron_prefix()` | Drops an ignored `CRON_TZ=`/`TZ=` token |
| `hhmm_to_cron()` | Converts a legacy `HH:MM` string to a daily cron expression |
| `humanize_cron()` | Human-readable label (respects 12h/24h preference) |
| `legacy_schedule_to_rules()` | Converts a legacy `schedule` list to rule dicts |
| `normalize_schedule_rules()` | Validates and de-duplicates an incoming rule payload |
| `cron_matches_minute()` | True when an expression matches the given minute |
| `next_fire_times()` | Upcoming fire datetimes within a horizon (weather prefetch) |
| `resolve_timezone_name()` | Validates a timezone string with safe fallback |

## Frontend

The Schedule Modal (`web/src/components/ScheduleModal.jsx`) is builder-first: users pick a frequency (Every day / Weekdays / Weekends / Specific days / Once a month) and a time, and the cron expression is generated for them. Raw cron editing is available behind the "Advanced (cron expression)" option, which includes a field legend, live validation, and a crontab.guru link. Schedules that fire more than once an hour show a paper-use warning before they can be added.

Helpers live in `web/src/utils.js`: `validateCronExpression()`, `describeCron()` (guarded `cronstrue` — invalid input never throws), `cronFiresSubHourly()`, and `channelScheduleRuleCount()`.

## Legacy Compatibility

Channels may still carry a `schedule` field (a list of `HH:MM` strings) from before cron rules existed. These are honored at runtime (converted on the fly by `_channel_schedule_rules()`) and shown in the UI as their cron equivalents. The first schedule edit rewrites the channel in the new format and clears the legacy list.

## Tests

- `testing/test_schedule.py` — unit tests for `schedule_utils`
- `testing/test_scheduler_integration.py` — scheduler loop, API payloads, weather prefetch interplay
