import React, { useState } from 'react';
import GCheckIcon from '../../assets/GCheckIcon';
import WarningIcon from '../../assets/WarningIcon';
import { adminAuthFetch } from '../../lib/adminAuthFetch';

const SETUP_STEPS = [
  <>
    Create a Slack app for your workspace at{' '}
    <a
      href="https://api.slack.com/apps"
      target="_blank"
      rel="noreferrer"
      className="underline"
    >
      api.slack.com/apps
    </a>{' '}
    (From scratch).
  </>,
  <>
    Under <strong>Socket Mode</strong>, enable Socket Mode and create an
    App-Level Token with the <code className="bg-white px-1 py-0.5 rounded">connections:write</code>{' '}
    scope. That token (xapp-...) goes in the App-Level Token field above.
  </>,
  <>
    Under <strong>OAuth &amp; Permissions</strong>, add these Bot Token Scopes:{' '}
    <code className="bg-white px-1 py-0.5 rounded">chat:write</code>,{' '}
    <code className="bg-white px-1 py-0.5 rounded">im:history</code>,{' '}
    <code className="bg-white px-1 py-0.5 rounded">reactions:write</code>,{' '}
    <code className="bg-white px-1 py-0.5 rounded">users:read</code>,{' '}
    <code className="bg-white px-1 py-0.5 rounded">files:read</code>. Then
    install the app to your workspace and copy the Bot User OAuth Token
    (xoxb-...) into the field above.
  </>,
  <>
    Under <strong>Event Subscriptions</strong>, enable events and add{' '}
    <code className="bg-white px-1 py-0.5 rounded">message.im</code> under
    Subscribe to bot events.
  </>,
  <>
    Optional: under <strong>Slash Commands</strong>, create{' '}
    <code className="bg-white px-1 py-0.5 rounded">/channels</code> (lists dial
    channels) and <code className="bg-white px-1 py-0.5 rounded">/channel</code>{' '}
    (prints a channel, e.g. /channel 3). Any request URL works - PC-1 uses
    Socket Mode.
  </>,
  <>
    In Slack, open the app's <strong>Messages</strong> tab and send it a DM.
    Text, links, and images all print. Links print as QR codes.
  </>,
];

/**
 * Setup walkthrough + connection test for the Slack module.
 * Used in SchemaForm with ui:widget: "slack-help".
 */
const SlackHelp = ({ rootValue = {} }) => {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState(null);

  const botToken = String(rootValue.bot_token || '').trim();
  const appToken = String(rootValue.app_token || '').trim();

  const handleTest = async () => {
    setTesting(true);
    setResult(null);
    try {
      const response = await adminAuthFetch('/api/slack/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bot_token: botToken, app_token: appToken }),
      });
      const data = await response.json();
      setResult(data);
    } catch (err) {
      setResult({ ok: false, error: err.message });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="mb-4 space-y-3">
      <div className="space-y-3">
        <button
          type="button"
          onClick={handleTest}
          disabled={testing || !botToken || !appToken}
          className="text-sm px-3 py-1.5 border-2 border-gray-300 rounded-lg hover:border-black disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {testing ? (
            <span className="flex items-center gap-2">
              <span className="w-3 h-3 border-2 border-black border-t-transparent rounded-full animate-spin"></span>
              Testing...
            </span>
          ) : (
            'Test Connection'
          )}
        </button>

        {result && (
          <div
            className={`p-3 rounded-lg text-sm border-2 ${
              result.ok ? 'bg-gray-50 border-gray-300' : 'bg-white border-black border-dashed'
            }`}
          >
            {result.ok ? (
              <div className="flex items-center gap-2 text-black font-bold">
                <GCheckIcon className="w-4 h-4" />
                <span>
                  Connected to {result.team || 'workspace'}
                  {result.bot ? ` as @${result.bot}` : ''}
                </span>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-2 text-black font-bold mb-1">
                  <WarningIcon className="w-4 h-4" />
                  <span>Connection failed</span>
                </div>
                <div className="text-gray-600 text-xs">{result.error}</div>
              </>
            )}
          </div>
        )}
      </div>

      <div className="rounded-lg border-2 border-dashed border-zinc-300 bg-zinc-50 p-4 space-y-2">
        <div className="text-sm font-bold text-black">How to connect Slack</div>
        <ol className="list-decimal pl-4 space-y-2">
          {SETUP_STEPS.map((step, idx) => (
            <li key={idx} className="text-xs text-zinc-600 leading-5">
              {step}
            </li>
          ))}
        </ol>
        <p className="text-xs text-zinc-500 leading-5 pt-1">
          Messages print as they arrive, even when this module is not on the
          active dial channel. Pressing the print button on a channel with this
          module prints a connection status receipt.
        </p>
      </div>
    </div>
  );
};

export default SlackHelp;
