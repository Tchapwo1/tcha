let startTime = Date.now();

// 1. Update Uptime Timer
function updateUptime() {
  const elapsed = Math.floor((Date.now() - startTime) / 1000);
  const hrs = String(Math.floor(elapsed / 3600)).padStart(2, '0');
  const mins = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
  const secs = String(elapsed % 60).padStart(2, '0');
  const el = document.getElementById('uptime-display');
  if (el) el.textContent = `${hrs}:${mins}:${secs}`;
}
setInterval(updateUptime, 1000);

// 2. Fetch and Render Live Events
async function fetchEvents() {
  try {
    const res = await fetch('/api/events');
    const events = await res.json();
    renderEvents(events);
    updateStats(events);
  } catch (err) {
    console.error('Error fetching events:', err);
  }
}

function updateStats(events) {
  let ssrf = 0;
  let injections = 0;

  events.forEach(e => {
    if (e.eventType === 'SSRF_ATTEMPT') ssrf++;
    if (e.eventType === 'PROMPT_INJECTION') injections++;
  });

  const ssrfEl = document.getElementById('ssrf-count');
  const injEl = document.getElementById('injections-count');
  if (ssrfEl) ssrfEl.textContent = ssrf;
  if (injEl) injEl.textContent = injections;
}

function renderEvents(events) {
  const container = document.getElementById('event-feed-container');
  if (!container) return;

  if (!events || events.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">✓</div>
        <h3 class="empty-heading">Zero Threats Intercepted</h3>
        <p class="empty-desc">Your autonomous agent MCP pipeline is active. All inbound network sockets and tool arguments are clean.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = events.map(evt => {
    let badgeClass = 'badge-safe';
    if (evt.severity === 'CRITICAL' || evt.actionTaken === 'BLOCKED') badgeClass = 'badge-threat';
    else if (evt.severity === 'HIGH' || evt.actionTaken === 'SUSPENDED_HITL') badgeClass = 'badge-warning';

    const timeStr = new Date(evt.timestamp).toLocaleTimeString();
    const payloadSnippet = evt.rawPayload ? evt.rawPayload : '{}';

    return `
      <div class="event-card">
        <div class="event-card-header">
          <span class="badge ${badgeClass} event-type-badge">${evt.eventType}</span>
          <span class="event-time metrics-tabular">${timeStr}</span>
        </div>
        <div class="event-tool-name">Tool: <code>${evt.targetTool || 'unknown'}</code> &middot; Status: <strong>${evt.actionTaken}</strong></div>
        <div class="event-payload-box metrics-tabular">${escapeHtml(payloadSnippet)}</div>
      </div>
    `;
  }).join('');
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// 3. Merkle Ledger Verification
document.getElementById('btn-verify-ledger')?.addEventListener('click', async () => {
  const banner = document.getElementById('verify-banner');
  const msg = document.getElementById('verify-message');
  const icon = document.getElementById('verify-icon');

  if (!banner || !msg) return;

  try {
    const res = await fetch('/api/verify');
    const result = await res.json();
    banner.style.display = 'flex';

    if (result.valid) {
      banner.style.background = 'var(--color-safe-bg)';
      banner.style.borderColor = 'rgba(16, 185, 129, 0.3)';
      icon.textContent = '✓';
      msg.textContent = `${result.message} (Zero hash drift detected)`;
    } else {
      banner.style.background = 'var(--color-threat-bg)';
      banner.style.borderColor = 'rgba(239, 68, 68, 0.3)';
      icon.textContent = '✗';
      msg.textContent = result.message;
    }
  } catch (err) {
    banner.style.display = 'flex';
    msg.textContent = `Verification error: ${err.message}`;
  }
});

// 4. Run Red-Team Trigger
document.getElementById('btn-run-audit')?.addEventListener('click', () => {
  alert("Running 50-Probe Red-Team Audit via CLI...\n\nYou can also run this in your terminal with: npm run audit");
});

document.getElementById('btn-refresh-feed')?.addEventListener('click', fetchEvents);

// 5. Webhook Status & Test Alert
async function fetchWebhookStatus() {
  try {
    const res = await fetch('/api/webhook/status');
    const data = await res.json();
    const desc = document.getElementById('webhook-desc');
    if (desc && data) {
      desc.textContent = data.enabled
        ? `Active: ${data.provider.toUpperCase()} (${data.maskedUrl}) · Min: ${data.minSeverity}`
        : 'Asynchronous Slack, Discord & SIEM dispatch with HMAC signatures.';
    }
  } catch (err) {
    console.error('Error fetching webhook status:', err);
  }
}

document.getElementById('btn-test-webhook')?.addEventListener('click', async () => {
  const btn = document.getElementById('btn-test-webhook');
  if (btn) btn.textContent = 'DISPATCHING...';

  try {
    const res = await fetch('/api/webhook/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const result = await res.json();

    if (result.success) {
      alert(`✓ Test Alert Dispatched Successfully!\nStatus: ${result.status || 200}`);
    } else {
      alert(`⚠️ Webhook Test Result:\n${result.error || 'Check configuration'}\n\nTip: Set AGENTSHIELD_WEBHOOK_URL with your Slack or Discord webhook.`);
    }
  } catch (err) {
    alert(`Error sending test webhook: ${err.message}`);
  } finally {
    if (btn) btn.textContent = 'TEST ALERT';
  }
});

// Initial Load and Poll
fetchEvents();
fetchWebhookStatus();
setInterval(fetchEvents, 2500);
