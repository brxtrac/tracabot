const state = { records: [], filter: 'all' };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'time unavailable';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function setPill(node, text, offline = false) {
  if (!node) return;
  node.textContent = text;
  node.classList.toggle('offline', offline);
}

async function api(path) {
  const response = await fetch(path, { headers: { accept: 'application/json' } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `request failed (${response.status})`);
  return body;
}

function indicatorChips(record) {
  const wrap = el('div', 'record-indicators');
  const indicators = record.indicators || {};
  const values = [
    ...(indicators.patterns || []).map((value) => `pattern:${value}`),
    ...(indicators.domains || []).map((value) => `domain:${value}`),
    ...(indicators.wallets || []).map((value) => `wallet:${value.slice(0, 10)}…${value.slice(-4)}`)
  ];
  if (!values.length) wrap.append(el('span', 'chip', 'no public indicator'));
  for (const value of values.slice(0, 6)) wrap.append(el('span', 'chip', value));
  return wrap;
}

function recordNode(record) {
  const item = el('li', 'record');
  const head = el('div', 'record-head');
  head.append(el('span', 'badge ' + record.claimLevel, record.claimLevel.replace(/_/g, ' ')));
  head.append(el('span', 'record-time', formatDate(record.createdAt)));
  const body = el('div');
  body.append(el('p', 'record-summary', record.summary || 'Sanitized evidence record.'));
  body.append(indicatorChips(record));
  const meta = el('div', 'record-meta');
  const confidence = el('span');
  confidence.append(document.createTextNode('confidence '));
  const strong = el('strong', '', `${Number(record.confidence || 0)}%`);
  confidence.append(strong);
  meta.append(confidence);
  meta.append(el('span', '', `${record.evidenceCount || 0} evidence item${record.evidenceCount === 1 ? '' : 's'}`));
  meta.append(el('span', '', record.publicId || 'public id unavailable'));
  item.append(head, body, meta);
  return item;
}

function visibleRecords() {
  if (state.filter === 'all') return state.records;
  if (state.filter === 'admin_enforcement') return state.records.filter((record) => record.claimLevel === 'admin_enforcement');
  return state.records.filter((record) => record.eventType === state.filter);
}

function renderLedger() {
  const list = document.querySelector('#ledger-list');
  const empty = document.querySelector('#ledger-state');
  if (!list || !empty) return;
  const records = visibleRecords();
  list.replaceChildren();
  if (!records.length) {
    list.hidden = true;
    empty.hidden = false;
    empty.textContent = state.records.length
      ? 'No public records match this filter.'
      : 'No sanitized shared-memory records yet. That is a valid empty state, not a claim that the community is safe.';
    return;
  }
  empty.hidden = true;
  list.hidden = false;
  for (const record of records) list.append(recordNode(record));
}

async function loadStatus() {
  const pill = document.querySelector('#read-status') || document.querySelector('#api-status');
  try {
    const status = await api('/api/public/status');
    setPill(pill, `reader / ${status.graph || 'tracabot'}`);
    const graph = document.querySelector('#graph-name');
    if (graph) graph.textContent = `graph: ${status.graph || 'tracabot'}`;
  } catch {
    setPill(pill, 'reader unavailable', true);
  }
}

async function loadOnboarding() {
  try {
    const info = await api('/api/public/onboarding');
    const rate = document.querySelector('#rate-limit');
    const body = document.querySelector('#body-limit');
    if (rate) rate.textContent = `${info.writeAccess?.limits?.requestsPerHour || 30} requests / hour / community`;
    if (body) body.textContent = `${info.writeAccess?.limits?.maxBodyBytes || 32768} bytes`;
  } catch {
    // Static onboarding copy still works when the API is not running.
  }
}

async function loadLedger() {
  const empty = document.querySelector('#ledger-state');
  if (!empty) return;
  try {
    const result = await api('/api/public/incidents?limit=40');
    state.records = Array.isArray(result.records) ? result.records : [];
    const refresh = document.querySelector('#last-refresh');
    if (refresh) refresh.textContent = `refreshed ${formatDate(new Date().toISOString())}`;
    renderLedger();
  } catch (error) {
    empty.textContent = `Reader API unavailable: ${error.message}. Static boundaries remain accurate; no live records are being claimed.`;
  }
}

function wireFilters() {
  const filters = [...document.querySelectorAll('.filter')];
  if (!filters.length) return;
  filters.forEach((button) => button.addEventListener('click', () => {
    state.filter = button.dataset.filter || 'all';
    filters.forEach((item) => item.classList.toggle('is-active', item === button));
    renderLedger();
  }));
}

function wireJoinForm() {
  const form = document.querySelector('#join-form');
  const status = document.querySelector('#join-status');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    status.className = 'form-status';
    status.textContent = 'Submitting request…';
    const data = Object.fromEntries(new FormData(form).entries());
    data.consent = data.consent === 'on';
    try {
      const result = await fetch('/api/public/join-requests', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(data)
      });
      const body = await result.json().catch(() => ({}));
      if (!result.ok) throw new Error(body.error || `request failed (${result.status})`);
      status.className = 'form-status ok';
      status.textContent = `Request ${body.requestId} recorded. Status: ${body.status}. No write access has been granted.`;
      form.reset();
    } catch (error) {
      status.className = 'form-status error';
      status.textContent = `Could not record request: ${error.message}`;
    }
  });
}

loadStatus();
loadOnboarding();
loadLedger();
wireFilters();
wireJoinForm();
