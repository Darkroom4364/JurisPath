const API_BASE = window.location.origin;

// Load initial data
async function init() {
    await Promise.all([loadReceipts(), loadViolations()]);
    connectSSE();
}

async function loadReceipts() {
    try {
        const resp = await fetch(`${API_BASE}/api/receipts`);
        const receipts = await resp.json();
        if (receipts) receipts.forEach(r => addTxRow(r, true));
    } catch (e) {
        console.log('No receipts yet');
    }
}

async function loadViolations() {
    try {
        const resp = await fetch(`${API_BASE}/api/violations`);
        const violations = await resp.json();
        if (violations) violations.forEach(v => {
            addTxRow(v, false);
            addAlertCard(v);
        });
    } catch (e) {
        console.log('No violations yet');
    }
}

function connectSSE() {
    const source = new EventSource(`${API_BASE}/api/events`);

    source.addEventListener('violation', (e) => {
        const v = JSON.parse(e.data);
        addTxRow(v, false);
        addAlertCard(v);
        flashPath('violation');
    });

    source.onerror = () => {
        console.log('SSE disconnected, retrying...');
    };
}

function addTxRow(item, compliant) {
    const tbody = document.getElementById('tx-body');
    const row = document.createElement('tr');

    const txId = item.transaction_id || '';
    const policyId = item.policy_id || '';
    const time = new Date(item.timestamp).toLocaleTimeString();
    const statusClass = compliant ? 'compliant' : 'violation';
    const statusText = compliant ? 'Compliant' : 'Violation';
    const details = compliant
        ? `Receipt #${item.seq_no}`
        : item.violated_clause || 'Path violation';

    row.append(
        tableCodeCell(txId),
        tableCodeCell(policyId),
        tableStatusCell(statusClass, statusText),
        tableTextCell(details),
        tableTextCell(time),
    );

    tbody.prepend(row);
}

function addAlertCard(v) {
    const list = document.getElementById('alert-list');
    const card = document.createElement('div');
    card.className = 'alert-card';

    const severity = document.createElement('div');
    severity.className = 'severity';
    severity.textContent = v.severity || '';

    const message = document.createElement('div');
    message.className = 'message';
    message.textContent = v.violated_clause || '';

    const meta = document.createElement('div');
    meta.className = 'alert-meta';
    meta.textContent = `TX: ${v.transaction_id || ''} | ${new Date(v.timestamp).toLocaleString()}`;

    card.append(severity, message, meta);
    list.prepend(card);
}

function flashPath(type) {
    const path = document.getElementById('path-via-x');
    if (type === 'violation') {
        path.style.display = 'block';
        path.style.opacity = '1';
        setTimeout(() => { path.style.opacity = '0.3'; }, 2000);
    }
}

// Scenario C: Path pre-filtering display
function displayPrefilterResults(result) {
    const container = document.getElementById('prefilter-results');
    if (!container) return;

    container.replaceChildren();

    if (result.compliant && result.compliant.length > 0) {
        result.compliant.forEach(path => {
            container.appendChild(prefilterCard(path, true));
        });
    }

    if (result.non_compliant && result.non_compliant.length > 0) {
        result.non_compliant.forEach(path => {
            container.appendChild(prefilterCard(path, false));
        });
    }

    if ((!result.compliant || result.compliant.length === 0) &&
        (!result.non_compliant || result.non_compliant.length === 0)) {
        const empty = document.createElement('p');
        empty.className = 'empty-state';
        empty.textContent = 'No paths to display.';
        container.appendChild(empty);
    }
}

function tableTextCell(value) {
    const td = document.createElement('td');
    td.textContent = value == null ? '' : String(value);
    return td;
}

function tableCodeCell(value) {
    const td = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = value == null ? '' : String(value);
    td.appendChild(code);
    return td;
}

function tableStatusCell(statusClass, statusText) {
    const td = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `status-badge ${statusClass}`;
    badge.textContent = statusText;
    td.appendChild(badge);
    return td;
}

function prefilterCard(path, compliant) {
    const pathObject = path && typeof path === 'object' ? path : {};
    const hopsList = Array.isArray(pathObject.hops) ? pathObject.hops : [];

    const card = document.createElement('div');
    card.className = `prefilter-card ${compliant ? 'compliant' : 'non-compliant'}`;

    const status = document.createElement('div');
    status.className = 'prefilter-status';
    status.textContent = compliant ? 'COMPLIANT' : 'NON-COMPLIANT';

    const fingerprint = document.createElement('div');
    fingerprint.className = 'prefilter-fingerprint';
    const code = document.createElement('code');
    code.textContent = pathObject.fingerprint == null ? 'path' : String(pathObject.fingerprint);
    fingerprint.appendChild(code);

    const hops = document.createElement('div');
    hops.className = 'prefilter-hops';
    hops.textContent = hopsList
        .map(h => (h && typeof h === 'object' && h.ia != null) ? String(h.ia) : '')
        .join(' -> ');

    card.append(status, fingerprint, hops);
    return card;
}

async function filterPaths(policyId, paths) {
    try {
        const resp = await fetch(`${API_BASE}/api/filter-paths`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ policy_id: policyId, paths: paths }),
        });
        const result = await resp.json();
        displayPrefilterResults(result);
        return result;
    } catch (e) {
        console.log('Path pre-filtering failed:', e);
        return null;
    }
}

document.addEventListener('DOMContentLoaded', init);
