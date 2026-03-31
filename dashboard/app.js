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

    const txId = item.transaction_id;
    const policyId = item.policy_id;
    const time = new Date(item.timestamp).toLocaleTimeString();
    const statusClass = compliant ? 'compliant' : 'violation';
    const statusText = compliant ? 'Compliant' : 'Violation';
    const details = compliant
        ? `Receipt #${item.seq_no}`
        : item.violated_clause || 'Path violation';

    row.innerHTML = `
        <td><code>${txId}</code></td>
        <td><code>${policyId}</code></td>
        <td><span class="status-badge ${statusClass}">${statusText}</span></td>
        <td>${details}</td>
        <td>${time}</td>
    `;

    tbody.prepend(row);
}

function addAlertCard(v) {
    const list = document.getElementById('alert-list');
    const card = document.createElement('div');
    card.className = 'alert-card';
    card.innerHTML = `
        <div class="severity">${v.severity}</div>
        <div class="message">${v.violated_clause}</div>
        <div style="margin-top: 0.5rem; font-size: 0.75rem; color: var(--text-dim)">
            TX: ${v.transaction_id} | ${new Date(v.timestamp).toLocaleString()}
        </div>
    `;
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

document.addEventListener('DOMContentLoaded', init);
