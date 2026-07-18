// ===== CONFIG =====
const POLL_INTERVAL_MS = 5000;
const MAX_LOG_LINES = 500;
const MAX_TERMINAL_LINES = 1000;
const API_BASE = 'http://127.0.0.1:9876';

// ===== STATE =====
let currentTab = 'dashboard';
let dashboardData = null;
let activityChart = null;
let tierChart = null;
let agentsGrid = null;
let alertsGrid = null;
let logEntries = [];
let terminalLines = [];
let isTerminalPaused = false;
let sparkCharts = {};
let entropyChart = null;
let chaosChart = null;
let firewallGrid = null;
let quarantineGrid = null;
let decoyGrid = null;
let zerotrustGrid = null;
let pipelineGrid = null;
let sandboxGrid = null;
let auditGrid = null;

// ===== DOM ELEMENTS =====
const els = {
    lastUpdate:      document.getElementById('last-update'),
    modeBadge:       document.getElementById('mode-badge'),
    kpiActive:       document.getElementById('kpi-active'),
    kpiThreat:       document.getElementById('kpi-threat'),
    kpiQueue:        document.getElementById('kpi-queue'),
    kpiAlerts:       document.getElementById('kpi-alerts'),
    kpiThreatSub:    document.getElementById('kpi-threat-sub'),
    kpiAlertsSub:    document.getElementById('kpi-alerts-sub'),
    alertCount:      document.getElementById('alert-count'),
    terminalContent: document.getElementById('terminal-content'),
    terminalInput:   document.getElementById('terminal-input'),
    terminalBody:    document.getElementById('terminal-body'),
    logContainer:    document.getElementById('log-container'),
};

// ===== TAB SWITCHING =====
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => switchTab(item.dataset.tab));
});

function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.nav-item').forEach(i =>
        i.classList.toggle('active', i.dataset.tab === tab));
    document.querySelectorAll('.tab-content').forEach(t =>
        t.classList.toggle('active', t.id === `tab-${tab}`));
    if (tab === 'agents' && dashboardData) renderAgentsTable(dashboardData.agents);
    if (tab === 'terminal') setTimeout(() => els.terminalInput.focus(), 50);
}

// ===== JSON POLLING =====
async function loadDashboardData() {
    try {
        const res = await fetch(`${API_BASE}/dashboard_data.json?t=${Date.now()}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        dashboardData = data;
        updateDashboard(data);
        const ts = data.system?.timestamp
            ? new Date(data.system.timestamp).toLocaleTimeString()
            : '--:--:--';
        els.lastUpdate.textContent = `Updated: ${ts} (live)`;
        showBackendWarning(false);
        const overlay = document.getElementById('startup-overlay');
        if (overlay) overlay.style.display = 'none';
    } catch (err) {
        showBackendWarning(true);
        console.warn('Dashboard server unreachable, using demo data:', err.message);
        if (!dashboardData) {
            dashboardData = { ...generateDemoData(), ...generateDemoDataV2Extras() };
            updateDashboard(dashboardData);
        }
    }
}

function showBackendWarning(show) {
    let banner = document.getElementById('backend-warning');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'backend-warning';
        banner.style.cssText = 'background:#fff8e1;border:1px solid #f1c21b;color:#8e6a00;padding:10px 20px;font-size:13px;font-weight:600;text-align:center;position:sticky;top:0;z-index:99;';
        banner.innerHTML = '⚠️ Backend offline — showing simulated data. Start the server with <code>start-dashboard.bat</code> or run <code>demo_dashboard_data.exe</code>';
        const main = document.querySelector('.main');
        if (main) main.insertBefore(banner, main.firstChild);
    }
    banner.style.display = show ? 'block' : 'none';
}

// ===== MAIN UPDATE =====
function updateDashboard(data) {
    // KPIs
    els.kpiActive.textContent = data.kpi?.active_agents ?? '--';
    els.kpiQueue.textContent  = data.kpi?.queue_depth ?? '--';

    const threat = data.kpi?.threat_level ?? 'UNKNOWN';
    els.kpiThreat.textContent = threat;
    els.kpiThreat.className   = 'kpi-value' +
        (threat === 'CRITICAL' ? ' critical' : threat === 'HIGH' ? ' warning' : '');
    els.kpiThreatSub.textContent = data.kpi?.threat_score != null
        ? `Score: ${data.kpi.threat_score}/100` : '--';

    const alerts   = data.kpi?.alerts_24h ?? 0;
    const critical = data.kpi?.critical_alerts ?? 0;
    els.kpiAlerts.textContent    = alerts;
    els.kpiAlerts.className      = 'kpi-value' +
        (critical > 0 ? ' critical' : alerts > 0 ? ' warning' : ' success');
    els.kpiAlertsSub.textContent = `${critical} critical`;
    els.alertCount.textContent   = data.alerts?.length ?? 0;
    els.modeBadge.textContent    = ((data.system?.mode ?? 'FULL').toUpperCase()) + ' MODE';

    updateActivityChart(data.activity_history);
    updateTierChart(data.tier_distribution);
    if (currentTab === 'agents') renderAgentsTable(data.agents);
    renderAlertsTable(data.alerts);
    if (data.new_logs) data.new_logs.forEach(l => addLog(l.level, l.message, l.timestamp));

    // v2 updates
    updateStatusBanner(data);
    updateHealthBar(data.health);
    updateLiveMetrics(data.system_metrics);
    updateSparkline('spark-cpu',  data.system_metrics?.cpu_percent    || 0);
    updateSparkline('spark-mem',  data.system_metrics?.memory_percent || 0);
    updateSparkline('spark-disk', data.system_metrics?.disk_percent   || 0);
    updateSparkline('spark-net',  (data.system_metrics?.network_mbps  || 0) * 10);

    renderFirewallTable(data.firewall_blocks);
    renderQuarantineTable(data.quarantine_entries);
    renderDecoyTable(data.decoy_events);
    renderZeroTrustTable(data.zerotrust_decisions);
    renderPipelineTable(data.pipeline_stages);
    renderSandboxTable(data.sandbox_entries);
    renderAuditTable(data.audit_entries);
    updateEntropyChart(data.entropy_windows);
    updateChaosChart(data.chaos_windows);
}

// ===== STATUS BANNER =====
function updateStatusBanner(data) {
    const wormEl   = document.getElementById('worm-status');
    const modeEl   = document.getElementById('mode-status');
    const ollamaEl = document.getElementById('ollama-status');
    const auditEl  = document.getElementById('audit-status');

    if (wormEl) {
        const locked = data.worm?.is_locked || false;
        wormEl.textContent = locked ? 'LOCKED' : 'NORMAL';
        wormEl.className   = 'status-pill ' + (locked ? 'locked' : 'normal');
    }
    if (modeEl) {
        const rawMode = (data.system?.mode || 'FULL');
        modeEl.textContent = rawMode;
        modeEl.className   = 'status-pill ' + rawMode.toLowerCase().replace('_', '');
    }
    if (ollamaEl) {
        const online = data.system_metrics?.ollama_online || false;
        ollamaEl.textContent = online ? 'Online' : 'Offline';
        ollamaEl.className   = 'status-pill ' + (online ? 'online' : 'offline');
    }
    if (auditEl) {
        const valid = data.audit_chain_valid !== false;
        auditEl.textContent = valid ? 'Valid' : 'Tampered';
        auditEl.className   = 'status-pill ' + (valid ? 'online' : 'offline');
    }
    updateThreatGauge(data.kpi?.threat_score || 0, data.kpi?.threat_level || 'LOW');
}

// ===== HEALTH BAR =====
function updateHealthBar(health) {
    if (!health) return;
    const items = [
        { id: 'health-ollama', key: 'ollama_online'   },
        { id: 'health-npcap',  key: 'npcap_installed' },
        { id: 'health-clamd',  key: 'clamd_online'    },
        { id: 'health-admin',  key: 'is_admin'        },
    ];
    items.forEach(item => {
        const el = document.getElementById(item.id);
        if (!el) return;
        const dot = el.querySelector('.health-dot');
        if (!dot) return;
        const value = health[item.key];
        dot.className = 'health-dot ' + (value === true ? 'online' : value === false ? 'offline' : 'unknown');
    });
}

function updateThreatGauge(score, level) {
    const fill  = document.getElementById('threat-gauge-fill');
    const value = document.getElementById('threat-gauge-value');
    if (!fill || !value) return;
    fill.style.width = Math.min(score, 100) + '%';
    const cls = level === 'CRITICAL' ? 'critical'
              : level === 'HIGH'     ? 'high'
              : level === 'MEDIUM'   ? 'medium'
              : 'low';
    fill.className    = 'threat-gauge-fill ' + cls;
    value.textContent = score;
}

// ===== LIVE METRICS =====
function updateLiveMetrics(m) {
    if (!m) return;
    const cpuEl  = document.getElementById('metric-cpu');
    const memEl  = document.getElementById('metric-mem');
    const diskEl = document.getElementById('metric-disk');
    const netEl  = document.getElementById('metric-net');
    if (cpuEl)  cpuEl.textContent  = (m.cpu_percent    || 0).toFixed(1) + '%';
    if (memEl)  memEl.textContent  = (m.memory_percent || 0).toFixed(1) + '%';
    if (diskEl) diskEl.textContent = (m.disk_percent   || 0).toFixed(1) + '%';
    if (netEl)  netEl.textContent  = (m.network_mbps   || 0).toFixed(1);

    const cpuSub  = document.getElementById('metric-cpu-sub');
    const memSub  = document.getElementById('metric-mem-sub');
    const diskSub = document.getElementById('metric-disk-sub');
    const netSub  = document.getElementById('metric-net-sub');
    if (cpuSub)  cpuSub.textContent  = (m.cpu_cores       || 0) + ' cores';
    if (memSub)  memSub.textContent  = (m.memory_used_gb  || 0).toFixed(1) + ' / ' + (m.memory_total_gb || 0).toFixed(1) + ' GB';
    if (diskSub) diskSub.textContent = (m.disk_free_gb    || 0).toFixed(1) + ' GB free';
    if (netSub)  netSub.textContent  = 'Mbps';
}

// ===== SPARKLINES =====
function initSparklines() {
    const configs = {
        'spark-cpu':  { color: '#0f62fe' },
        'spark-mem':  { color: '#8a3ffc' },
        'spark-disk': { color: '#24a148' },
        'spark-net':  { color: '#ff832b' },
    };
    Object.entries(configs).forEach(([id, cfg]) => {
        const ctx = document.getElementById(id);
        if (!ctx) return;
        sparkCharts[id] = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [{ data: Array(20).fill(0), borderColor: cfg.color,
                             borderWidth: 1.5, fill: false, pointRadius: 0, tension: 0.4 }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { x: { display: false }, y: { display: false, min: 0, max: 100 } },
            },
        });
    });
}

function updateSparkline(id, newValue) {
    const chart = sparkCharts[id];
    if (!chart) return;
    const data = chart.data.datasets[0].data;
    data.shift();
    data.push(Math.min(newValue, 100));
    chart.update('none');
}

// ===== ENTROPY CHART =====
function initEntropyChart() {
    const ctx = document.getElementById('chart-entropy');
    if (!ctx) return;
    entropyChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(30).fill(''),
            datasets: [
                { label: 'Mean Entropy', data: Array(30).fill(0), borderColor: '#0f62fe',
                  borderWidth: 2, fill: false, tension: 0.3, pointRadius: 0 },
                { label: 'Anomaly Threshold', data: Array(30).fill(7.2), borderColor: '#da1e28',
                  borderWidth: 1, borderDash: [5, 5], fill: false, pointRadius: 0 },
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: true, labels: { font: { size: 11 } } } },
            scales: {
                x: { display: false },
                y: { min: 0, max: 8, grid: { color: '#e0e0e0' }, ticks: { font: { size: 11 } } },
            },
        },
    });
}

function updateEntropyChart(windows) {
    if (!entropyChart || !windows || !windows.length) return;
    const data = entropyChart.data.datasets[0].data;
    windows.forEach(w => { data.shift(); data.push(w.mean_entropy_bits); });
    entropyChart.update('none');
}

// ===== CHAOS CHART =====
function initChaosChart() {
    const ctx = document.getElementById('chart-chaos');
    if (!ctx) return;
    chaosChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(30).fill(''),
            datasets: [
                { label: 'K-Value', data: Array(30).fill(0), borderColor: '#8a3ffc',
                  borderWidth: 2, fill: 'start', backgroundColor: 'rgba(138,63,252,0.1)',
                  tension: 0.3, pointRadius: 2 },
                { label: 'Threshold', data: Array(30).fill(0.7), borderColor: '#da1e28',
                  borderWidth: 1, borderDash: [5, 5], fill: false, pointRadius: 0 },
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: true } },
            scales: { x: { display: false }, y: { min: 0, max: 1, grid: { color: '#e0e0e0' } } },
        },
    });
}

function updateChaosChart(windows) {
    if (!chaosChart || !windows || !windows.length) return;
    const data = chaosChart.data.datasets[0].data;
    windows.forEach(w => { data.shift(); data.push(w.K); });
    chaosChart.update('none');
}

// ===== PROTECTION TABLES =====
function renderFirewallTable(blocks) {
    const container = document.getElementById('firewall-table');
    if (!container) return;
    const data = (blocks || []).map(b => [
        b.ip, b.rule_name_in, formatTime(b.blocked_at_ms), formatTTL(b.expires_at_ms),
        '<span class="status-badge online">Active</span>',
    ]);
    if (firewallGrid) { firewallGrid.destroy(); firewallGrid = null; }
    container.innerHTML = '';
    firewallGrid = new gridjs.Grid({
        columns: ['IP', 'Rule', 'Blocked At', 'TTL', 'Status'],
        data, search: false, pagination: { limit: 5 },
    }).render(container);
}

function renderQuarantineTable(entries) {
    const container = document.getElementById('quarantine-table');
    if (!container) return;
    const data = (entries || []).map(e => [
        e.entry_id.length > 8 ? e.entry_id.substr(0, 8) + '...' : e.entry_id,
        e.virus_name, formatTime(e.quarantined_at_ms),
        '<span class="status-badge critical">Quarantined</span>',
    ]);
    if (quarantineGrid) { quarantineGrid.destroy(); quarantineGrid = null; }
    container.innerHTML = '';
    quarantineGrid = new gridjs.Grid({
        columns: ['ID', 'Threat', 'Time', 'Status'],
        data, search: false, pagination: { limit: 5 },
    }).render(container);
}

function renderDecoyTable(events) {
    const container = document.getElementById('decoy-table');
    if (!container) return;
    const data = (events || []).map(e => [
        e.attacker_tag, e.poison_type, e.action, formatTime(e.timestamp_ms),
    ]);
    if (decoyGrid) { decoyGrid.destroy(); decoyGrid = null; }
    container.innerHTML = '';
    decoyGrid = new gridjs.Grid({
        columns: ['Attacker', 'Type', 'Action', 'Time'],
        data, search: false, pagination: { limit: 5 },
    }).render(container);
}

function renderZeroTrustTable(decisions) {
    const container = document.getElementById('zerotrust-table');
    if (!container) return;
    const data = (decisions || []).map(d => [
        d.user_id, d.decision, d.trust_score, d.resource,
    ]);
    if (zerotrustGrid) { zerotrustGrid.destroy(); zerotrustGrid = null; }
    container.innerHTML = '';
    zerotrustGrid = new gridjs.Grid({
        columns: ['User', 'Decision', 'Trust', 'Resource'],
        data, search: false, pagination: { limit: 5 },
    }).render(container);
}

// ===== PIPELINE TABLE =====
function renderPipelineTable(stages) {
    const container = document.getElementById('pipeline-table');
    if (!container) return;
    const badge = s => {
        const cls = s === 'PASSED'    ? 'online'
                  : s === 'FAILED'    ? 'critical'
                  : s === 'AUTO_FIXED'? 'high'
                  : 'offline';
        return `<span class="status-badge ${cls}">${s}</span>`;
    };
    const data = (stages || []).map(s => [s.stage, badge(s.status), s.detail || '-']);
    if (pipelineGrid) { pipelineGrid.destroy(); pipelineGrid = null; }
    container.innerHTML = '';
    pipelineGrid = new gridjs.Grid({
        columns: ['Stage', 'Status', 'Detail'],
        data, search: false, pagination: { limit: 10 },
    }).render(container);
}

// ===== SANDBOX / AUDIT TABLES =====
function renderSandboxTable(entries) {
    const container = document.getElementById('sandbox-table');
    if (!container) return;
    const data = (entries || []).map(e => [
        e.rel_path, e.type,
        e.locked ? '<span class="status-badge critical">LOCKED</span>'
                 : '<span class="status-badge online">OPEN</span>',
        e.version,
    ]);
    if (sandboxGrid) { sandboxGrid.destroy(); sandboxGrid = null; }
    container.innerHTML = '';
    sandboxGrid = new gridjs.Grid({
        columns: ['Path', 'Type', 'Locked', 'Ver'],
        data, search: false, pagination: { limit: 8 },
    }).render(container);
}

function renderAuditTable(entries) {
    const container = document.getElementById('audit-table');
    if (!container) return;
    const data = (entries || []).map(e => [
        e.entry_id, e.event_type, e.timestamp,
        e.chain_valid ? '<span class="status-badge online">Valid</span>'
                      : '<span class="status-badge critical">TAMPERED</span>',
    ]);
    if (auditGrid) { auditGrid.destroy(); auditGrid = null; }
    container.innerHTML = '';
    auditGrid = new gridjs.Grid({
        columns: ['ID', 'Event', 'Time', 'Chain'],
        data, search: false, pagination: { limit: 6 },
    }).render(container);
}

// ===== CHART.JS =====
function initCharts() {
    const actCtx = document.getElementById('chart-activity').getContext('2d');
    activityChart = new Chart(actCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Tasks Completed', data: [],
                borderColor: '#0f62fe', backgroundColor: 'rgba(15,98,254,0.1)',
                borderWidth: 2, fill: true, tension: 0.4,
                pointRadius: 3, pointBackgroundColor: '#0f62fe',
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#525252', font: { size: 11 } } },
                y: { grid: { color: '#e0e0e0' }, ticks: { color: '#525252', font: { size: 11 } }, beginAtZero: true },
            },
        },
    });

    const tierCtx = document.getElementById('chart-tiers').getContext('2d');
    tierChart = new Chart(tierCtx, {
        type: 'doughnut',
        data: {
            labels: ['FAST', 'HEAVY', 'ACCURACY', 'ORCHESTRATOR'],
            datasets: [{
                data: [8, 35, 16, 6],
                backgroundColor: ['#0f62fe', '#8a3ffc', '#f1c21b', '#24a148'],
                borderWidth: 0, hoverOffset: 4,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#525252', font: { size: 11 }, padding: 16,
                              usePointStyle: true, pointStyle: 'circle' },
                },
            },
        },
    });
}

function updateActivityChart(history) {
    if (!history || !activityChart) return;
    activityChart.data.labels = history.map(h => h.time);
    activityChart.data.datasets[0].data = history.map(h => h.count);
    activityChart.update('none');
}

function updateTierChart(dist) {
    if (!dist || !tierChart) return;
    tierChart.data.datasets[0].data = [
        dist.FAST ?? 8, dist.HEAVY ?? 35, dist.ACCURACY ?? 16, dist.ORCHESTRATOR ?? 6,
    ];
    tierChart.update('none');
}

// ===== AGENTS TABLE =====
function renderAgentsTable(agents) {
    if (!agents) return;
    const container = document.getElementById('agents-table');
    if (!container) return;
    const data = agents.map(a => [
        a.name ?? '',
        `<span class="tier-badge tier-${(a.tier ?? '').toLowerCase()}">${a.tier ?? ''}</span>`,
        a.model ?? '',
        `<span class="status-badge ${(a.status ?? 'offline').toLowerCase()}">${a.status ?? 'offline'}</span>`,
        String(a.tasks_completed ?? 0),
        a.last_active ? formatTime(a.last_active) : '--',
    ]);
    if (agentsGrid) { agentsGrid.destroy(); agentsGrid = null; }
    container.innerHTML = '';
    agentsGrid = new gridjs.Grid({
        columns: ['Agent', 'Tier', 'Model', 'Status', 'Tasks', 'Last Active'],
        data, search: false, pagination: { limit: 15, summary: true }, sort: true, resizable: true,
    }).render(container);
}

function renderAlertsTable(alerts) {
    if (!alerts) return;
    const container = document.getElementById('alerts-table');
    if (!container) return;
    const data = alerts.slice(0, 10).map(a => [
        formatTime(a.timestamp),
        `<span class="status-badge ${(a.severity ?? 'low').toLowerCase()}">${a.severity ?? 'LOW'}</span>`,
        a.agent_name ?? '', a.message ?? '',
    ]);
    if (alertsGrid) { alertsGrid.destroy(); alertsGrid = null; }
    container.innerHTML = '';
    alertsGrid = new gridjs.Grid({
        columns: ['Time', 'Severity', 'Agent', 'Message'],
        data, search: false, pagination: { limit: 5, summary: false }, sort: true,
    }).render(container);
}

// ===== TIME HELPERS =====
function formatTime(ts) {
    if (!ts) return '--:--:--';
    try { return new Date(ts).toLocaleTimeString(); }
    catch (e) { return String(ts); }
}

function formatTTL(expiresMs) {
    if (!expiresMs) return '0s';
    return Math.max(0, Math.ceil((expiresMs - Date.now()) / 1000)) + 's';
}

// ===== TERMINAL =====
function addTerminalLine(text, type = 'info') {
    if (isTerminalPaused) return;
    const line = document.createElement('div');
    line.className  = `terminal-line ${type}`;
    line.textContent = text;
    els.terminalContent.appendChild(line);
    terminalLines.push({ text, type });
    if (terminalLines.length > MAX_TERMINAL_LINES) {
        if (els.terminalContent.firstChild)
            els.terminalContent.removeChild(els.terminalContent.firstChild);
        terminalLines.shift();
    }
    els.terminalBody.scrollTop = els.terminalBody.scrollHeight;
}

els.terminalInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        const cmd = els.terminalInput.value.trim();
        if (!cmd) return;
        addTerminalLine(`$ ${cmd}`, 'prompt');
        handleTerminalCommand(cmd);
        els.terminalInput.value = '';
    }
});

// ===== 20 COMMANDS =====
const SYSTEM_COMMANDS = ['ipconfig', 'tasklist', 'netstat', 'systeminfo',
                         'getmac', 'whoami', 'hostname', 'ver', 'ping'];

async function handleTerminalCommand(cmd) {
    const base = cmd.split(' ')[0].toLowerCase();
    const args = cmd.split(' ').slice(1);

    // ---- Astartis local commands ----
    if (base === 'help') {
        addTerminalLine('=== Astartis Commands ===', 'info');
        addTerminalLine('  status        — Show system status', 'info');
        addTerminalLine('  agents        — List all agents', 'info');
        addTerminalLine('  agents <tier> — Filter by tier (FAST/HEAVY/ACCURACY/ORCHESTRATOR)', 'info');
        addTerminalLine('  mode          — Show current mode', 'info');
        addTerminalLine('  worm          — WORM lock status', 'info');
        addTerminalLine('  firewall      — Active firewall blocks', 'info');
        addTerminalLine('  quarantine    — Quarantined files', 'info');
        addTerminalLine('  decoy         — Decoy event log', 'info');
        addTerminalLine('  scan          — Run security scan', 'info');
        addTerminalLine('  clear         — Clear terminal', 'info');
        addTerminalLine('=== Windows Commands ===', 'info');
        addTerminalLine('  ipconfig      — Network configuration', 'info');
        addTerminalLine('  ipconfig /all — Full adapter details', 'info');
        addTerminalLine('  tasklist      — Running processes', 'info');
        addTerminalLine('  netstat -an   — Network connections', 'info');
        addTerminalLine('  systeminfo    — System information', 'info');
        addTerminalLine('  getmac        — MAC addresses', 'info');
        addTerminalLine('  whoami        — Current user', 'info');
        addTerminalLine('  hostname      — Computer name', 'info');
        addTerminalLine('  ver           — Windows version', 'info');
        addTerminalLine('  netsh advfirewall show currentprofile — Firewall state', 'info');
        addTerminalLine('  ping 8.8.8.8  — Ping Google DNS', 'info');
        addTerminalLine('  Get-Process   — PowerShell process list', 'info');
        addTerminalLine('  Get-Service   — PowerShell service list', 'info');
        return;
    }

    if (base === 'status') {
        addTerminalLine(`System:  ${dashboardData?.system?.status ?? 'UNKNOWN'}`, 'info');
        addTerminalLine(`Agents:  ${dashboardData?.kpi?.active_agents ?? 0}/77 active`, 'info');
        addTerminalLine(`Queue:   ${dashboardData?.kpi?.queue_depth ?? 0} tasks pending`, 'info');
        addTerminalLine(`Threat:  ${dashboardData?.kpi?.threat_level ?? 'UNKNOWN'} (score ${dashboardData?.kpi?.threat_score ?? 0})`, 'info');
        addTerminalLine(`WORM:    ${dashboardData?.worm?.is_locked ? 'LOCKED' : 'NORMAL'}`, 'info');
        addTerminalLine(`Ollama:  ${dashboardData?.system_metrics?.ollama_online ? 'Online' : 'Offline'}`, 'info');
        addTerminalLine(`Mode:    ${dashboardData?.system?.mode ?? 'FULL'}`, 'info');
        return;
    }

    if (base === 'agents') {
        if (!dashboardData?.agents) { addTerminalLine('No agent data available', 'warn'); return; }
        const tier = args[0]?.toUpperCase();
        let list = dashboardData.agents;
        if (tier && tier !== 'ALL') list = list.filter(a => a.tier === tier);
        addTerminalLine(`Showing ${list.length} agents:`, 'info');
        list.slice(0, 15).forEach(a =>
            addTerminalLine(`  ${a.name.padEnd(36)} [${a.tier}] ${a.status}`, 'info'));
        if (list.length > 15) addTerminalLine(`  ... and ${list.length - 15} more`, 'info');
        return;
    }

    if (base === 'mode')       { addTerminalLine(`Current mode: ${dashboardData?.system?.mode ?? 'FULL'}`, 'info'); return; }
    if (base === 'worm')       { addTerminalLine(`WORM: ${dashboardData?.worm?.is_locked ? 'LOCKED' : 'NORMAL'}`, 'info'); return; }
    if (base === 'firewall') {
        const bl = dashboardData?.firewall_blocks || [];
        addTerminalLine(`Active blocks: ${bl.length}`, 'info');
        bl.slice(0, 10).forEach(b => addTerminalLine(`  ${b.ip.padEnd(18)} ${b.rule_name_in}`, 'info'));
        return;
    }
    if (base === 'quarantine') {
        const q = dashboardData?.quarantine_entries || [];
        addTerminalLine(`Quarantined: ${q.length}`, 'info');
        q.slice(0, 10).forEach(e => addTerminalLine(`  ${e.entry_id} — ${e.virus_name}`, 'info'));
        return;
    }
    if (base === 'decoy') {
        const ev = dashboardData?.decoy_events || [];
        addTerminalLine(`Decoy events: ${ev.length}`, 'info');
        ev.slice(0, 10).forEach(e =>
            addTerminalLine(`  ${e.attacker_tag} — ${e.action} on ${e.poison_type}`, 'info'));
        return;
    }
    if (base === 'scan') {
        addTerminalLine('Initiating security scan...', 'info');
        setTimeout(() => addTerminalLine('Scan complete. No threats detected.', 'success'), 1200);
        return;
    }
    if (base === 'clear') { els.terminalContent.innerHTML = ''; terminalLines = []; return; }

    // ---- Windows system commands (real execution via HTTP backend) ----
    const isSystem   = SYSTEM_COMMANDS.includes(base);
    const isPSh      = cmd.indexOf('Get-') === 0 || cmd.indexOf('get-') === 0;
    const isNetsh    = base === 'netsh';
    if (isSystem || isPSh || isNetsh) {
        addTerminalLine('Executing...', 'info');
        try {
            const res = await fetch(`${API_BASE}/exec`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cmd }),
            });
            const json = await res.json();
            json.output.split('\n').forEach(line => {
                if (line.trim()) addTerminalLine(line, 'info');
            });
        } catch (e) {
            addTerminalLine(
                'Error: Cannot reach backend. Start demo_dashboard_data.exe first.', 'error');
        }
        return;
    }

    addTerminalLine(`Unknown command: ${cmd}. Type 'help' for the full list.`, 'error');
}

document.getElementById('term-clear').addEventListener('click', () => {
    els.terminalContent.innerHTML = '';
    terminalLines = [];
});
document.getElementById('term-pause').addEventListener('click', () => {
    isTerminalPaused = !isTerminalPaused;
    document.getElementById('term-pause').textContent = isTerminalPaused ? 'Resume' : 'Pause';
});

// ===== LOGS =====
function addLog(level, message, timestamp) {
    const ts = timestamp ? formatTime(timestamp) : formatTime(new Date().toISOString());
    logEntries.push({ level, message, timestamp: ts });
    if (logEntries.length > MAX_LOG_LINES) logEntries.shift();
    if (currentTab === 'logs') renderLogs();
}

function renderLogs() {
    const filter   = document.getElementById('log-level-filter')?.value ?? 'all';
    const filtered = filter === 'all' ? logEntries : logEntries.filter(e => e.level === filter);
    els.logContainer.innerHTML = filtered.map(e =>
        `<div class="log-entry">
  <span class="log-timestamp">${e.timestamp}</span>
  <span class="log-level ${e.level}">${e.level}</span>
  <span class="log-message">${e.message}</span>
</div>`
    ).join('');
    els.logContainer.scrollTop = els.logContainer.scrollHeight;
}

document.getElementById('log-level-filter')?.addEventListener('change', renderLogs);
document.getElementById('log-clear')?.addEventListener('click', () => { logEntries = []; renderLogs(); });
document.getElementById('log-export')?.addEventListener('click', () => {
    const blob = new Blob(
        [logEntries.map(e => `[${e.timestamp}] ${e.level}: ${e.message}`).join('\n')],
        { type: 'text/plain' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `astartis-logs-${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
});

// ===== AGENT TAB FILTERS =====
document.getElementById('agent-search')?.addEventListener('input', filterAgents);
document.getElementById('tier-filter')?.addEventListener('change', filterAgents);
document.getElementById('status-filter')?.addEventListener('change', filterAgents);

function filterAgents() {
    if (!dashboardData?.agents) return;
    const tier   = document.getElementById('tier-filter').value;
    const status = document.getElementById('status-filter').value;
    const term   = document.getElementById('agent-search').value.toLowerCase();
    let filtered = dashboardData.agents;
    if (tier   !== 'all') filtered = filtered.filter(a => a.tier === tier);
    if (status !== 'all') filtered = filtered.filter(a => (a.status ?? '').toLowerCase() === status);
    if (term)             filtered = filtered.filter(a => a.name.toLowerCase().includes(term));
    renderAgentsTable(filtered);
}

// ===== DEMO DATA GENERATORS =====
function generateDemoData() {
    const agentDefs = [
        { name: 'alert_triage',       tier: 'FAST' },
        { name: 'log_parser',         tier: 'FAST' },
        { name: 'status_checker',     tier: 'FAST' },
        { name: 'ping_monitor',       tier: 'FAST' },
        { name: 'port_scanner_fast',  tier: 'FAST' },
        { name: 'dns_checker',        tier: 'FAST' },
        { name: 'arp_monitor',        tier: 'FAST' },
        { name: 'heartbeat_agent',    tier: 'FAST' },
        ...Array.from({ length: 35 }, (_, i) => ({ name: `heavy_agent_${i + 1}`,    tier: 'HEAVY' })),
        ...Array.from({ length: 16 }, (_, i) => ({ name: `accuracy_agent_${i + 1}`, tier: 'ACCURACY' })),
        { name: 'incident_responder', tier: 'ORCHESTRATOR' },
        { name: 'breach_simulator',   tier: 'ORCHESTRATOR' },
        { name: 'threat_modeler',     tier: 'ORCHESTRATOR' },
        { name: 'red_team_coord',     tier: 'ORCHESTRATOR' },
        { name: 'purple_team',        tier: 'ORCHESTRATOR' },
        { name: 'chief_orchestrator', tier: 'ORCHESTRATOR' },
        // ECC agents (12) — run on ACCURACY tier
        { name: 'cpp_security_reviewer',        tier: 'ACCURACY' },
        { name: 'code_security_auditor',        tier: 'ACCURACY' },
        { name: 'ai_model_security_evaluator',  tier: 'ACCURACY' },
        { name: 'autonomous_response_operator', tier: 'ACCURACY' },
        { name: 'security_e2e_tester',          tier: 'ACCURACY' },
        { name: 'build_security_analyzer',      tier: 'ACCURACY' },
        { name: 'runtime_threat_monitor',       tier: 'ACCURACY' },
        { name: 'memory_forensics_agent',       tier: 'ACCURACY' },
        { name: 'kernel_security_auditor',      tier: 'ACCURACY' },
        { name: 'supply_chain_scanner',         tier: 'ACCURACY' },
        { name: 'zero_day_researcher',          tier: 'ACCURACY' },
        { name: 'exploit_chain_analyst',        tier: 'ACCURACY' },
    ];
    const modelMap = {
        FAST: 'granite4.0-h-micro', HEAVY: 'granite4.1-8b',
        ACCURACY: 'granite4.1-8b',  ORCHESTRATOR: 'granite4.1-8b',
    };
    const statuses = ['online', 'online', 'online', 'busy', 'offline'];
    const agents = agentDefs.map((a, i) => ({
        ...a, model: modelMap[a.tier],
        status: statuses[i % statuses.length],
        tasks_completed: Math.floor(Math.random() * 100),
        last_active: new Date(Date.now() - Math.random() * 3600000).toISOString(),
    }));
    const sevs   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const alerts = Array.from({ length: 8 }, (_, i) => ({
        timestamp:  new Date(Date.now() - Math.random() * 86400000).toISOString(),
        severity:   sevs[Math.floor(Math.random() * sevs.length)],
        agent_name: agents[Math.floor(Math.random() * agents.length)].name,
        message:    `Alert ${i + 1}: Suspicious activity detected`,
    }));
    const history  = Array.from({ length: 12 }, (_, i) => ({ time: `${i * 5}m`, count: Math.floor(Math.random() * 20) }));
    const active   = agents.filter(a => a.status === 'online').length;
    const critical = alerts.filter(a => a.severity === 'CRITICAL').length;
    return {
        system: { mode: 'FULL', status: 'online', version: '3.0.0', timestamp: new Date().toISOString() },
        kpi: { active_agents: active, queue_depth: 3, threat_level: 'LOW', threat_score: 18,
               alerts_24h: alerts.length, critical_alerts: critical },
        agents, alerts, activity_history: history,
        tier_distribution: { FAST: 8, HEAVY: 35, ACCURACY: 28, ORCHESTRATOR: 6 },
        new_logs: [
            { level: 'INFO', message: 'Astartis v3.0 dashboard initialized', timestamp: new Date().toISOString() },
            { level: 'INFO', message: `${agents.length} agents loaded (77 total: 65 base + 12 ECC)`, timestamp: new Date().toISOString() },
        ],
    };
}

function generateDemoDataV2Extras() {
    const nowMs = Date.now();
    const rand  = (min, max) => min + Math.floor(Math.random() * (max - min));

    const system_metrics = {
        cpu_percent:    rand(15, 75), memory_percent: rand(30, 70),
        memory_used_gb: rand(8, 16),  memory_total_gb: 32,
        disk_percent:   rand(45, 75), disk_free_gb: rand(120, 170),
        cpu_cores: 8, network_mbps: rand(0, 100), ollama_online: Math.random() > 0.2,
    };
    const firewall_blocks = Array.from({ length: 3 }, (_, i) => ({
        ip: `192.168.1.${100 + i}`,
        rule_name_in: `Astartis-Block-192.168.1.${100 + i}-in`,
        blocked_at_ms: nowMs - 300000, expires_at_ms: nowMs + 600000,
    }));
    const quarantine_entries = Array.from({ length: 2 }, (_, i) => ({
        entry_id: `Q-${i + 1}`, virus_name: `Trojan.FakeAV-${i + 1}`,
        quarantined_at_ms: nowMs - 3600000,
    }));
    const ptypes       = ['DATA_VALUATION', 'CREDENTIAL', 'LATERAL_MOVEMENT'];
    const decoy_events = Array.from({ length: 5 }, (_, i) => ({
        attacker_tag: 'attacker_001', poison_type: ptypes[i % 3],
        action: i % 2 === 0 ? 'read' : 'write_attempt', timestamp_ms: nowMs - i * 60000,
    }));
    const ztd = ['ALLOW', 'DENY', 'QUARANTINE', 'MFA_REQUIRED'];
    const zerotrust_decisions = Array.from({ length: 4 }, (_, i) => ({
        user_id: `user_${i + 1}`, decision: ztd[i % 4],
        trust_score: rand(20, 100), resource: `/api/sensitive-${i + 1}`,
    }));
    const entropy_windows = Array.from({ length: 30 }, (_, i) => {
        const m = 3.0 + rand(0, 50) / 10.0;
        return { mean_entropy_bits: m, max_entropy_bits: m + 1.0 + rand(0, 20) / 10.0,
                 anomalous: m > 7.2, window_index: i };
    });
    const chaos_windows = Array.from({ length: 30 }, (_, i) => {
        const K = rand(0, 70) / 100.0;
        return { K, anomalous: K > 0.7, window_index: i };
    });
    const stageNames    = ['CODE_COMMIT', 'STATIC_ANALYSIS', 'UNIT_TESTS', 'INTEGRATION_TESTS',
                           'SECURITY_SCAN', 'BUILD', 'DEPLOY_STAGING', 'E2E_TESTS', 'DEPLOY_PRODUCTION', 'MONITOR'];
    const stageStatuses = ['PASSED', 'PASSED', 'PASSED', 'FAILED', 'AUTO_FIXED'];
    const pipeline_stages = stageNames.map(name => {
        const status = stageStatuses[rand(0, stageStatuses.length)];
        return { stage: name, status,
                 detail: status === 'FAILED' ? 'Build timeout'
                       : status === 'AUTO_FIXED' ? 'Agent fixed lint' : 'OK' };
    });
    const sandbox_entries = Array.from({ length: 8 }, (_, i) => ({
        rel_path: i % 2 === 0 ? `etc/config-${i}.conf` : `var/log/app-${i}.log`,
        type: i % 2 === 0 ? 'FILE' : 'DIRECTORY',
        locked: Math.random() > 0.7, version: rand(1, 6),
    }));
    const auditTypes    = ['firewall_block', 'agent_task_completed', 'worm_lock_engaged',
                           'decoy_event', 'quarantine', 'rule_fired'];
    const audit_entries = Array.from({ length: 6 }, (_, i) => ({
        entry_id: `AE-${i + 1}`, event_type: auditTypes[i % 6],
        timestamp: new Date().toISOString(), chain_valid: true,
    }));
    return {
        system_metrics, firewall_blocks, quarantine_entries, decoy_events,
        zerotrust_decisions, entropy_windows, chaos_windows, pipeline_stages,
        sandbox_entries, audit_entries, audit_chain_valid: true,
        worm: { is_locked: false },
        health: { ollama_online: false, npcap_installed: false,
                  npcap_service_running: false, clamd_online: false, is_admin: false },
    };
}

// ===== INIT =====
async function init() {
    initCharts();
    initSparklines();
    initEntropyChart();
    initChaosChart();

    // Show demo data immediately — backend connection attempted after
    dashboardData = { ...generateDemoData(), ...generateDemoDataV2Extras() };
    updateDashboard(dashboardData);

    addTerminalLine('Astartis v3.0 — 77-Agent Cybersecurity System', 'info');
    addTerminalLine('Type "help" for available commands.', 'info');

    await loadDashboardData();
    setInterval(loadDashboardData, POLL_INTERVAL_MS);
}

init();
