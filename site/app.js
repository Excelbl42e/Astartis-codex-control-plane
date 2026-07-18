const views = {
  overview: () => `
    <div class="view-heading"><div><p class="eyebrow">Security assurance</p><h3>Local evidence overview</h3><p>One simulated view of host, trust, evidence, and developer workflow state.</p></div><span class="status good">healthy baseline</span></div>
    <div class="metric-grid"><div class="metric"><small>Host health</small><strong>86%</strong><span>CPU 18% · RAM 9.4 / 16 GB</span></div><div class="metric"><small>Network</small><strong>Not collecting</strong><span>Npcap capture is opt-in</span></div><div class="metric"><small>Audit chain</small><strong>VALID</strong><span>head af6dc734a223</span></div><div class="metric"><small>Recovery</small><strong>47 backups</strong><span>integrity checked</span></div></div>
    <div class="split-grid"><section class="dashboard-card"><p class="eyebrow">Evidence available to Codex</p><ul class="evidence-list"><li><b>AUDIT</b><span>Hash-linked local evidence</span><em>VALID</em></li><li><b>WORM</b><span>Protected recovery evidence</span><em>READY</em></li><li><b>ZT</b><span>NAC and Zero Trust decisions</span><em>SIMULATE</em></li><li><b>SWARM</b><span>Routed agent catalogue</span><em>77 AGENTS</em></li></ul></section><section class="dashboard-card"><p class="eyebrow">What the plugin can do</p><p>Use the Codex tab to inspect the seven safe local MCP tools. Enforcement actions, WORM unlock, quarantine, and arbitrary shell execution are intentionally not exposed.</p><button class="inline-action" data-jump="codex">Open Codex evidence</button></section></div>`,
  network: () => `
    <div class="view-heading"><div><p class="eyebrow">Network assurance</p><h3>Local packet metadata capture</h3><p>Capture is opt-in and requires Npcap on the real dashboard.</p></div><span id="capture-badge" class="status warning">not collecting</span></div>
    <div class="split-grid"><section class="dashboard-card"><label>Capture adapter<select><option>Automatic selection</option><option>Ethernet</option><option>Wi-Fi</option></select></label><button id="capture-toggle" class="button primary">Start simulated capture</button><p class="small-note">This page does not request Windows permission or collect traffic. It only demonstrates the dashboard interaction.</p></section><section class="dashboard-card"><p class="eyebrow">Capture telemetry</p><div id="capture-stats" class="stat-stack"><div><span>Packets</span><strong>0</strong></div><div><span>Entropy mean</span><strong>--</strong></div><div><span>Anomalies</span><strong>0</strong></div><div><span>Threat score</span><strong>LOW</strong></div></div></section></div>`,
  trust: () => `
    <div class="view-heading"><div><p class="eyebrow">NAC + Zero Trust</p><h3>Evaluate a bounded access decision</h3><p>Use the control below to replay the same non-compliant-device scenario used by Proof Mode.</p></div><span class="status warning">simulation</span></div>
    <div class="split-grid"><section class="dashboard-card"><label>Identity<input value="demo.contractor" readonly /></label><label>Device<input value="unpatched-demo-laptop" readonly /></label><label>Protected resource<input value="citizen-records" readonly /></label><button id="trust-evaluate" class="button primary">Evaluate simulated request</button></section><section id="trust-result" class="dashboard-card"><p class="eyebrow">Decision evidence</p><p>Run the simulation to inspect the deterministic NAC and Zero Trust result.</p></section></div>`,
  audit: () => `
    <div class="view-heading"><div><p class="eyebrow">Audit + recovery</p><h3>Protected evidence with verifiable history</h3><p>WORM and audit-chain state are exposed as evidence, not as an unlock control.</p></div><span class="status good">chain valid</span></div>
    <div class="metric-grid"><div class="metric"><small>Audit records</small><strong>26</strong><span>local scenario record set</span></div><div class="metric"><small>Current head</small><strong>953a7c7d5db2</strong><span>hash-linked</span></div><div class="metric"><small>WORM state</small><strong>LOCKED</strong><span>23 sandbox artifacts</span></div><div class="metric"><small>Recovery</small><strong>47 backups</strong><span>last check valid</span></div></div>
    <section class="dashboard-card chain-card"><p class="eyebrow">Audit-chain verification</p><div class="chain"><span>posture</span><i></i><span>NAC deny</span><i></i><span>ZT deny</span><i></i><span>WORM lock</span><i></i><span>verify</span></div><p class="small-note">The simulator visualises a deterministic local sequence. The real project validates evidence through the native bridge.</p></section>`,
  agents: () => `
    <div class="view-heading"><div><p class="eyebrow">AI fleet</p><h3>77 routed security-agent definitions</h3><p>The catalogue is not 77 simultaneous models. It records role, queue, availability, and local routing evidence.</p></div><span class="status good">queue: 0</span></div>
    <div class="metric-grid"><div class="metric"><small>Definitions</small><strong>77</strong><span>65 JSON + 12 ECC</span></div><div class="metric"><small>Running</small><strong>0</strong><span>idle at baseline</span></div><div class="metric"><small>Completed</small><strong>1,904</strong><span>simulated dashboard state</span></div><div class="metric"><small>Inference</small><strong>optional</strong><span>local runtime only</span></div></div>
    <section class="dashboard-card"><p class="eyebrow">Sample catalogue routing</p><table><thead><tr><th>Role</th><th>State</th><th>Routing tier</th><th>Evidence</th></tr></thead><tbody><tr><td>sentinel_alpha</td><td><span class="dot good-dot"></span> IDLE</td><td>fast</td><td>network posture</td></tr><tr><td>threat_hunter_1</td><td><span class="dot warning-dot"></span> READY</td><td>heavy</td><td>IOC review</td></tr><tr><td>forensics_lead</td><td><span class="dot good-dot"></span> IDLE</td><td>accuracy</td><td>audit review</td></tr></tbody></table></section>`,
  terminal: () => `
    <div class="view-heading"><div><p class="eyebrow">Safe diagnostic terminal</p><h3>Allowlisted local diagnostics</h3><p>Only a small set of diagnostic commands is represented here. Shell chaining and arbitrary execution are rejected.</p></div><span class="status good">allowlisted</span></div>
    <section class="terminal-sim"><div class="terminal-top"><span></span><span></span><span></span><p>ASTARTIS SAFE TERMINAL</p></div><pre id="terminal-output">Select a diagnostic command.</pre><div class="terminal-buttons"><button data-command="ipconfig">ipconfig /all</button><button data-command="whoami">whoami</button><button data-command="systeminfo">systeminfo</button><button data-command="blocked">powershell -Command ...</button></div></section>`,
  codex: () => `
    <div class="view-heading"><div><p class="eyebrow">Astartis Control Plane for Codex</p><h3>Seven safe local MCP tools</h3><p>Codex can investigate and verify evidence while the deterministic engine retains authority.</p></div><span class="status good">local stdio</span></div>
    <div class="tool-grid"><span>get_security_posture</span><span>list_network_zones</span><span>simulate_nac_admission</span><span>evaluate_zero_trust_access</span><span>get_agent_health</span><span>get_attack_attribution</span><span>run_proof_mode</span></div>
    <section class="codex-prompt"><p>Run Astartis Proof Mode. Explain the NAC denial, Zero Trust denial, WORM/audit evidence, and MITRE attribution. Clearly label what is simulated.</p><button id="run-codex" class="button primary">Run simulated safe-tool response</button><div id="codex-result" class="codex-result">The response will appear here. This browser simulator never calls a real MCP server.</div></section>`
};

const proofStages = [
  { view: "overview", summary: "Step 1 of 5: review the device posture.", label: "Posture reviewed" },
  { view: "trust", summary: "Step 2 of 5: evaluate NAC admission and inspect failed posture controls.", label: "NAC denied" },
  { view: "trust", summary: "Step 3 of 5: evaluate protected-resource access with Zero Trust.", label: "Zero Trust denied" },
  { view: "audit", summary: "Step 4 of 5: verify WORM-protected evidence and the audit chain.", label: "Evidence verified" },
  { view: "codex", summary: "Step 5 of 5: use bounded Codex evidence to explain and verify the result.", label: "Codex verification" }
];

const viewRoot = document.querySelector("#dashboard-view");
const tabs = [...document.querySelectorAll(".sim-tab")];
let activeView = "overview";
let proofIndex = 0;
let captureTimer;

function bindViewInteractions() {
  document.querySelectorAll("[data-jump]").forEach((button) => button.addEventListener("click", () => renderView(button.dataset.jump)));
  const capture = document.querySelector("#capture-toggle");
  if (capture) capture.addEventListener("click", toggleCapture);
  const trust = document.querySelector("#trust-evaluate");
  if (trust) trust.addEventListener("click", showTrustResult);
  document.querySelectorAll("[data-command]").forEach((button) => button.addEventListener("click", () => runTerminal(button.dataset.command)));
  const codex = document.querySelector("#run-codex");
  if (codex) codex.addEventListener("click", runCodex);
}

function renderView(name) {
  clearInterval(captureTimer);
  activeView = name;
  tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.view === name));
  viewRoot.innerHTML = views[name]();
  bindViewInteractions();
}

function toggleCapture() {
  const button = document.querySelector("#capture-toggle");
  const badge = document.querySelector("#capture-badge");
  const stats = document.querySelector("#capture-stats");
  let packets = 0;
  button.textContent = "Stop simulated capture";
  badge.textContent = "collecting";
  badge.className = "status good";
  clearInterval(captureTimer);
  captureTimer = setInterval(() => {
    packets += 84;
    stats.innerHTML = `<div><span>Packets</span><strong>${packets.toLocaleString()}</strong></div><div><span>Entropy mean</span><strong>0.42</strong></div><div><span>Anomalies</span><strong>0</strong></div><div><span>Threat score</span><strong>LOW</strong></div>`;
  }, 650);
  button.addEventListener("click", () => renderView("network"), { once: true });
}

function showTrustResult() {
  document.querySelector("#trust-result").innerHTML = `<p class="eyebrow">Decision evidence</p><h3 class="deny-title">NAC DENIED - Zero Trust DENIED</h3><ul class="result-list"><li>Identity <b>demo.contractor</b> was not found in the directory.</li><li>Patch status, antivirus, encryption, and firewall posture fail.</li><li>Trust score is <b>20 / 100</b>; citizen-records access is denied.</li><li>No VLAN or privileged role is assigned; remediation is proposed.</li></ul><p class="small-note">This is a deterministic local simulation. It does not contact a real switch, directory, or protected resource.</p>`;
}

function runTerminal(command) {
  const output = document.querySelector("#terminal-output");
  const responses = {
    ipconfig: "Windows IP Configuration\n\nHost Name . . . . . . . . . . . : astartis-demo\nAdapter . . . . . . . . . . . . : Automatic selection\nSimulation mode: no live adapter queried.",
    whoami: "astartis-demo\\developer\n\nSimulation mode: no local account was queried.",
    systeminfo: "OS Name: Windows 11\nSystem Type: x64-based PC\nSecurity posture: healthy baseline\n\nSimulation mode: representative diagnostic output.",
    blocked: "REJECTED\n\nThe safe terminal permits diagnostic allowlist commands only. Shell execution, scripts, chaining, and redirection are not exposed."
  };
  output.textContent = `> ${command === "blocked" ? "powershell -Command ..." : command === "ipconfig" ? "ipconfig /all" : command}\n\n${responses[command]}`;
}

function runCodex() {
  document.querySelector("#codex-result").innerHTML = `<strong>Simulated Astartis Proof Mode result</strong><br><br>NAC admission is denied because the identity is unknown and four endpoint posture controls fail. Zero Trust denies citizen-records because trust is 20 / 100. WORM evidence is locked and the audit chain is valid. The attribution record is bounded local evidence. No real network, firewall, identity provider, endpoint, or production data was changed.`;
}

function updateProof() {
  const stage = proofStages[proofIndex];
  document.querySelector("#proof-summary").textContent = stage.summary;
  document.querySelector("#proof-back").disabled = proofIndex === 0;
  document.querySelector("#proof-next").textContent = proofIndex === proofStages.length - 1 ? "Restart Proof Mode" : "Next step";
  renderView(stage.view);
  if (stage.view === "trust" && proofIndex > 1) showTrustResult();
}

tabs.forEach((tab) => tab.addEventListener("click", () => renderView(tab.dataset.view)));
document.querySelector("#proof-back").addEventListener("click", () => { proofIndex = Math.max(0, proofIndex - 1); updateProof(); });
document.querySelector("#proof-next").addEventListener("click", () => { proofIndex = proofIndex === proofStages.length - 1 ? 0 : proofIndex + 1; updateProof(); });
document.querySelector("#replay").addEventListener("click", async () => {
  for (let index = 0; index < proofStages.length; index += 1) {
    proofIndex = index;
    updateProof();
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
});

renderView(activeView);
updateProof();
