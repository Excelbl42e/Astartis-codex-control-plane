const stages = [
  {
    kicker: "01 / posture", title: "Device posture is evaluated locally.", badge: "review", tone: "warning",
    description: "The scenario begins with a laptop whose identity and endpoint posture must be evaluated before it reaches a protected service.",
    explanation: "Astartis assesses identity, patch status, antivirus, disk encryption, and local firewall posture. The policy result remains deterministic and inspectable.",
    audit: "Policy input captured: endpoint posture", metrics: [["Device", "unpatched-demo-laptop"], ["Identity", "demo.contractor"], ["Patch status", "outdated"], ["Trust score", "20 / 100"]]
  },
  {
    kicker: "02 / NAC", title: "NAC denies admission to the trusted network.", badge: "denied", tone: "danger",
    description: "802.1X completes, but identity and posture requirements are not satisfied. The device is routed to remediation instead of being admitted.",
    explanation: "The simulated user is unknown to the directory. Antivirus, encryption, firewall, and patch controls fail. No VLAN or privileged role is assigned.",
    audit: "NAC decision recorded: deny → remediation", metrics: [["Admission", "DENIED"], ["Identity", "not found"], ["Posture controls", "0 / 4 pass"], ["Assigned role", "none"]]
  },
  {
    kicker: "03 / Zero Trust", title: "Protected-resource access is denied.", badge: "denied", tone: "danger",
    description: "A low-trust, non-compliant device requests citizen-records. The request is evaluated as a local policy scenario and denied.",
    explanation: "The trust score is insufficient for the protected resource. This is an explanatory simulation: it does not contact the service or alter a real access-control system.",
    audit: "Zero Trust decision recorded: citizen-records → deny", metrics: [["Resource", "citizen-records"], ["Destination", "10.200.0.10"], ["Trust score", "20 / 100"], ["Decision", "DENY"]]
  },
  {
    kicker: "04 / WORM + audit", title: "Evidence is protected and verified.", badge: "verified", tone: "good",
    description: "The scenario’s local evidence is marked protected and the audit chain is checked for tampering.",
    explanation: "WORM protection and the audit chain make the demonstration evidence reviewable. This does not lock a real backup, file share, or production workload.",
    audit: "Audit verification complete: chain valid", metrics: [["WORM state", "LOCKED"], ["Artifacts", "23 sandbox records"], ["Audit chain", "VALID"], ["Chain head", "953a7c7d5db2"]]
  },
  {
    kicker: "05 / Codex", title: "Codex receives bounded evidence for verification.", badge: "safe tools", tone: "good",
    description: "The local control-plane plugin lets Codex explain the result, inspect evidence, and run Proof Mode through a narrow MCP contract.",
    explanation: "Codex is an investigation and verification surface—not an enforcement engine. Safe tools cannot run arbitrary commands, block a firewall, quarantine files, or unlock WORM evidence.",
    audit: "Proof Mode complete: local simulation labelled", metrics: [["MCP transport", "local stdio"], ["Safe tools", "7 available"], ["Proof Mode", "complete"], ["Enforcement", "not exposed"]]
  }
];

const metricGrid = document.querySelector("#metrics");
const buttons = [...document.querySelectorAll(".stage")];
const kicker = document.querySelector("#stage-kicker");
const title = document.querySelector("#stage-title");
const badge = document.querySelector("#state-badge");
const description = document.querySelector("#stage-description");
const explanation = document.querySelector("#explanation-text");
const audit = document.querySelector("#audit-text");

function render(index) {
  const stage = stages[index];
  buttons.forEach((button, position) => button.classList.toggle("active", position === index));
  kicker.textContent = stage.kicker;
  title.textContent = stage.title;
  badge.textContent = stage.badge;
  badge.className = `status ${stage.tone}`;
  description.textContent = stage.description;
  explanation.textContent = stage.explanation;
  audit.textContent = stage.audit;
  metricGrid.innerHTML = stage.metrics.map(([label, value]) => `<div class="metric"><small>${label}</small><strong>${value}</strong></div>`).join("");
}

buttons.forEach((button) => button.addEventListener("click", () => render(Number(button.dataset.stage))));
document.querySelector("#replay").addEventListener("click", async () => {
  for (let index = 0; index < stages.length; index += 1) {
    render(index);
    await new Promise((resolve) => setTimeout(resolve, 900));
  }
});

render(0);
