// WinTrace web UI. Log content is attacker-controlled: it is only ever inserted with
// textContent / DOM APIs, never innerHTML.
import { loadEvents } from "../src/events.js";
import { analyzeEvents } from "../src/analyze.js";
import { toAlertsJson, toMarkdown, toNavigatorLayer, toTimelineCsv } from "../src/report.js";
import { TACTICS, TECHNIQUES, techniqueUrl } from "../src/mitre.js";
import { COMMAND_RULES } from "../src/rules.js";

const SAMPLES = [
  { file: "01-rdp-bruteforce-ransomware-prep.xml", title: "RDP brute force → ransomware prep", desc: "46 failed RDP logons from the internet, a successful one, a backdoor admin, deleted shadow copies and a wiped Security log.", tags: ["T1110", "T1490", "T1070"], sev: "critical" },
  { file: "02-kerberoasting-asrep-roasting.xml", title: "Kerberoasting + AS-REP roasting", desc: "Rubeus requests weak RC4 tickets for five service accounts, plus a TGT for an account without pre-authentication.", tags: ["T1558.003", "T1558.004"], sev: "high" },
  { file: "03-phishing-macro-mimikatz-lsass.xml", title: "Macro → PowerShell → Mimikatz", desc: "Word spawns encoded PowerShell, AMSI is bypassed, LSASS is dumped with comsvcs.dll and a Run key is planted.", tags: ["T1566", "T1059.001", "T1003.001"], sev: "critical" },
  { file: "04-pass-the-hash-psexec-lateral.xml", title: "Pass-the-hash + PsExec", desc: "Stolen hash used with runas /netonly, NTLM logon to a file server, PSEXESVC over ADMIN$ and a scheduled task.", tags: ["T1550.002", "T1021.002", "T1053.005"], sev: "critical" },
  { file: "05-dcsync-ntds-theft.xml", title: "DCSync + NTDS.dit theft", desc: "A user account asks the domain controller to replicate password hashes, then copies the AD database.", tags: ["T1003.006", "T1003.003"], sev: "critical" },
  { file: "06-password-spraying-internet.xml", title: "Password spraying", desc: "One IP tries two passwords against twelve accounts, and one of them works.", tags: ["T1110.003", "T1078"], sev: "critical" },
  { file: "07-normal-workday-clean.xml", title: "A normal workday", desc: "Logons, Office, Chrome and Teams. A control sample: WinTrace should stay quiet.", tags: ["control"], sev: "clean" },
];
const SEV = ["critical", "high", "medium", "low"];
const $ = (s, r = document) => r.querySelector(s);
const state = { r: null, names: [], tab: "story", tl: { notable: true, q: "", cat: "", page: 0 } };

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "href") el.href = /^(https:\/\/|#|\.\/)/.test(v) ? v : "#";
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const svgEl = (tag, attrs) => {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
};
const ext = (href, label, cls) => h("a", { class: cls, href, target: "_blank", rel: "noopener noreferrer" }, label);
const fmtTime = (iso) => (iso ? iso.replace("T", " ").slice(0, 19) : "");
const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* blocked */ } } };

function toast(m) {
  const t = $("#toast");
  t.textContent = m;
  t.classList.add("show");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove("show"), 2200);
}
function download(name, mime, text) {
  const a = h("a", { download: name });
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// ------------------------------------------------------------------ loading
async function analyze(inputs) {
  if (!inputs.length) return;
  $("#busy").hidden = false;
  $("#busyText").textContent = `Parsing ${inputs.length > 1 ? `${inputs.length} logs` : inputs[0].name}…`;
  await new Promise((r) => setTimeout(r, 30)); // let the overlay paint before heavy parsing
  try {
    const loaded = [];
    for (const inp of inputs) loaded.push({ name: inp.name, ...loadEvents(inp.data, inp.name) });
    const events = loaded.flatMap((x) => x.events).sort((a, b) => a.ts - b.ts || a.recordId - b.recordId);
    events.forEach((e, i) => (e.idx = i));
    $("#busyText").textContent = `Hunting through ${events.length.toLocaleString()} events…`;
    await new Promise((r) => setTimeout(r, 20));
    const errors = loaded.reduce((n, x) => n + (x.meta.errors?.length || 0), 0);
    state.r = analyzeEvents(events, { filename: loaded.map((x) => x.name).join(" + "), format: [...new Set(loaded.map((x) => x.format))].join(" + "), meta: { errors: Array(errors), chunks: loaded.reduce((n, x) => n + (x.meta.chunks || 0), 0) } });
    state.names = loaded.map((x) => x.name);
    state.tab = "story";
    state.tl = { notable: state.r.alerts.length > 0, q: "", cat: "", page: 0 };
    render();
    $("#landing").hidden = true;
    $("#results").hidden = false;
    scrollTo({ top: 0 });
  } catch (e) {
    console.error(e);
    toast(`Could not read that file: ${e.message}`);
  } finally {
    $("#busy").hidden = true;
  }
}

async function fromFiles(list) {
  const files = [...list].slice(0, 20);
  if (files.some((f) => f.size > 300 * 1024 * 1024)) return toast("Files over 300 MB are too large for the browser; use the CLI instead.");
  analyze(await Promise.all(files.map(async (f) => ({ name: f.name, data: new Uint8Array(await f.arrayBuffer()) }))));
}

async function loadSample(file) {
  try {
    const res = await fetch(`samples/${file}`);
    if (!res.ok) throw new Error(res.status);
    await analyze([{ name: file, data: new Uint8Array(await res.arrayBuffer()) }]);
    if (!location.hash.startsWith(`#sample=${file.slice(0, 2)}`)) history.replaceState(null, "", `#sample=${file.slice(0, 2)}`);
  } catch {
    toast("Couldn't load the sample (serve the folder over HTTP, not file://)");
  }
}

function home() {
  $("#results").hidden = true;
  $("#landing").hidden = false;
  history.replaceState(null, "", location.pathname + location.search);
}

// ------------------------------------------------------------------ results
function render() {
  const r = state.r;
  const root = $("#results");
  root.replaceChildren(resultsBar(r), verdictCard(r), activityChart(r), tabs(r));
  const panel = h("div", { class: "fade" });
  ({ story, detections, timeline, entities, mitre, ids })[state.tab](panel, r);
  root.append(panel);
}

function resultsBar(r) {
  const list = h("div", { class: "menu-list", hidden: true });
  const base = (state.names[0] || "logs").replace(/\.[^.]+$/, "");
  const opt = (label, hint, fn) => h("button", { type: "button", onclick: () => { list.hidden = true; fn(); } }, label, h("small", { text: hint }));
  list.append(
    opt("Incident report", ".md", () => download(`${base}-incident-report.md`, "text/markdown", toMarkdown(r))),
    opt("Timeline (all events)", ".csv", () => download(`${base}-timeline.csv`, "text/csv", toTimelineCsv(r))),
    opt("Timeline (evidence only)", ".csv", () => download(`${base}-evidence.csv`, "text/csv", toTimelineCsv(r, { notableOnly: true }))),
    opt("Detections", ".json", () => download(`${base}-detections.json`, "application/json", toAlertsJson(r))),
    opt("ATT&CK Navigator layer", ".json", () => download(`${base}-attack-layer.json`, "application/json", toNavigatorLayer(r))),
    opt("Print / save as PDF", "", () => { state.tab = "story"; render(); setTimeout(() => print(), 150); }),
  );
  document.addEventListener("click", () => (list.hidden = true), { once: true });
  return h("div", { class: "rbar" },
    h("button", { class: "btn sm ghost", type: "button", onclick: home }, "← New analysis"),
    h("span", { class: "file", text: r.filename, title: r.filename }),
    h("span", { class: "tag", text: r.format.toUpperCase() }),
    r.parser?.chunks ? h("span", { class: "tag", text: `${r.parser.chunks} EVTX chunks · ${r.parser.errors} errors` }) : null,
    h("span", { class: "sp" }),
    h("div", { class: "menu" }, h("button", { class: "btn primary sm", type: "button", onclick: (e) => { e.stopPropagation(); list.hidden = !list.hidden; } }, "Export ▾"), list),
  );
}

function verdictCard(r) {
  const C = 2 * Math.PI * 62;
  const svg = svgEl("svg", { viewBox: "0 0 150 150", width: 150, height: 150 });
  const mk = (cls) => svgEl("circle", { cx: 75, cy: 75, r: 62, fill: "none", "stroke-width": 12, class: cls });
  svg.append(mk("track"));
  const bar = mk("bar");
  const final = C * (1 - r.score / 100);
  bar.setAttribute("stroke-dasharray", C);
  bar.setAttribute("stroke-dashoffset", document.documentElement.classList.contains("static") ? final : C);
  svg.append(bar);
  requestAnimationFrame(() => requestAnimationFrame(() => bar.setAttribute("stroke-dashoffset", final)));
  const span = r.stats.first && r.stats.last ? Math.round((Date.parse(r.stats.last) - Date.parse(r.stats.first)) / 60000) : 0;
  const dur = span < 120 ? `${span} min` : span < 2880 ? `${Math.round(span / 60)} h` : `${Math.round(span / 1440)} days`;
  const hosts = r.entities.hosts.filter((x) => x.alerts).map((x) => x.name.split(".")[0]);
  return h("div", { class: `verdict v-${r.verdict.key} fade` },
    h("div", { class: "gauge" }, svg, h("div", { class: "num" }, h("b", { text: r.score }), h("span", { text: "RISK / 100" }))),
    h("div", null,
      h("div", { class: "v-label", text: r.verdict.label }),
      h("h2", { class: "v-title", text: hosts.length ? `Attack activity on ${hosts.slice(0, 3).join(", ")}` : r.alerts.length ? "Suspicious activity found" : "No attack patterns found" }),
      h("p", { class: "v-sum", text: r.summary }),
      h("div", { class: "facts" },
        h("span", null, h("b", { text: r.stats.events.toLocaleString() }), " events"),
        h("span", null, h("b", { text: r.stats.hosts }), r.stats.hosts === 1 ? " host" : " hosts"),
        h("span", null, h("b", { text: dur }), " covered"),
        h("span", null, h("b", { text: r.mitre.length }), " ATT&CK techniques"),
        h("span", null, "parsed in ", h("b", { text: `${r.durationMs || "<1"} ms` })),
      ),
    ),
    h("div", { class: "sevcol" }, SEV.map((s) => h("div", { class: "sevrow" }, h("span", { class: `sev sev-${s}`, text: s }), h("b", { text: r.counts[s] })))),
  );
}

function activityChart(r) {
  const hgm = r.histogram;
  const box = h("div", { class: "chart fade" });
  if (!hgm.buckets.length) return box;
  const W = 1000, H = 96, n = hgm.buckets.length, bw = W / n, max = Math.max(...hgm.buckets.map((b) => b.events));
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": "Event volume over time with detections" });
  hgm.buckets.forEach((b, i) => {
    const bh = b.events ? Math.max(3, ((H - 26) * b.events) / max) : 0;
    const rect = svgEl("rect", { x: i * bw + 1, y: H - 14 - bh, width: Math.max(1, bw - 2), height: bh, rx: 2, class: `b${b.alerts ? " hot" : ""}` });
    rect.append(svgEl("title", {}));
    rect.firstChild.textContent = `${fmtTime(new Date(b.t).toISOString())} · ${b.events} events${b.alerts ? ` · ${b.alerts} detection(s)` : ""}`;
    svg.append(rect);
    if (b.alerts) svg.append(svgEl("circle", { cx: i * bw + bw / 2, cy: 6, r: 4.5, class: `m-${b.worst}` }));
  });
  const axis = svgEl("text", { x: 0, y: H - 2, class: "axis" });
  axis.textContent = fmtTime(r.stats.first);
  const axis2 = svgEl("text", { x: W, y: H - 2, class: "axis", "text-anchor": "end" });
  axis2.textContent = fmtTime(r.stats.last);
  svg.append(axis, axis2);
  box.append(h("div", { class: "chart-head" }, h("span", { text: "Activity over time · dots mark detections" }), h("span", { text: `${r.stats.channels.join(" · ") || "events"}` })), svg);
  return box;
}

function tabs(r) {
  const T = [
    ["story", "Attack story", r.story.length, r.counts.critical > 0],
    ["detections", "Detections", r.alerts.length, r.counts.critical + r.counts.high > 0],
    ["timeline", "Timeline", r.stats.events],
    ["entities", "Accounts, hosts & IPs", r.entities.users.length + r.entities.hosts.length + r.entities.ips.length],
    ["mitre", "MITRE ATT&CK", r.mitre.length],
    ["ids", "Event IDs", r.stats.byId.length],
  ];
  return h("div", { class: "tabs", role: "tablist" }, T.map(([id, label, n, hot]) => h("button", { class: `tab${state.tab === id ? " on" : ""}`, type: "button", role: "tab", "aria-selected": String(state.tab === id), onclick: () => { state.tab = id; render(); } }, label, n != null ? h("span", { class: `n${hot ? " hot" : ""}`, text: n.toLocaleString() }) : null)));
}

// ------------------------------------------------------------------ tabs
function story(p, r) {
  const main = h("div", { class: "card" }, h("h3", null, "What the attacker did", h("span", { class: "muted", text: "in order, from the logs" })));
  if (!r.story.length) main.append(h("div", { class: "empty", text: "Nothing in these logs matches an attack pattern. That's the expected result for a normal day." }));
  else main.append(h("ol", { class: "story" }, r.story.map((s) => h("li", { class: `st ${s.severity}` },
    h("div", { class: "st-meta" }, h("time", { text: fmtTime(s.time) }), h("span", { class: "tag", text: s.host.split(".")[0] }), h("span", { class: "tactic", text: s.tactic }), h("span", { class: `sev sev-${s.severity}`, text: s.severity }), s.ip ? h("span", { class: "tag mono", text: s.ip }) : null),
    h("p", { class: "st-text" }, h("b", { text: "The attacker " }), s.text, "."),
  ))));
  const side = h("div", null,
    h("div", { class: "card" }, h("h3", null, "What to do now"), h("ul", { class: "list" }, r.recommendations.map((x) => h("li", null, h("span", { class: "do", text: "→" }), h("span", { text: x }))))),
  );
  const ips = r.entities.ips.filter((i) => i.public && (i.alerts || i.failures));
  if (ips.length) side.append(h("div", { class: "card" }, h("h3", null, "Internet addresses involved"), h("ul", { class: "list" }, ips.slice(0, 6).map((i) => h("li", null, h("span", { class: "mono", text: i.name }), h("span", { class: "muted", text: `${i.failures} failed · ${i.logons} ok` }), ext(`https://www.abuseipdb.com/check/${encodeURIComponent(i.name)}`, "AbuseIPDB ↗", "att"))))));
  p.append(h("div", { class: "grid2" }, main, side));
}

function evidenceTable(r, idxs) {
  const rows = idxs.slice(0, 25).map((i) => r.timeline[i]);
  return h("table", { class: "evlist" }, h("tbody", null, rows.map((t) => h("tr", null, h("td", { text: fmtTime(t.time) }), h("td", null, h("span", { class: "eid", text: t.id })), h("td", null, h("div", { text: t.title }), t.detail ? h("div", { class: "muted mono", text: t.detail.slice(0, 220) }) : null)))),
    idxs.length > 25 ? h("tfoot", null, h("tr", null, h("td", { colspan: 3, class: "muted", text: `…and ${idxs.length - 25} more (see the Timeline tab)` }))) : null);
}

function detections(p, r) {
  const card = h("div", { class: "card" }, h("h3", null, "Detections", h("span", { class: "muted", text: "most severe first · click to see the evidence" })));
  if (!r.alerts.length) card.append(h("div", { class: "empty", text: "No detections." }));
  const sorted = [...r.alerts].sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.ts - b.ts);
  sorted.forEach((a, i) => card.append(h("details", { class: `det ${a.severity}`, open: i < 2 },
    h("summary", null, h("span", { class: `sev sev-${a.severity}`, text: a.severity }), h("span", { class: "t", text: a.title }), a.count > 1 ? h("span", { class: "tag", text: `×${a.count}` }) : null, h("span", { class: "meta", text: `${fmtTime(a.time)} · ${a.host.split(".")[0]}` })),
    h("div", { class: "body" },
      h("p", null, "The attacker ", a.story, "."),
      a.detail ? h("pre", { class: "pre", text: a.detail }) : null,
      a.decoded ? [h("p", { class: "decoded-label", text: "DECODED BY WINTRACE" }), h("pre", { class: "pre decoded", text: a.decoded })] : null,
      a.techniques.length ? h("div", { class: "chips" }, a.techniques.map((t) => ext(t.url, `${t.id} · ${t.name}`, "att"))) : null,
      evidenceTable(r, a.events),
    ),
  )));
  p.append(card);
}

function timeline(p, r) {
  const st = state.tl;
  const cats = [...new Set(r.timeline.map((t) => t.category))].sort();
  const search = h("input", { class: "search", type: "search", placeholder: "Search events: user, IP, process, command, event ID…", value: st.q });
  const list = h("div");
  const pager = h("div", { class: "pager" });
  const draw = () => {
    const q = st.q.toLowerCase();
    const rows = r.timeline.filter((t) => (!st.notable || t.notable) && (!st.cat || t.category === st.cat) && (!q || `${t.id} ${t.title} ${t.detail} ${t.actor} ${t.ip} ${t.host} ${t.cmd}`.toLowerCase().includes(q)));
    const per = 100;
    const pages = Math.max(1, Math.ceil(rows.length / per));
    st.page = Math.min(st.page, pages - 1);
    list.replaceChildren(...(rows.length ? rows.slice(st.page * per, st.page * per + per).map((t) => eventRow(r, t)) : [h("div", { class: "empty", text: "No events match." })]));
    pager.replaceChildren(
      h("button", { class: "btn sm", type: "button", disabled: st.page === 0 || null, onclick: () => { st.page--; draw(); } }, "← Newer"),
      h("span", { text: `${rows.length.toLocaleString()} events · page ${st.page + 1} of ${pages}` }),
      h("button", { class: "btn sm", type: "button", disabled: st.page >= pages - 1 || null, onclick: () => { st.page++; draw(); } }, "Older →"),
    );
  };
  search.addEventListener("input", () => { st.q = search.value; st.page = 0; draw(); });
  const notable = h("input", { type: "checkbox" });
  notable.checked = st.notable;
  notable.addEventListener("change", () => { st.notable = notable.checked; st.page = 0; draw(); });
  const sel = h("select", { class: "select", "aria-label": "Category" }, h("option", { value: "", text: "All categories" }), cats.map((c) => h("option", { value: c, text: c })));
  sel.value = st.cat;
  sel.addEventListener("change", () => { st.cat = sel.value; st.page = 0; draw(); });
  draw();
  p.append(h("div", { class: "card" }, h("div", { class: "tl-tools" }, search, sel, h("label", { class: "toggle" }, notable, "Only evidence for detections")), list, pager));
}

function eventRow(r, t) {
  const ev = r.events[t.idx];
  const det = h("details", { class: `ev${t.notable ? " notable" : ""}` },
    h("summary", null, h("time", { text: fmtTime(t.time) }), h("span", null, h("span", { class: "eid", text: t.id })), h("span", null, h("span", { class: "ttl", text: t.title }), t.detail ? h("span", { class: "dtl", text: t.detail }) : null)),
  );
  det.addEventListener("toggle", () => {
    if (!det.open || det.dataset.filled) return;
    det.dataset.filled = "1";
    const rows = [["Host", ev.computer], ["Channel", ev.channel], ["Provider", ev.provider], ["Record", ev.recordId], ...Object.entries(ev.data)];
    det.append(h("table", { class: "kv" }, h("tbody", null, rows.filter(([, v]) => v !== "" && v != null).map(([k, v]) => h("tr", null, h("th", { text: k }), h("td", { text: String(v) }))))));
  });
  return det;
}

function entities(p, r) {
  const table = (title, rows, cols, extra) => h("div", { class: "card" }, h("h3", null, title, h("span", { class: "muted", text: `${rows.length}` })),
    rows.length ? h("table", { class: "ent" }, h("thead", null, h("tr", null, cols.map((c) => h("th", { text: c[0] })))), h("tbody", null, rows.slice(0, 40).map((x) => h("tr", null, cols.map(([, key, num]) => h("td", { class: `${num ? "n" : ""}${key === "alerts" && x.alerts ? " hot" : ""}`, text: typeof key === "function" ? key(x) : x[key] })), extra ? extra(x) : null)))) : h("div", { class: "empty", text: "None" }));
  p.append(h("div", { class: "ent-grid" },
    table("Accounts", r.entities.users, [["Account", "name"], ["Logons", "logons", 1], ["Failed", "failures", 1], ["Alerts", "alerts", 1]]),
    table("Hosts", r.entities.hosts, [["Host", (x) => x.name.split(".")[0]], ["Events", "events", 1], ["Alerts", "alerts", 1]]),
    table("Source IPs", r.entities.ips, [["IP", (x) => `${x.name}${x.public ? "  🌐" : ""}`], ["OK", "logons", 1], ["Failed", "failures", 1], ["Alerts", "alerts", 1]]),
  ));
}

function mitre(p, r) {
  const seen = new Map();
  for (const a of r.alerts) for (const t of a.mitre) if (!seen.has(t) || SEV.indexOf(a.severity) < SEV.indexOf(seen.get(t))) seen.set(t, a.severity);
  const byTactic = new Map(TACTICS.map((t) => [t, []]));
  for (const [id, t] of Object.entries(TECHNIQUES)) byTactic.get(t.tactic)?.push({ id, ...t });
  p.append(h("div", { class: "card" }, h("h3", null, "ATT&CK coverage", h("span", { class: "muted", text: `${seen.size} of ${Object.keys(TECHNIQUES).length} detectable techniques seen · colour = worst severity` })),
    h("div", { class: "matrix" }, [...byTactic].filter(([, l]) => l.length).map(([tac, list]) => h("div", { class: "tac" }, h("h4", { text: tac }), list.map((t) => {
      const sev = seen.get(t.id);
      return sev ? h("a", { class: `tech on ${sev}`, href: techniqueUrl(t.id), target: "_blank", rel: "noopener" }, h("code", { text: t.id }), t.name) : h("div", { class: "tech" }, h("code", { text: t.id }), t.name);
    })))),
  ));
}

function ids(p, r) {
  const example = new Map();
  for (const t of r.timeline) if (!example.has(t.id)) example.set(t.id, t);
  p.append(h("div", { class: "card" }, h("h3", null, "Event IDs in these logs", h("span", { class: "muted", text: "click a row to search the timeline" })),
    h("table", { class: "ent" }, h("thead", null, h("tr", null, h("th", { text: "ID" }), h("th", { text: "Example" }), h("th", { text: "Count" }))),
      h("tbody", null, r.stats.byId.map(([id, n]) => h("tr", { onclick: () => { state.tab = "timeline"; state.tl = { notable: false, q: String(id), cat: "", page: 0 }; render(); } },
        h("td", null, h("span", { class: "eid", text: id })), h("td", { text: example.get(Number(id))?.title || "" }), h("td", { class: "n", text: n.toLocaleString() }))))),
  ));
}

// ------------------------------------------------------------------ wiring
function init() {
  $("#samples").replaceChildren(...SAMPLES.map((s) => h("button", { class: "sample", type: "button", onclick: () => loadSample(s.file) },
    h("div", { class: "top" }, h("h3", { text: s.title }), h("span", { class: s.sev === "clean" ? "tag" : `sev sev-${s.sev}`, text: s.sev === "clean" ? "clean" : s.sev })),
    h("p", { text: s.desc }),
    h("div", { class: "chips" }, s.tags.map((t) => h("span", { class: "tag", text: t }))),
  )));
  $("#detects").replaceChildren(...["Brute force & password spraying", "Brute force that succeeded", "RDP from the internet", "Kerberoasting", "AS-REP roasting", "Pass-the-hash", "DCSync", "NTDS.dit theft", "LSASS dumps", "Mimikatz", "Encoded PowerShell (decoded)", "Download cradles", "AMSI bypass", "Office → shell", "PsExec & admin shares", "New services", "Scheduled tasks", "Run keys & Startup", "Backdoor admins", "Defender tampering", "Shadow copy deletion", "Log clearing", "Audit policy changes", ...COMMAND_RULES.filter((r) => /certutil|mshta|regsvr32|rundll32|BloodHound/i.test(r.title)).map((r) => r.title)].map((t) => h("span", { class: "tag", text: t })));

  const input = $("#file");
  $("#choose").addEventListener("click", (e) => { e.stopPropagation(); input.click(); });
  $("#trySample").addEventListener("click", (e) => { e.stopPropagation(); loadSample(SAMPLES[0].file); });
  $("#drop").addEventListener("click", () => input.click());
  $("#drop").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  input.addEventListener("change", () => { fromFiles(input.files); input.value = ""; });
  let depth = 0;
  addEventListener("dragenter", (e) => { if (e.dataTransfer?.types?.includes("Files")) { depth++; $("#dropOverlay").hidden = false; } });
  addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; $("#dropOverlay").hidden = true; } });
  addEventListener("dragover", (e) => e.preventDefault());
  addEventListener("drop", (e) => { e.preventDefault(); depth = 0; $("#dropOverlay").hidden = true; if (e.dataTransfer?.files?.length) fromFiles(e.dataTransfer.files); });
  $("#home").addEventListener("click", (e) => { e.preventDefault(); home(); });
  $("#themeBtn").addEventListener("click", () => {
    const t = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", t);
    store.set("wintrace-theme", t);
  });
  const fromHash = async () => {
    const m = /#sample=(\d{2})/.exec(location.hash);
    const tab = /[#&]tab=(\w+)/.exec(location.hash)?.[1];
    const s = m && SAMPLES.find((x) => x.file.startsWith(m[1]));
    if (s && state.names[0] !== s.file) await loadSample(s.file);
    if (s && tab && ["story", "detections", "timeline", "entities", "mitre", "ids"].includes(tab)) { state.tab = tab; render(); }
  };
  addEventListener("hashchange", fromHash);
  fromHash();
}
init();
