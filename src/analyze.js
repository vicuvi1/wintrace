// WinTrace pipeline: load → describe → detect → score → attack story → entities → stats
import { loadEvents } from "./events.js";
import { describe, isPublicIp } from "./describe.js";
import { detect } from "./rules.js";
import { TACTICS, describeTechnique } from "./mitre.js";

export const VERSION = "1.0.0";
const WEIGHT = { info: 0, low: 7, medium: 16, high: 30, critical: 50 };
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const VERDICTS = [
  { key: "compromise", min: 80, label: "Active compromise", short: "An attacker got in and acted on this system." },
  { key: "attack", min: 50, label: "Attack detected", short: "These logs show a clear attack in progress." },
  { key: "suspicious", min: 20, label: "Suspicious activity", short: "Some activity here needs a closer look." },
  { key: "clean", min: 0, label: "No attack found", short: "Nothing in these logs matches a known attack pattern." },
];

function score(alerts) {
  let keep = 1;
  for (const a of alerts) keep *= 1 - (WEIGHT[a.severity] || 0) / 100;
  let s = 100 * (1 - keep);
  const crit = alerts.filter((a) => a.severity === "critical").length;
  if (crit) s = Math.max(s, 80 + Math.min(15, (crit - 1) * 5));
  else s = Math.min(s, 79); // "Active compromise" needs at least one critical finding
  s = Math.round(Math.min(100, s));
  return { score: s, verdict: VERDICTS.find((v) => s >= v.min) };
}

function tacticOf(alert) {
  const tactics = alert.mitre.map((t) => describeTechnique(t).tactic).filter(Boolean);
  // earliest stage in the kill chain wins
  return tactics.sort((a, b) => TACTICS.indexOf(a) - TACTICS.indexOf(b))[0] || "Other";
}

function histogram(events, alerts, buckets = 48) {
  if (!events.length) return { buckets: [], start: 0, end: 0, size: 0 };
  const start = events[0].ts;
  const end = events[events.length - 1].ts;
  const size = Math.max(1000, Math.ceil((end - start + 1) / buckets));
  const n = Math.max(1, Math.min(buckets, Math.ceil((end - start + 1) / size)));
  const out = Array.from({ length: n }, (_, i) => ({ t: start + i * size, events: 0, alerts: 0, worst: "" }));
  for (const e of events) out[Math.min(n - 1, Math.floor((e.ts - start) / size))].events++;
  for (const a of alerts) {
    const b = out[Math.min(n - 1, Math.max(0, Math.floor((a.ts - start) / size)))];
    b.alerts++;
    if (!b.worst || SEVERITIES.indexOf(a.severity) < SEVERITIES.indexOf(b.worst)) b.worst = a.severity;
  }
  return { buckets: out, start, end, size };
}

function entities(events, described, alerts) {
  const users = new Map();
  const hosts = new Map();
  const ips = new Map();
  const acct = (s) => String(s || "").split("\\").pop(); // strip the DOMAIN\ prefix
  const bump = (map, key, patch) => {
    if (!key) return;
    const k = (map === users ? acct(key) : key).toLowerCase(); // DOMAIN\user and user are the same account
    if (!map.has(k)) map.set(k, { name: key, events: 0, alerts: 0, logons: 0, failures: 0, first: Infinity, last: 0 });
    const o = map.get(k);
    if (key.length > o.name.length) o.name = key; // prefer the fully qualified form
    o.events++;
    Object.entries(patch || {}).forEach(([p, v]) => (o[p] += v));
    return o;
  };
  for (const e of events) {
    const d = described[e.idx];
    const ok = e.id === 4624 ? 1 : 0;
    const bad = e.id === 4625 || e.id === 4771 ? 1 : 0;
    for (const [map, key] of [[users, d.actor], [hosts, e.computer], [ips, d.ip]]) {
      const o = bump(map, key, { logons: ok, failures: bad });
      if (o) {
        o.first = Math.min(o.first, e.ts);
        o.last = Math.max(o.last, e.ts);
      }
    }
  }
  for (const a of alerts) {
    for (const u of String(a.user || "").split(/,\s*/)) {
      const k = acct(u).toLowerCase();
      if (k && users.has(k)) users.get(k).alerts++;
    }
    if (a.host && hosts.has(a.host.toLowerCase())) hosts.get(a.host.toLowerCase()).alerts++;
    if (a.ip && ips.has(a.ip.toLowerCase())) ips.get(a.ip.toLowerCase()).alerts++;
  }
  const sort = (m) => [...m.values()].sort((a, b) => b.alerts - a.alerts || b.failures - a.failures || b.events - a.events);
  return {
    users: sort(users).filter((u) => !/\$$|^(system|local service|network service|anonymous logon)$/i.test(u.name)),
    hosts: sort(hosts),
    ips: sort(ips).map((i) => ({ ...i, public: isPublicIp(i.name) })),
  };
}

function summarize(alerts, verdict, hosts) {
  if (!alerts.length) return verdict.short;
  const top = [...alerts].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)).slice(0, 3);
  // keep acronyms / proper names (DCSync, PsExec, LSASS, DOMAIN\user) as written
  const keep = (t) => /^[A-Z][A-Z]|^[A-Z][a-z]+[A-Z]|^\S+\\|^(Mimikatz|Microsoft|Windows|Defender|Remote|Kerberos|Active)\b/.test(t);
  const what = top.map((a) => (keep(a.title) ? a.title : a.title.charAt(0).toLowerCase() + a.title.slice(1)));
  const list = what.length > 1 ? `${what.slice(0, -1).join(", ")} and ${what[what.length - 1]}` : what[0];
  const where = hosts.filter((h) => h.alerts).map((h) => h.name).slice(0, 3);
  return `${verdict.short} Most serious: ${list}${where.length ? `, on ${where.join(", ")}` : ""}.`;
}

function recommendations(alerts, verdict) {
  const has = (...rules) => alerts.some((a) => rules.includes(a.rule));
  const out = [];
  if (verdict.key === "clean") return ["No action needed. Keep Sysmon and PowerShell script-block logging enabled so future attacks leave evidence."];
  if (has("lsass_access", "mimikatz", "lsass_minidump", "procdump_lsass", "dcsync", "ntds", "sam_hive")) out.push("Treat every password used on the affected machines as stolen: reset them, starting with admin and service accounts. After DCSync or an NTDS copy, reset the krbtgt password twice.");
  if (has("bruteforce_success", "brute_force", "password_spray", "rdp_external")) out.push("Take Remote Desktop off the internet (VPN or RD Gateway with MFA), block the attacking IPs and turn on account lockout.");
  if (has("backdoor_admin", "user_created", "priv_group_add", "net_admin_add")) out.push("Disable the newly created or newly privileged accounts and review the membership of admin groups.");
  if (has("kerberoast", "asrep_roast")) out.push("Give service accounts long random passwords (or gMSA), enforce AES-only Kerberos and enable pre-authentication on every account.");
  if (has("service_installed", "psexec_service", "task_created", "run_key", "startup_folder", "schtasks_create")) out.push("Remove the persistence: the listed services, scheduled tasks and Run keys.");
  if (has("shadow_delete")) out.push("Ransomware precursor: isolate the hosts now and confirm that offline backups are intact.");
  if (has("log_cleared", "wevtutil_clear", "audit_policy")) out.push("Logs were tampered with: assume more happened than you can see, and pull logs from your SIEM or other machines for the missing window.");
  out.push("Isolate the affected hosts from the network, keep a memory image if possible, and escalate to incident response.");
  return out;
}

/**
 * Analyze Windows event logs.
 * @param {Uint8Array|ArrayBuffer|string} input .evtx bytes, event XML or JSON
 * @param {{ filename?: string }} [opts]
 */
export function analyzeLogs(input, opts = {}) {
  const started = Date.now();
  const { events, format, meta } = loadEvents(input, opts.filename);
  return analyzeEvents(events, { ...opts, format, meta, started });
}

export function analyzeEvents(events, opts = {}) {
  const started = opts.started || Date.now();
  // learn SID → account name from the log itself (4720/4624/4688 carry both)
  const sids = {};
  for (const e of events) {
    for (const [s, n] of [["TargetSid", "TargetUserName"], ["TargetUserSid", "TargetUserName"], ["SubjectUserSid", "SubjectUserName"]]) {
      const sid = e.data[s];
      const name = e.data[n];
      if (sid && name && name !== "-" && /^S-1-5-21-/.test(sid) && !sids[sid]) sids[sid] = name;
    }
  }
  const described = events.map((e) => describe(e, { sids }));
  const alerts = detect(events, described);
  alerts.forEach((a, i) => {
    a.n = i + 1;
    a.tactic = tacticOf(a);
    a.techniques = a.mitre.map(describeTechnique);
  });
  const notable = new Set(alerts.flatMap((a) => a.events));
  const { score: s, verdict } = score(alerts);
  const ent = entities(events, described, alerts);

  const counts = Object.fromEntries(SEVERITIES.map((x) => [x, 0]));
  for (const a of alerts) counts[a.severity]++;
  const byId = {};
  for (const e of events) byId[e.id] = (byId[e.id] || 0) + 1;

  const mitre = new Map();
  for (const a of alerts) {
    for (const t of a.techniques) {
      if (!mitre.has(t.id)) mitre.set(t.id, { ...t, alerts: [] });
      mitre.get(t.id).alerts.push(a.title);
    }
  }

  // attack story: one line per (merged) alert, in time order, grouped by tactic stage
  const story = alerts
    .filter((a) => a.severity !== "low" || alerts.length < 6)
    .map((a) => ({ time: a.time, host: a.host, user: a.user, ip: a.ip, tactic: a.tactic, severity: a.severity, text: a.story, alert: a.n }));

  return {
    tool: { name: "WinTrace", version: VERSION },
    analyzedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    filename: opts.filename || "",
    format: opts.format || "",
    parser: opts.meta ? { errors: opts.meta.errors?.length || 0, chunks: opts.meta.chunks, dirty: opts.meta.header?.dirty } : null,
    score: s,
    verdict,
    summary: summarize(alerts, verdict, ent.hosts),
    recommendations: recommendations(alerts, verdict),
    counts,
    alerts,
    story,
    mitre: [...mitre.values()].sort((a, b) => TACTICS.indexOf(a.tactic) - TACTICS.indexOf(b.tactic)),
    entities: ent,
    stats: {
      events: events.length,
      first: events[0]?.time || "",
      last: events[events.length - 1]?.time || "",
      hosts: ent.hosts.length,
      byId: Object.entries(byId).sort((a, b) => b[1] - a[1]),
      channels: [...new Set(events.map((e) => e.channel).filter(Boolean))],
    },
    histogram: histogram(events, alerts),
    // full timeline (UI paginates); `notable` marks events that are evidence for an alert
    timeline: events.map((e) => ({ idx: e.idx, time: e.time, id: e.id, host: e.computer, channel: e.channel, provider: e.provider, ...described[e.idx], notable: notable.has(e.idx) })),
    events,
  };
}
