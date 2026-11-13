import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyzeLogs } from "../src/analyze.js";
import { loadEvents } from "../src/events.js";
import { isPublicIp } from "../src/describe.js";
import { toMarkdown, toNavigatorLayer, toTimelineCsv } from "../src/report.js";

const sample = (n) => analyzeLogs(readFileSync(new URL(`../samples/${n}`, import.meta.url), "utf8"), { filename: n });
const rules = (r) => new Set(r.alerts.map((a) => a.rule));

test("RDP brute force → backdoor admin → shadow copies deleted → log cleared", () => {
  const r = sample("01-rdp-bruteforce-ransomware-prep.xml");
  for (const id of ["brute_force", "bruteforce_success", "rdp_external", "discovery_burst", "backdoor_admin", "priv_group_add", "defender_tamper", "shadow_delete", "log_cleared"]) assert.ok(rules(r).has(id), id);
  assert.equal(r.verdict.key, "compromise");
  assert.equal(r.alerts.find((a) => a.rule === "shadow_delete").count, 3);
  assert.equal(r.entities.ips[0].name, "203.0.113.45");
  assert.ok(r.entities.ips[0].public);
});

test("Kerberoasting burst and AS-REP roasting", () => {
  const r = sample("02-kerberoasting-asrep-roasting.xml");
  const k = r.alerts.find((a) => a.rule === "kerberoast");
  assert.equal(k.severity, "high");
  assert.equal(k.user, "a.ionescu");
  assert.ok(rules(r).has("asrep_roast"));
  assert.ok(rules(r).has("rubeus"));
  // AES tickets and machine accounts must not count as kerberoasting
  assert.ok(!/krbtgt|WS07\$/.test(k.detail));
});

test("macro → encoded PowerShell (decoded) → Mimikatz → LSASS dump → persistence", () => {
  const r = sample("03-phishing-macro-mimikatz-lsass.xml");
  for (const id of ["office_child", "encoded_ps", "lolbin_network", "mimikatz", "amsi_bypass", "lsass_minidump", "lsass_access", "run_key", "defender_detection"]) assert.ok(rules(r).has(id), id);
  const enc = r.alerts.find((a) => a.rule === "encoded_ps");
  assert.match(enc.decoded, /DownloadString\('http:\/\/198\.51\.100\.7/);
  assert.equal(enc.severity, "critical", "an encoded download cradle escalates to critical");
});

test("pass-the-hash and PsExec lateral movement", () => {
  const r = sample("04-pass-the-hash-psexec-lateral.xml");
  for (const id of ["pth_seclogo", "pth_ntlm", "admin_share", "psexec_service", "discovery_burst", "task_created"]) assert.ok(rules(r).has(id), id);
  assert.equal(r.alerts.find((a) => a.rule === "task_created").severity, "high");
});

test("DCSync and NTDS theft are critical", () => {
  const r = sample("05-dcsync-ntds-theft.xml");
  assert.equal(r.alerts.find((a) => a.rule === "dcsync").severity, "critical");
  assert.ok(rules(r).has("ntds"));
  assert.ok(rules(r).has("sam_hive"));
});

test("password spraying followed by a successful logon", () => {
  const r = sample("06-password-spraying-internet.xml");
  assert.ok(rules(r).has("password_spray"));
  const ok = r.alerts.find((a) => a.rule === "bruteforce_success");
  assert.match(ok.user, /m\.popescu/);
});

test("a normal workday produces no alerts at all", () => {
  const r = sample("07-normal-workday-clean.xml");
  assert.equal(r.alerts.length, 0);
  assert.equal(r.verdict.key, "clean");
  assert.equal(r.score, 0);
});

test("real security.evtx: account created and made admin is flagged", () => {
  const r = analyzeLogs(new Uint8Array(readFileSync(new URL("./fixtures/security.evtx", import.meta.url))));
  assert.ok(rules(r).has("backdoor_admin"));
  assert.ok(r.alerts.some((a) => a.title === "fsir added to Administrators"), "SIDs resolved to account names");
});

test("JSON inputs: Winlogbeat/ECS and flat objects", () => {
  const ecs = JSON.stringify({ "@timestamp": "2026-11-10T08:00:00Z", host: { name: "WS1" }, winlog: { event_id: 1102, channel: "Security", provider_name: "Microsoft-Windows-Eventlog", computer_name: "WS1", event_data: { SubjectUserName: "bob" } } });
  const flat = JSON.stringify({ EventID: 4720, TimeCreated: "2026-11-10T08:01:00Z", Computer: "WS1", Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", TargetUserName: "eve", SubjectUserName: "bob" });
  const { events, format } = loadEvents(`${ecs}\n${flat}\n`);
  assert.equal(format, "json");
  assert.deepEqual(events.map((e) => e.id), [1102, 4720]);
  const r = analyzeLogs(`${ecs}\n${flat}\n`);
  assert.ok(rules(r).has("log_cleared"));
  assert.ok(rules(r).has("user_created"));
});

test("public vs private IPs", () => {
  for (const ip of ["10.1.2.3", "192.168.0.1", "172.16.5.4", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1"]) assert.equal(isPublicIp(ip), false, ip);
  for (const ip of ["8.8.8.8", "203.0.113.45", "::ffff:198.51.100.7"]) assert.equal(isPublicIp(ip), true, ip);
});

test("exports: Markdown report, CSV (formula-safe) and ATT&CK Navigator layer", () => {
  const r = sample("03-phishing-macro-mimikatz-lsass.xml");
  const mdText = toMarkdown(r);
  assert.match(mdText, /## What happened/);
  assert.match(mdText, /T1003\.001/);
  r.timeline[0].title = "=cmd|' /C calc'!A0";
  assert.match(toTimelineCsv(r), /'=cmd/);
  const layer = JSON.parse(toNavigatorLayer(r));
  assert.equal(layer.domain, "enterprise-attack");
  assert.ok(layer.techniques.some((t) => t.techniqueID === "T1003.001" && t.score === 100));
});
