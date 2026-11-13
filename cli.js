#!/usr/bin/env node
// WinTrace CLI: hunt for attacks in Windows event logs from the terminal or a pipeline.
//   node cli.js Security.evtx
//   node cli.js samples/*.xml
//   node cli.js Security.evtx System.evtx Sysmon.evtx --md > report.md     (several logs = one combined timeline)
//   node cli.js Security.evtx --csv > timeline.csv
//   node cli.js Security.evtx --fail-above 49                                (exit code 2 = attack found)
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { loadEvents } from "./src/events.js";
import { analyzeEvents, VERSION } from "./src/analyze.js";
import { toAlertsJson, toMarkdown, toNavigatorLayer, toTimelineCsv } from "./src/report.js";

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const fi = args.indexOf("--fail-above");
const failAbove = fi !== -1 ? Number(args[fi + 1]) : null;
const files = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--fail-above");

if (flags.has("--version")) {
  console.log(`wintrace ${VERSION}`);
  process.exit(0);
}
if (!files.length || flags.has("--help")) {
  console.log(`WinTrace ${VERSION}: Windows event log attack hunter

Usage: node cli.js <log> [more logs…] [options]
  Logs: .evtx files, Windows event XML (Event Viewer "Save as XML", wevtutil /f:xml) or JSON (Winlogbeat/ECS, NDJSON).
  Several files are merged into one timeline (e.g. Security + System + Sysmon from the same host).

  --separate        analyse each file on its own instead of merging
  --json            alerts as JSON
  --md              Markdown incident report
  --csv             full timeline as CSV (--notable for alert evidence only)
  --navigator       MITRE ATT&CK Navigator layer
  --fail-above N    exit with code 2 if the risk score is above N
`);
  process.exit(files.length ? 0 : 1);
}

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const SEV = { critical: "1;31", high: "31", medium: "33", low: "36" };
const VERD = { compromise: "1;41;97", attack: "1;31", suspicious: "1;33", clean: "1;32" };

async function load(f) {
  const bytes = new Uint8Array(await readFile(f));
  return loadEvents(bytes, basename(f));
}

const groups = flags.has("--separate") ? files.map((f) => [f]) : [files];
let worst = 0;
for (const group of groups) {
  const loaded = await Promise.all(group.map(load));
  const events = loaded.flatMap((x) => x.events).sort((a, b) => a.ts - b.ts);
  events.forEach((e, i) => (e.idx = i));
  const r = analyzeEvents(events, { filename: group.map((f) => basename(f)).join(" + "), format: [...new Set(loaded.map((x) => x.format))].join("+"), meta: loaded[0].meta });
  worst = Math.max(worst, r.score);
  if (flags.has("--json")) console.log(toAlertsJson(r));
  else if (flags.has("--md")) console.log(toMarkdown(r));
  else if (flags.has("--csv")) process.stdout.write(toTimelineCsv(r, { notableOnly: flags.has("--notable") }));
  else if (flags.has("--navigator")) console.log(toNavigatorLayer(r));
  else {
    console.log(`\n${c("1", r.filename)}  ${c("2", `${r.stats.events} events · ${r.format} · ${r.stats.hosts} host(s) · ${r.durationMs} ms`)}`);
    console.log(`  ${c(VERD[r.verdict.key], ` ${r.verdict.label.toUpperCase()} `)}  risk ${c("1", r.score + "/100")}`);
    console.log(`  ${c("2", r.summary)}\n`);
    for (const s of r.story) console.log(`  ${c("2", s.time.slice(11, 19))}  ${c(SEV[s.severity] || "0", "●")} ${s.host.split(".")[0]}: ${s.text}`);
    if (r.alerts.length) console.log("");
    for (const a of r.alerts) console.log(`  ${c(SEV[a.severity], a.severity.toUpperCase().padEnd(9))}${a.title}${a.count > 1 ? c("2", ` ×${a.count}`) : ""}${a.mitre.length ? c("2", `  [${a.mitre.join(", ")}]`) : ""}`);
    const dec = r.alerts.find((a) => a.decoded);
    if (dec) console.log(`\n  ${c("1", "Decoded PowerShell:")} ${dec.decoded.slice(0, 160)}`);
  }
}
if (failAbove != null && worst > failAbove) process.exit(2);
