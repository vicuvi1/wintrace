import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseEvtx, isEvtx } from "../src/evtx.js";
import { loadEvents } from "../src/events.js";

const fx = (n) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));
const child = (t, n) => t.children.find((c) => c.name === n);

test("file header fields match python-evtx's known values", () => {
  const r = parseEvtx(fx("system.evtx"));
  assert.equal(r.header.majorVersion, 3);
  assert.equal(r.header.minorVersion, 1);
  assert.equal(r.header.chunkCount, 9);
  assert.equal(r.header.currentChunk, 8);
  assert.equal(r.header.nextRecord, 0x34d8);
  assert.equal(r.header.dirty, true);
  assert.equal(r.chunks, 9);
});

test("every record is parsed, with zero errors (system 1601, security 2261)", () => {
  const sys = parseEvtx(fx("system.evtx"));
  assert.equal(sys.records.length, 1601);
  assert.equal(sys.errors.length, 0);
  const sec = parseEvtx(fx("security.evtx"));
  assert.equal(sec.records.length, 2261);
  assert.equal(sec.errors.length, 0);
});

test("first record renders exactly like the python-evtx reference", () => {
  const { records } = parseEvtx(fx("system.evtx"));
  const ev = records[0].tree;
  const sys = child(ev, "System");
  assert.equal(child(sys, "Provider").attrs.Name, "Microsoft-Windows-Eventlog");
  assert.equal(child(sys, "Provider").attrs.Guid, "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}");
  assert.equal(child(sys, "EventID").text, "105");
  assert.equal(child(sys, "Keywords").text, "0x8000000000000000");
  assert.equal(child(sys, "TimeCreated").attrs.SystemTime, "2012-03-14T04:17:43.354563Z");
  assert.equal(child(sys, "EventRecordID").text, "12049");
  assert.equal(child(sys, "Execution").attrs.ProcessID, "820");
  assert.equal(child(sys, "Computer").text, "WKS-WIN764BITB.shieldbase.local");
  const ab = child(child(ev, "UserData"), "AutoBackup");
  assert.equal(child(ab, "BackupPath").text, "C:\\Windows\\System32\\Winevt\\Logs\\Archive-System-2012-03-14-04-17-39-932.evtx");
});

test("SIDs, hex values and named EventData are decoded", () => {
  const { events } = loadEvents(fx("security.evtx"));
  const logon = events.find((e) => e.id === 4624 && e.data.TargetUserName === "SYSTEM");
  assert.equal(logon.data.TargetUserSid, "S-1-5-18");
  assert.equal(logon.data.TargetLogonId, "0x3e7");
  assert.equal(logon.channel, "Security");
  assert.equal(logon.provider, "Microsoft-Windows-Security-Auditing");
});

test("malformed real-world file still parses without throwing", () => {
  const r = parseEvtx(fx("dns_log_malformed.evtx"));
  assert.equal(r.records.length, 5);
});

test("rejects non-EVTX input", () => {
  assert.equal(isEvtx(new TextEncoder().encode("<Events/>")), false);
  assert.throws(() => parseEvtx(new TextEncoder().encode("hello world, not a log")));
});
