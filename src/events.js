// Turns any supported input into one normalized event shape:
// { idx, ts, time, id, provider, channel, computer, recordId, level, userSid, pid, data: {}, source }
import { isEvtx, parseEvtx } from "./evtx.js";
import { eventsFromXml } from "./xml.js";

const child = (t, name) => t?.children?.find((c) => c.name === name);

export function fromTree(tree, source) {
  const sys = child(tree, "System") || { children: [] };
  const get = (n) => child(sys, n)?.text ?? "";
  const attr = (n, a) => child(sys, n)?.attrs?.[a] ?? "";
  const data = {};
  const ed = child(tree, "EventData");
  if (ed) {
    let i = 0;
    for (const d of ed.children) {
      if (d.name === "Data") data[d.attrs.Name || `Data${i++}`] = d.text ?? "";
      else if (d.name === "Binary") data.Binary = d.text;
      else data[d.name] = d.text;
    }
  }
  const ud = child(tree, "UserData");
  if (ud) {
    for (const block of ud.children) {
      for (const d of block.children) data[d.name] = d.children.length ? d.children.map((x) => x.text).join(", ") : d.text;
      data._userData = block.name;
    }
  }
  const rd = child(tree, "RenderingInfo");
  if (rd) {
    const msg = child(rd, "Message")?.text;
    if (msg) data.Message = msg;
  }
  return mk({
    id: get("EventID"),
    provider: attr("Provider", "Name") || attr("Provider", "EventSourceName"),
    channel: get("Channel"),
    computer: get("Computer"),
    recordId: get("EventRecordID"),
    level: get("Level"),
    time: attr("TimeCreated", "SystemTime"),
    userSid: attr("Security", "UserID"),
    pid: attr("Execution", "ProcessID"),
    data,
    source,
  });
}

function mk(e) {
  const t = e.time ? Date.parse(String(e.time).replace(" ", "T").replace(/\+00:00$/, "Z")) : NaN;
  return {
    idx: 0,
    ts: Number.isNaN(t) ? 0 : t,
    time: Number.isNaN(t) ? "" : new Date(t).toISOString(),
    id: Number(e.id) || 0,
    provider: String(e.provider || ""),
    channel: String(e.channel || ""),
    computer: String(e.computer || ""),
    recordId: Number(e.recordId) || 0,
    level: String(e.level ?? ""),
    userSid: String(e.userSid || ""),
    pid: String(e.pid || ""),
    data: e.data || {},
    source: e.source,
  };
}

// --------------------------------------------------------------------------- JSON flavours
const flatten = (o) => {
  const out = {};
  for (const [k, v] of Object.entries(o || {})) out[k] = v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
  return out;
};

function fromJson(o) {
  // Winlogbeat / Elastic Common Schema
  if (o.winlog) {
    const w = o.winlog;
    return mk({
      id: w.event_id ?? o.event?.code,
      provider: w.provider_name,
      channel: w.channel,
      computer: w.computer_name || o.host?.name || o.host?.hostname,
      recordId: w.record_id,
      level: o.log?.level,
      time: o["@timestamp"],
      data: { ...flatten(w.event_data), ...flatten(w.user_data) },
      source: "json",
    });
  }
  // xmltodict / python-evtx JSON: { Event: { System: {...}, EventData: { Data: [...] } } }
  const ev = o.Event || (o.System ? o : null);
  if (ev && ev.System) {
    const s = ev.System;
    const txt = (v) => (v && typeof v === "object" ? v["#text"] ?? v.text ?? "" : v ?? "");
    const data = {};
    const d = ev.EventData?.Data;
    for (const item of Array.isArray(d) ? d : d ? [d] : []) {
      if (item && typeof item === "object") data[item["@Name"] || item.Name || `Data${Object.keys(data).length}`] = String(txt(item));
    }
    if (ev.EventData && !d) Object.assign(data, flatten(ev.EventData));
    return mk({
      id: txt(s.EventID),
      provider: s.Provider?.["@Name"] || s.Provider?.Name,
      channel: txt(s.Channel),
      computer: txt(s.Computer),
      recordId: txt(s.EventRecordID),
      level: txt(s.Level),
      time: s.TimeCreated?.["@SystemTime"] || s.TimeCreated?.SystemTime,
      data,
      source: "json",
    });
  }
  // Get-WinEvent | ConvertTo-Json
  if (o.Id !== undefined && (o.ProviderName || o.LogName)) {
    const m = /\/Date\((\d+)\)\//.exec(String(o.TimeCreated || ""));
    const data = {};
    (o.Properties || []).forEach((p, i) => (data[`Data${i}`] = String(p?.Value ?? "")));
    if (o.Message) data.Message = String(o.Message);
    return mk({ id: o.Id, provider: o.ProviderName, channel: o.LogName, computer: o.MachineName, recordId: o.RecordId, level: o.Level, time: m ? new Date(Number(m[1])).toISOString() : o.TimeCreated, data, source: "json" });
  }
  // Flat: { EventID, TimeCreated, Computer, ...fields }
  const id = o.EventID ?? o.EventId ?? o.event_id ?? o.eventId;
  if (id !== undefined) {
    const { EventID, EventId, event_id, eventId, TimeCreated, timestamp, Timestamp, Computer, computer, Channel, channel, Provider, provider, ...rest } = o;
    return mk({ id, time: TimeCreated ?? timestamp ?? Timestamp, computer: Computer ?? computer, channel: Channel ?? channel, provider: Provider ?? provider, data: flatten(rest.EventData || rest), source: "json" });
  }
  return null;
}

function parseJsonInput(text) {
  const t = text.trim();
  let items;
  if (t.startsWith("[")) items = JSON.parse(t);
  else if (t.startsWith("{") && !/}\s*\n\s*{/.test(t)) {
    const o = JSON.parse(t);
    items = Array.isArray(o.events) ? o.events : Array.isArray(o.records) ? o.records : [o];
  } else items = t.split(/\r?\n/).filter((l) => l.trim()).map((l) => JSON.parse(l));
  return items.map(fromJson).filter(Boolean);
}

/**
 * Detect the format and return normalized, time-sorted events.
 * @param {Uint8Array|string|ArrayBuffer} input
 * @param {string} [name]
 */
export function loadEvents(input, name = "") {
  const bytes = typeof input === "string" ? null : input instanceof Uint8Array ? input : new Uint8Array(input);
  let events = [];
  let format = "";
  const meta = { errors: [] };
  if (bytes && isEvtx(bytes)) {
    format = "evtx";
    const r = parseEvtx(bytes);
    meta.errors = r.errors;
    meta.header = r.header;
    meta.chunks = r.chunks;
    events = r.records.map((rec) => {
      const e = fromTree(rec.tree, "evtx");
      if (!e.ts && rec.time) {
        e.ts = Date.parse(rec.time);
        e.time = rec.time;
      }
      if (!e.recordId) e.recordId = rec.recordId;
      return e;
    });
  } else {
    let text = typeof input === "string" ? input : new TextDecoder(bytes[0] === 0xff && bytes[1] === 0xfe ? "utf-16le" : "utf-8").decode(bytes);
    text = text.replace(/^﻿/, "");
    const head = text.trimStart().slice(0, 1);
    if (head === "<") {
      format = "xml";
      events = eventsFromXml(text).map((t) => fromTree(t, "xml"));
    } else if (head === "[" || head === "{") {
      format = "json";
      events = parseJsonInput(text);
    } else {
      throw new Error(`Unsupported file${name ? ` (${name})` : ""}: expected .evtx, Windows event XML or JSON`);
    }
  }
  events.sort((a, b) => a.ts - b.ts || a.recordId - b.recordId);
  events.forEach((e, i) => (e.idx = i));
  return { events, format, meta };
}
