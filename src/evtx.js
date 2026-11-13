// Dependency-free parser for Windows XML Event Log files (.evtx).
//
// Layout: a 4 KB file header, then 64 KB chunks. Each chunk holds event records whose
// payload is "Binary XML" (BinXML): a token stream that references element names and
// templates stored elsewhere in the same chunk, with per-record substitution values.
// Format reference: libyal/libevtx documentation and python-evtx (Apache-2.0).
//
// The parser is defensive: a corrupted record or chunk is skipped and reported,
// never fatal, because real-world logs are often truncated or dirty.

const FILE_MAGIC = "ElfFile\0";
const CHUNK_MAGIC = "ElfChnk\0";
const CHUNK_SIZE = 0x10000;
const FILE_HEADER_SIZE = 0x1000;
const RECORD_MAGIC = 0x00002a2a;

const utf16 = new TextDecoder("utf-16le");
const latin1 = new TextDecoder("latin1");

function ascii(bytes, off, len) {
  let s = "";
  for (let i = 0; i < len; i++) s += String.fromCharCode(bytes[off + i]);
  return s;
}

export function isEvtx(bytes) {
  return bytes.length >= 8 && ascii(bytes, 0, 8) === FILE_MAGIC;
}

export function filetimeToIso(lo, hi) {
  // FILETIME = 100-ns intervals since 1601-01-01 UTC
  const ft = (BigInt(hi) << 32n) | BigInt(lo);
  if (ft === 0n) return "";
  const us = (ft + 5n) / 10n - 11644473600000000n; // round to the nearest microsecond
  const ms = Number(us / 1000n);
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  const micro = String(Number(us % 1000000n < 0n ? 0n : us % 1000000n)).padStart(6, "0");
  return d.toISOString().replace(/\.\d{3}Z$/, `.${micro}Z`);
}

class Chunk {
  constructor(bytes, dv, base, errors) {
    this.bytes = bytes;
    this.dv = dv;
    this.base = base;
    this.errors = errors;
    this.templates = new Map();
    this.names = new Map();
  }
  u8(p) { return this.bytes[p]; }
  u16(p) { return this.dv.getUint16(p, true); }
  u32(p) { return this.dv.getUint32(p, true); }

  // Element / attribute names: [u32 next][u16 hash][u16 chars][UTF-16 chars][u16 NUL]
  name(off) {
    let n = this.names.get(off);
    if (n !== undefined) return n;
    const p = this.base + off;
    const count = this.u16(p + 6);
    n = utf16.decode(this.bytes.subarray(p + 8, p + 8 + count * 2));
    this.names.set(off, n);
    return n;
  }
  nameLength(off) {
    return 8 + this.u16(this.base + off + 6) * 2 + 2;
  }
  plausibleName(off) {
    if (off < 0x200 || off + 10 > CHUNK_SIZE) return false;
    const count = this.u16(this.base + off + 6);
    return count > 0 && count < 512 && off + 10 + count * 2 <= CHUNK_SIZE;
  }

  // Template definition: [u32 next][16-byte GUID][u32 data size][BinXML fragment]
  template(off) {
    let t = this.templates.get(off);
    if (t) return t;
    const p = this.base + off;
    const size = this.u32(p + 20);
    const start = p + 24;
    const end = Math.min(start + size, this.base + CHUNK_SIZE);
    const { nodes } = this.parseContent(start, end, true);
    t = { size, nodes };
    this.templates.set(off, t);
    return t;
  }

  // Parse a token stream into nodes until EndElement (0x04) or EOF (0x00).
  // Node shapes: { el, attrs:[{name, value:[parts]}], children:[parts] } | string | { sub, optional }
  parseContent(pos, end, inTemplate) {
    const nodes = [];
    while (pos < end) {
      const tok = this.u8(pos);
      const base = tok & 0x0f;
      switch (base) {
        case 0x00: // EOF
          return { nodes, pos: pos + 1 };
        case 0x04: // EndElement
          return { nodes, pos: pos + 1, closed: true };
        case 0x0f: // FragmentHeader: token + major + minor + flags
          pos += 4;
          break;
        case 0x01: { // OpenStartElement
          const r = this.parseElement(pos, end, inTemplate);
          nodes.push(r.node);
          pos = r.pos;
          break;
        }
        case 0x05: { // Value
          const type = this.u8(pos + 1);
          const r = this.inlineValue(pos + 2, type);
          nodes.push(r.text);
          pos = r.pos;
          break;
        }
        case 0x0d: // NormalSubstitution
        case 0x0e: // OptionalSubstitution
          nodes.push({ sub: this.u16(pos + 1), type: this.u8(pos + 3), optional: base === 0x0e });
          pos += 4;
          break;
        case 0x07: { // CDATA: u16 chars
          const n = this.u16(pos + 1);
          nodes.push(utf16.decode(this.bytes.subarray(pos + 3, pos + 3 + n * 2)));
          pos += 3 + n * 2;
          break;
        }
        case 0x08: // CharRef
          nodes.push(String.fromCharCode(this.u16(pos + 1)));
          pos += 3;
          break;
        case 0x09: { // EntityRef
          const off = this.u32(pos + 1);
          pos += 5;
          const ent = this.name(off);
          if (off === pos - this.base) pos += this.nameLength(off);
          nodes.push({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" }[ent] ?? `&${ent};`);
          break;
        }
        case 0x0a: { // PITarget
          const off = this.u32(pos + 1);
          pos += 5;
          if (off === pos - this.base) pos += this.nameLength(off);
          break;
        }
        case 0x0b: { // PIData
          const n = this.u16(pos + 1);
          pos += 3 + n * 2;
          break;
        }
        case 0x0c: { // TemplateInstance
          const r = this.templateInstance(pos);
          nodes.push(...r.nodes);
          pos = r.pos;
          break;
        }
        default:
          throw new Error(`unknown BinXML token 0x${tok.toString(16)} at 0x${(pos - this.base).toString(16)}`);
      }
    }
    return { nodes, pos };
  }

  parseElement(pos, end, inTemplate) {
    const hasAttrs = (this.u8(pos) & 0x40) !== 0;
    // Normal layout has a 2-byte dependency id; some producers omit it. Detect by sanity-checking the name offset.
    let p = pos + 1;
    let nameOff = this.u32(p + 2 + 4);
    let fixed = 1 + 2 + 4 + 4;
    if (!this.plausibleName(nameOff) && this.plausibleName(this.u32(p + 4))) {
      nameOff = this.u32(p + 4);
      fixed = 1 + 4 + 4;
    }
    p = pos + fixed;
    if (nameOff === p - this.base) p += this.nameLength(nameOff); // name stored inline (first use in this chunk)
    if (hasAttrs) p += 4; // attribute list size (comes after the inline name)
    const node = { el: this.name(nameOff), attrs: [], children: [] };

    if (hasAttrs) {
      for (;;) {
        const t = this.u8(p);
        if ((t & 0x0f) !== 0x06) break;
        const aoff = this.u32(p + 1);
        p += 5;
        if (aoff === p - this.base) p += this.nameLength(aoff);
        const value = [];
        // exactly one value-ish token follows
        const vt = this.u8(p) & 0x0f;
        if (vt === 0x05) {
          const r = this.inlineValue(p + 2, this.u8(p + 1));
          value.push(r.text);
          p = r.pos;
        } else if (vt === 0x0d || vt === 0x0e) {
          value.push({ sub: this.u16(p + 1), type: this.u8(p + 3), optional: vt === 0x0e });
          p += 4;
        } else if (vt === 0x08) {
          value.push(String.fromCharCode(this.u16(p + 1)));
          p += 3;
        } else if (vt === 0x09) {
          const off = this.u32(p + 1);
          p += 5;
          if (off === p - this.base) p += this.nameLength(off);
          value.push("&");
        }
        node.attrs.push({ name: this.name(aoff), value });
        if ((t & 0x40) === 0) break;
      }
    }
    const close = this.u8(p) & 0x0f;
    if (close === 0x03) return { node, pos: p + 1 }; // CloseEmptyElement
    if (close !== 0x02) throw new Error(`expected CloseStartElement at 0x${(p - this.base).toString(16)}`);
    const r = this.parseContent(p + 1, end, inTemplate);
    node.children = r.nodes;
    return { node, pos: r.pos };
  }

  inlineValue(p, type) {
    if (type === 0x01) { // UTF-16 string with u16 length prefix
      const n = this.u16(p);
      return { text: utf16.decode(this.bytes.subarray(p + 2, p + 2 + n * 2)), pos: p + 2 + n * 2 };
    }
    throw new Error(`unsupported inline value type 0x${type.toString(16)}`);
  }

  templateInstance(pos) {
    // token(1) unknown(1) templateId(4) definitionOffset(4)
    const defOff = this.u32(pos + 6);
    let p = pos + 10;
    const tpl = this.template(defOff);
    if (defOff === p - this.base) p += 24 + tpl.size; // definition stored inline right here
    const count = this.u32(p);
    p += 4;
    if (count > 4096) throw new Error("implausible substitution count");
    const descs = [];
    for (let i = 0; i < count; i++) {
      descs.push({ size: this.u16(p), type: this.u8(p + 2) });
      p += 4;
    }
    const values = descs.map((d) => {
      const v = this.decodeValue(p, d.size, d.type);
      p += d.size;
      return v;
    });
    return { nodes: instantiate(tpl.nodes, values), pos: p };
  }

  decodeValue(p, size, type) {
    const b = this.bytes;
    const dv = this.dv;
    if (size === 0 && type !== 0x21) return null;
    switch (type) {
      case 0x00: return null;
      case 0x01: return utf16.decode(b.subarray(p, p + size)).replace(/\0+$/, "");
      case 0x02: return latin1.decode(b.subarray(p, p + size)).replace(/\0+$/, "");
      case 0x03: return String(dv.getInt8(p));
      case 0x04: return String(b[p]);
      case 0x05: return String(dv.getInt16(p, true));
      case 0x06: return String(dv.getUint16(p, true));
      case 0x07: return String(dv.getInt32(p, true));
      case 0x08: return String(dv.getUint32(p, true));
      case 0x09: return dv.getBigInt64(p, true).toString();
      case 0x0a: return dv.getBigUint64(p, true).toString();
      case 0x0b: return String(dv.getFloat32(p, true));
      case 0x0c: return String(dv.getFloat64(p, true));
      case 0x0d: return dv.getUint32(p, true) ? "true" : "false";
      case 0x0e: return hex(b.subarray(p, p + size)).toUpperCase();
      case 0x0f: return guid(b, p);
      case 0x10: return size === 8 ? "0x" + dv.getBigUint64(p, true).toString(16) : "0x" + dv.getUint32(p, true).toString(16);
      case 0x11: return filetimeToIso(dv.getUint32(p, true), dv.getUint32(p + 4, true));
      case 0x12: {
        const v = (i) => dv.getUint16(p + i * 2, true);
        const d = new Date(Date.UTC(v(0), v(1) - 1, v(3), v(4), v(5), v(6), v(7)));
        return Number.isNaN(d.getTime()) ? "" : d.toISOString();
      }
      case 0x13: return sid(b, dv, p, size);
      case 0x14: return "0x" + dv.getUint32(p, true).toString(16);
      case 0x15: return "0x" + dv.getBigUint64(p, true).toString(16);
      case 0x21: { // embedded BinXML (e.g. EventData/UserData fragment)
        if (!size) return null;
        const { nodes } = this.parseContent(p, p + size, false);
        return { binxml: nodes };
      }
      case 0x81: // array of UTF-16 strings, NUL separated
        return utf16.decode(b.subarray(p, p + size)).split("\0").filter(Boolean).join(", ");
      default:
        if (type & 0x80) {
          const inner = type & 0x7f;
          const width = { 0x04: 1, 0x06: 2, 0x08: 4, 0x0a: 8, 0x0f: 16, 0x14: 4, 0x15: 8 }[inner];
          if (width) {
            const out = [];
            for (let o = 0; o + width <= size; o += width) out.push(this.decodeValue(p + o, width, inner));
            return out.join(", ");
          }
        }
        return hex(b.subarray(p, p + size));
    }
  }
}

function hex(bytes) {
  let s = "";
  for (const x of bytes) s += x.toString(16).padStart(2, "0");
  return s;
}

function guid(b, p) {
  const h = (i, n, rev) => {
    const arr = Array.from(b.subarray(p + i, p + i + n));
    if (rev) arr.reverse();
    return arr.map((x) => x.toString(16).padStart(2, "0")).join("");
  };
  return `{${h(0, 4, true)}-${h(4, 2, true)}-${h(6, 2, true)}-${h(8, 2)}-${h(10, 6)}}`;
}

function sid(b, dv, p, size) {
  if (size < 8) return "";
  const rev = b[p];
  const count = b[p + 1];
  let auth = 0;
  for (let i = 0; i < 6; i++) auth = auth * 256 + b[p + 2 + i];
  const parts = [`S-${rev}-${auth}`];
  for (let i = 0; i < count && 8 + i * 4 + 4 <= size; i++) parts.push(String(dv.getUint32(p + 8 + i * 4, true)));
  return parts.join("-");
}

// Replace substitution placeholders in a template tree with this record's values.
function instantiate(nodes, values) {
  const out = [];
  for (const n of nodes) {
    if (typeof n === "string") out.push(n);
    else if (n.sub !== undefined) {
      const v = values[n.sub];
      if (v == null || v === "") continue;
      if (typeof v === "object" && v.binxml) out.push(...v.binxml);
      else out.push(String(v));
    } else {
      out.push({
        el: n.el,
        attrs: n.attrs.map((a) => ({
          name: a.name,
          value: a.value.flatMap((x) => {
            if (typeof x === "string") return [x];
            const v = values[x.sub];
            if (v == null) return [];
            return [typeof v === "object" ? "" : String(v)];
          }),
        })),
        children: instantiate(n.children, values),
      });
    }
  }
  return out;
}

// Convert a parsed node to the simple tree shape shared with the XML reader:
// { name, attrs: {k: v}, children: [tree], text }
export function toTree(node) {
  const attrs = {};
  for (const a of node.attrs || []) attrs[a.name] = a.value.join("");
  const children = [];
  let text = "";
  for (const c of node.children || []) {
    if (typeof c === "string") text += c;
    else if (c.el) children.push(toTree(c));
  }
  return { name: node.el, attrs, children, text };
}

/**
 * Parse an .evtx file.
 * @param {Uint8Array} bytes
 * @param {{ limit?: number }} [opts]
 * @returns {{ header: object, records: Array<{recordId:number, time:string, tree:object}>, errors: string[], chunks: number }}
 */
export function parseEvtx(bytes, opts = {}) {
  const limit = opts.limit ?? 2_000_000;
  if (!isEvtx(bytes)) throw new Error("not an EVTX file (missing ElfFile signature)");
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const header = {
    oldestChunk: Number(dv.getBigUint64(8, true)),
    currentChunk: Number(dv.getBigUint64(16, true)),
    nextRecord: Number(dv.getBigUint64(24, true)),
    minorVersion: dv.getUint16(36, true),
    majorVersion: dv.getUint16(38, true),
    chunkCount: dv.getUint16(42, true),
    flags: dv.getUint32(120, true),
  };
  header.dirty = (header.flags & 1) === 1;
  header.full = (header.flags & 2) === 2;
  const errors = [];
  const records = [];
  let chunks = 0;
  for (let off = FILE_HEADER_SIZE; off + 0x200 <= bytes.length && records.length < limit; off += CHUNK_SIZE) {
    if (ascii(bytes, off, 8) !== CHUNK_MAGIC) continue; // empty / unused chunk slot
    chunks++;
    const chunk = new Chunk(bytes, dv, off, errors);
    const free = Math.min(dv.getUint32(off + 48, true), CHUNK_SIZE);
    let p = off + 0x200;
    while (p + 28 <= off + free && records.length < limit) {
      if (dv.getUint32(p, true) !== RECORD_MAGIC) break;
      const size = dv.getUint32(p + 4, true);
      if (size < 28 || p + size > off + CHUNK_SIZE) {
        errors.push(`chunk ${chunks - 1}: bad record size at 0x${(p - off).toString(16)}`);
        break;
      }
      const recordId = Number(dv.getBigUint64(p + 8, true));
      const time = filetimeToIso(dv.getUint32(p + 16, true), dv.getUint32(p + 20, true));
      try {
        const { nodes } = chunk.parseContent(p + 24, p + size - 4, false);
        const root = nodes.find((n) => n && n.el);
        if (root) records.push({ recordId, time, tree: toTree(root) });
      } catch (e) {
        errors.push(`record ${recordId}: ${e.message}`);
      }
      p += size;
    }
  }
  return { header, records, errors, chunks };
}
