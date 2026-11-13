// Tiny XML reader for Windows event XML (Event Viewer "Save as XML", wevtutil qe /f:xml,
// Get-WinEvent ... .ToXml()). Produces the same tree shape as the EVTX parser:
// { name, attrs: {k: v}, children: [tree], text }. No DTDs, no external entities (safe by design).

const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

export function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === "#") {
      const cp = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try {
        return String.fromCodePoint(cp);
      } catch {
        return m;
      }
    }
    return ENT[e.toLowerCase()] ?? m;
  });
}

const TOKEN = /<\?[\s\S]*?\?>|<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<!DOCTYPE[^>]*>|<\/\s*([\w:.-]+)\s*>|<([\w:.-]+)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;
const ATTR = /([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

const local = (n) => n.slice(n.indexOf(":") + 1); // drop namespace prefixes

export function parseXml(text) {
  const root = { name: "#root", attrs: {}, children: [], text: "" };
  const stack = [root];
  TOKEN.lastIndex = 0;
  let m;
  while ((m = TOKEN.exec(text))) {
    const top = stack[stack.length - 1];
    if (m[1] !== undefined) top.text += m[1];
    else if (m[2] !== undefined) {
      const name = local(m[2]);
      // pop to the matching element (tolerates small mistakes)
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].name === name) {
          stack.length = i;
          break;
        }
      }
    } else if (m[3] !== undefined) {
      const el = { name: local(m[3]), attrs: {}, children: [], text: "" };
      let a;
      ATTR.lastIndex = 0;
      while ((a = ATTR.exec(m[4] || ""))) el.attrs[local(a[1])] = decodeEntities(a[2] ?? a[3] ?? "");
      top.children.push(el);
      if (!m[5]) stack.push(el);
    } else if (m[6] !== undefined && stack.length > 1) {
      top.text += decodeEntities(m[6]);
    }
  }
  return root;
}

// Collect every <Event> element, wherever it sits (root <Events>, concatenated events, …)
export function eventsFromXml(text) {
  const root = parseXml(text);
  const out = [];
  const walk = (n) => {
    for (const c of n.children) {
      if (c.name === "Event") out.push(trimTree(c));
      else walk(c);
    }
  };
  walk(root);
  return out;
}

function trimTree(t) {
  return { name: t.name, attrs: t.attrs, text: t.children.length ? t.text.trim() : t.text.replace(/^\s+|\s+$/g, ""), children: t.children.map(trimTree) };
}
