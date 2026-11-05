import { JSDOM } from 'jsdom';
import fs from 'node:fs';
const dom = new JSDOM('<!doctype html><html><body></body></html>');
globalThis.window = dom.window; globalThis.document = dom.window.document;
for (const k of ["Element","HTMLElement","Node","DocumentFragment","NodeFilter","navigator"]) { try { globalThis[k] = dom.window[k]; } catch {} }
const { default: mermaid } = await import('mermaid');
mermaid.initialize({ startOnLoad: false });
let bad = 0;
for (const f of process.argv.slice(2)) {
  const s = fs.readFileSync(f, 'utf8');
  const blocks = [...s.matchAll(/```mermaid\n([\s\S]*?)```/g)];
  for (const [i, m] of blocks.entries()) {
    try { await mermaid.parse(m[1]); console.log(`ok   ${f} #${i + 1}`); }
    catch (e) { bad++; console.log(`FAIL ${f} #${i + 1}: ${String(e.message || e).split('\n').slice(0, 3).join(' | ')}`); }
  }
}
process.exit(bad ? 1 : 0);
