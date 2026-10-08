import { describe, expect, it } from 'vitest';

import { defaultRuleset } from '../policy/default-ruleset';
import { defaultConfig } from '../policy/default-config';
import { runScan } from './scan';
import { AST_CONFIRMABLE_MATCHERS, applyAstConfirmation } from './ast-confirm';
import type { FileEntry, Finding } from '../types';

const noop = () => {};

function file(path: string, content: string, tags: string[] = []): FileEntry {
  return {
    path,
    content,
    sizeBytes: content.length,
    ext: path.slice(path.lastIndexOf('.')).toLowerCase(),
    isTextCandidate: true,
    tags,
    isIgnored: false
  };
}

function scan(ruleId: string, content: string, path = 'dist/app.js'): Finding[] {
  const rule = defaultRuleset.rules.find((candidate) => candidate.ruleId === ruleId);
  if (!rule) throw new Error(`rule ${ruleId} is not in the default ruleset`);
  return runScan([file(path, content)], { ...defaultRuleset, rules: [rule] }, defaultConfig, noop);
}

function only(findings: Finding[], matcherId: string): Finding {
  const matches = findings.filter((finding) => finding.matcherId === matcherId);
  expect(matches, matcherId).toHaveLength(1);
  return matches[0] as Finding;
}

describe('AST confirmation: user interaction vs load', () => {
  it('clears window.open called from a click listener', () => {
    const f = only(scan('UX-NO-POPUPS', 'btn.addEventListener("click", () => { window.open(url, "_blank"); });'), 'window-open');
    expect(f.confidence).toBe('LOW');
    expect(f.confidenceReason).toContain('user-interaction handler');
  });

  it('clears window.open from a compiled JSX onClick prop and from a named handler bound in scope', () => {
    const jsx = only(scan('UX-NO-POPUPS', 'jsx("button", { onClick: () => window.open(docs) });'), 'window-open');
    expect(jsx.confidence).toBe('LOW');

    const named = only(
      scan('UX-NO-POPUPS', 'function openDocs() { window.open(docs); }\nel.onclick = openDocs;'),
      'window-open'
    );
    expect(named.confidence).toBe('LOW');
  });

  it('confirms window.open at module load, inside an IIFE, and from a timer', () => {
    expect(only(scan('UX-NO-POPUPS', 'window.open("https://promo.example.com");'), 'window-open').confidence).toBe('HIGH');
    expect(only(scan('UX-NO-POPUPS', '(function(){ window.open("https://promo.example.com"); })();'), 'window-open').confidence).toBe('HIGH');
    const timer = only(scan('UX-NO-POPUPS', 'setTimeout(() => window.open("https://promo.example.com"), 3000);'), 'window-open');
    expect(timer.confidence).toBe('HIGH');
    expect(timer.confidenceReason).toContain('timer');
  });

  it('leaves window.open inside an ordinary function alone', () => {
    const f = only(scan('UX-NO-POPUPS', 'function maybe() { window.open(url); }\nexport { maybe };'), 'window-open');
    expect(f.confidence).toBe('LOW');
    expect(f.confidenceReason).toBeUndefined();
  });

  it('raises a mount-effect call to medium, no further', () => {
    const f = only(scan('UX-NO-POPUPS', 'useEffect(() => { window.open(url); }, []);'), 'window-open');
    expect(f.confidence).toBe('MEDIUM');
  });

  it('applies the same rule to Designer write calls and media capture', () => {
    expect(only(scan('UX-NO-MUTATION-ON-LOAD', 'await webflow.createStyle("hero");'), 'designer-write-call').confidence).toBe('HIGH');
    expect(
      only(scan('UX-NO-MUTATION-ON-LOAD', 'apply.addEventListener("click", async () => { await webflow.createStyle("hero"); });'), 'designer-write-call').confidence
    ).toBe('LOW');
    expect(only(scan('SEC-WEBRTC-HARDWARE', 'navigator.mediaDevices.getUserMedia({ audio: true });'), 'get-user-media').confidence).toBe('HIGH');
    expect(
      only(scan('SEC-WEBRTC-HARDWARE', 'rec.onclick = async () => { await navigator.mediaDevices.getUserMedia({ audio: true }); };'), 'get-user-media').confidence
    ).toBe('LOW');
  });
});

describe('AST confirmation: message handlers', () => {
  it('confirms a handler that reads only event.data', () => {
    const f = only(
      scan('SEC-MESSAGE-ORIGIN', 'window.addEventListener("message", (e) => { apply(e.data.payload); });'),
      'inline-window-message-handler'
    );
    expect(f.confidence).toBe('HIGH');
    expect(f.confidenceReason).toContain('never reads event.origin');
  });

  it('confirms a destructured handler that never takes origin', () => {
    const f = only(scan('SEC-MESSAGE-ORIGIN', 'window.onmessage = ({ data }) => { apply(data); };'), 'inline-window-message-handler');
    expect(f.confidence).toBe('HIGH');
  });

  it('clears a handler whose origin check sits past the snippet window', () => {
    const lines = ['window.addEventListener("message", function (event) {', ...Array.from({ length: 8 }, (_, i) => `  const v${i} = ${i};`), '  if (event.origin !== ALLOWED) return;', '  apply(event.data);', '});'];
    const f = only(scan('SEC-MESSAGE-ORIGIN', lines.join('\n')), 'inline-window-message-handler');
    expect(f.confidence).toBe('LOW');
  });

  it('leaves a handler that delegates the whole event alone', () => {
    const f = only(scan('SEC-MESSAGE-ORIGIN', 'window.addEventListener("message", (e) => handle(e));'), 'inline-window-message-handler');
    expect(f.confidence).toBe('MEDIUM');
  });
});

describe('AST confirmation: plaintext URLs', () => {
  it('confirms a const URL that flows into fetch, in template, concatenation, and bare forms', () => {
    for (const use of ['fetch(`${API}/v1/items`)', 'fetch(API + "/v1/items")', 'axios.get(API)']) {
      const f = only(scan('NET-URL-HYGIENE', `const API = "http://api.example.com";\n${use};`), 'http-usage');
      expect(f.confidence, use).toBe('HIGH');
    }
  });

  it('confirms a plaintext URL assigned to src or configured as a baseURL', () => {
    expect(only(scan('NET-URL-HYGIENE', 'img.src = "http://cdn.example.com/a.png";'), 'http-usage').confidence).toBe('HIGH');
    expect(only(scan('NET-URL-HYGIENE', 'const client = create({ baseURL: "http://api.example.com" });'), 'http-usage').confidence).toBe('HIGH');
  });

  it('does not treat URL parsing, Request probes, or String#replace as requests (real-bundle false positives)', () => {
    expect(only(scan('NET-URL-HYGIENE', 'try { new URL(`http://[${v}]`) } catch {}'), 'http-usage').confidence).toBe('LOW');
    expect(only(scan('NET-URL-HYGIENE', 'new Request("http://www.example.com");'), 'http-usage').confidence).toBe('LOW');
    expect(only(scan('NET-URL-HYGIENE', 's.replace("x", "http://");'), 'http-usage').confidence).toBe('MEDIUM');
    expect(only(scan('NET-URL-HYGIENE', 'location.replace("http://example.com/next");'), 'http-usage').confidence).toBe('HIGH');
  });

  it('tells a localhost library fallback from a configured dev endpoint', () => {
    const fallback = only(scan('PROD-NO-LOCALHOST', 'const DEFAULT = "http://localhost:9999";\nthis.url = options.url ?? DEFAULT;'), 'localhost-url');
    expect(fallback.confidence).toBe('LOW');
    const inline = only(scan('PROD-NO-LOCALHOST', 'const base = window.location.href || "http://localhost:3000";'), 'localhost-url');
    expect(inline.confidence).toBe('LOW');
    const configured = only(scan('PROD-NO-LOCALHOST', 'const client = axios.create({ baseURL: "http://localhost:3000" });'), 'localhost-url');
    expect(configured.confidence).toBe('HIGH');
    const libraryDefault = only(
      scan('PROD-NO-LOCALHOST', 'const GOTRUE_URL = "http://localhost:9999";\nconst DEFAULTS = { url: GOTRUE_URL, headers: {} };\nfunction make(options) { const settings = { ...DEFAULTS, ...options }; return settings.url; }'),
      'localhost-url'
    );
    expect(libraryDefault.confidence).toBe('LOW');
    expect(libraryDefault.confidenceReason).toContain('spread under caller options');
    const constantRead = only(
      scan('PROD-NO-LOCALHOST', 'const CONFIG = { api: "http://localhost:3000" };\nfetch(CONFIG.api);'),
      'localhost-url'
    );
    expect(constantRead.confidence).toBe('HIGH');
    const requested = only(scan('PROD-NO-LOCALHOST', 'fetch("http://localhost:8031/query");'), 'localhost-url');
    expect(requested.confidence).toBe('HIGH');
  });

  it('clears a URL inside a regular expression and leaves a comparison list alone', () => {
    expect(only(scan('NET-URL-HYGIENE', 'const re = new RegExp("^http://cdn\\.");'), 'http-usage').confidence).toBe('LOW');
    const list = only(scan('NET-URL-HYGIENE', 'const BLOCKED = ["http://evil.example.com"];'), 'http-usage');
    expect(list.confidence).toBe('MEDIUM');
  });
});

describe('AST confirmation: runtime script injection', () => {
  it('confirms a created script element that receives a src, by assignment or setAttribute', () => {
    const assigned = only(scan('SEC-SCRIPT-INJECTION', 'const s = document.createElement("script"); s.src = "https://cdn.example.com/x.js"; document.head.appendChild(s);'), 'script-src-assignment');
    expect(assigned.confidence).toBe('HIGH');
    const attr = only(scan('SEC-SCRIPT-INJECTION', 'var q=document.createElement("script");q.setAttribute("src",u);q.src=u;'), 'script-src-assignment');
    expect(attr.confidence).toBe('HIGH');
  });

  it('confirms <script src> strings only when they reach a DOM sink, not when displayed as install snippets', () => {
    const sink = only(scan('SEC-SCRIPT-INJECTION', 'el.innerHTML = \'<script src="https://cdn.example.com/x.js"></script>\';'), 'script-tag-literal');
    expect(sink.confidence).toBe('HIGH');
    const built = only(scan('SEC-SCRIPT-INJECTION', 'host.insertAdjacentHTML("beforeend", "<div>" + `<script src="https://cdn.example.com/${v}.js"></script>`);'), 'script-tag-literal');
    expect(built.confidence).toBe('HIGH');
    const displayed = only(scan('SEC-SCRIPT-INJECTION', 'const snippet = `<script src="https://cdn.example.com/x.js"></script>`; const html = Prism.highlight(snippet, Prism.languages.markup); pre.innerHTML = html;'), 'script-tag-literal');
    expect(displayed.confidence).toBe('MEDIUM');
  });

  it('clears React DOM resource hoisting, where the .src on the line belongs to other code', () => {
    const reactDom = 'function P(a){var n=u.createElement("script");Hl(n);Xl(n,"link",l);u.head.appendChild(n);return{type:"script",instance:n}}function Q(i){i.src=o}';
    const f = only(scan('SEC-SCRIPT-INJECTION', reactDom), 'script-src-assignment');
    expect(f.confidence).toBe('LOW');
    expect(f.confidenceReason).toContain('never receives a src');
  });
});

describe('AST confirmation: raw HTML', () => {
  it('clears static markup and leaves variables and script markup alone', () => {
    expect(only(scan('SEC-UNSAFE-HTML', 'el.innerHTML = "<p>Loading…</p>";'), 'inner-outer-html').confidence).toBe('LOW');
    expect(only(scan('SEC-UNSAFE-HTML', 'document.write("<p>hi</p>");'), 'doc-write').confidence).toBe('LOW');
    expect(only(scan('SEC-UNSAFE-HTML', 'document.write(html);'), 'doc-write').confidence).toBe('MEDIUM');
    expect(only(scan('SEC-UNSAFE-HTML', 'document.write("<script src=\\"https://x.y/z.js\\"></script>");'), 'doc-write').confidence).toBe('MEDIUM');
  });
});

describe('AST confirmation: boundaries', () => {
  it('skips TypeScript and JSX sources, comment matches, and unparseable files', () => {
    const ts = only(scan('UX-NO-POPUPS', 'window.open("https://promo.example.com");', 'src/main.ts'), 'window-open');
    expect(ts.confidence).toBe('LOW');
    expect(ts.confidenceReason).toBeUndefined();

    const broken = only(scan('UX-NO-POPUPS', 'window.open("https://promo.example.com"); function {'), 'window-open');
    expect(broken.confidenceReason).toBeUndefined();

    const findings: Finding[] = [
      { ruleId: 'UX-NO-POPUPS', matcherId: 'window-open', filePath: 'a.js', line: 1, col: 4, snippet: '', triggerToken: '', locationType: 'COMMENT', confidence: 'LOW' }
    ];
    expect(applyAstConfirmation([file('a.js', '// window.open(x)')], findings)).toBe(0);
  });

  it('declares which matchers it can confirm', () => {
    expect([...AST_CONFIRMABLE_MATCHERS].sort()).toEqual([
      'designer-write-call', 'doc-write', 'get-user-media', 'http-usage', 'inline-window-message-handler', 'inner-outer-html', 'insert-adjacent', 'localhost-url', 'script-src-assignment', 'script-tag-literal', 'window-open'
    ]);
  });
});
