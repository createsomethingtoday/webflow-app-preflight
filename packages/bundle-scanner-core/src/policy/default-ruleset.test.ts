import { describe, expect, it } from 'vitest';

import { defaultRuleset } from './default-ruleset';
import { defaultConfig } from '../policy/default-config';
import { runScan } from '../scanner/scan';
import { AST_RAISING_MATCHERS } from '../scanner/ast-confirm';
import type { FileEntry } from '../types';

const noop = () => {};

function file(path: string, content: string): FileEntry {
  return {
    path,
    content,
    sizeBytes: content.length,
    ext: path.slice(path.lastIndexOf('.')).toLowerCase(),
    isTextCandidate: true,
    tags: [],
    isIgnored: false
  };
}

function findingsFor(ruleId: string, content: string, path = 'dist/app.js') {
  const rule = defaultRuleset.rules.find((candidate) => candidate.ruleId === ruleId);
  if (!rule) throw new Error(`rule ${ruleId} is not in the default ruleset`);
  return runScan(
    [file(path, content)],
    { ...defaultRuleset, rules: [rule] },
    defaultConfig,
    noop
  );
}

describe('API-ELEMENT-TYPE-DISCRIMINATOR', () => {
  const RULE = 'API-ELEMENT-TYPE-DISCRIMINATOR';

  it('is an advisory rule, never a gate', () => {
    const rule = defaultRuleset.rules.find((candidate) => candidate.ruleId === RULE);
    expect(rule).toBeDefined();
    expect(rule?.severity).toBe('LOW');
    expect(rule?.disposition).toBe('INFO');
    expect(rule?.reviewBucket).toBe('NEEDS_EXPLANATION');
  });

  it.each([
    ['readable strict equality', "if (el.type === 'Section') { render(el); }"],
    ['minified strict equality', 'e.type==="Section"&&r(e)'],
    ['loose equality', 'if (ztsContainer.type == "Section") {}'],
    ['negated comparison', "if (el.type !== 'Section') return;"],
    ['yoda comparison', '"Section"===t.type&&n(t)'],
    ['optional chaining', "if (selected?.type === 'Section') {}"]
  ])('flags a %s against Section', (_label, code) => {
    const findings = findingsFor(RULE, code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe(RULE);
  });

  it.each([
    ['DOM input type checks (React bundles)', 'e.type==="radio"||e.type==="checkbox"'],
    ['event type checks', 't.type==="keydown"'],
    ['the stable getTag() check', "if ((await el.getTag()) === 'section') {}"],
    ['comparison against Block, which is what the runtime returns', "el.type === 'Block'"],
    ['object literal property', "const preset = { type: 'Section', tag: 'section' };"],
    ['non-structural element types', "el.type === 'Heading' || el.type === 'Paragraph'"],
    ['div-tagged block types getTag() cannot distinguish', "el.type === 'Container' || e.type==='VFlex' || t.type === 'Column'"],
    ['bare string literal', "const label = 'Section';"]
  ])('stays quiet on %s', (_label, code) => {
    expect(findingsFor(RULE, code)).toHaveLength(0);
  });

  it('only scans executable source files', () => {
    expect(findingsFor(RULE, "el.type === 'Section'", 'README.md')).toHaveLength(0);
    expect(findingsFor(RULE, "el.type === 'Section'", 'src/main.tsx')).toHaveLength(1);
  });
});

// Reviewer-practice patterns (ruleset 1.9.0). One call to `hits` returns the
// findings of a single matcher so each pattern is tested on its own.
function hits(ruleId: string, matcherId: string, content: string, path = 'dist/app.js') {
  return findingsFor(ruleId, content, path).filter((finding) => finding.matcherId === matcherId);
}

describe('ruleset 1.9.0 reviewer-practice patterns', () => {
  it('keeps every 1.9.0 matcher at MEDIUM confidence', () => {
    const ids = [
      'window-open-no-opener',
      'storage-set-credential-name',
      'client-default-authorization',
      'debug-query-switch',
      'top-target-markup',
      'top-target-assignment'
    ];
    const matchers = defaultRuleset.rules.flatMap((rule) => rule.matchers).filter((m) => ids.includes(m.id));
    expect(matchers.map((m) => m.id).sort()).toEqual([...ids].sort());
    for (const matcher of matchers) {
      expect(matcher.confidence, matcher.id).toBe('MEDIUM');
      expect(matcher.conditionalOverrides, matcher.id).toBeUndefined();
    }
  });

  describe('UX-NO-POPUPS window-open-no-opener', () => {
    const run = (code: string, path?: string) => hits('UX-NO-POPUPS', 'window-open-no-opener', code, path);

    it.each([
      ['two arguments', 'window.open("https://docs.example.com", "_blank");'],
      ['features without noopener', 'window.open(url, "_blank", "width=600,height=400");'],
      ['minified', 'a.onclick=function(){window.open(e.url,"_blank")};'],
      ['call in the URL argument', 'window.open(buildUrl(a, b), "_blank");'],
      ['template literal URL', 'window.open(`https://docs.example.com/${id}`, "_blank");'],
      ['comma inside a string URL', 'window.open("https://x.example.com/a?b=1,2", "_blank");'],
      ['globalThis', 'globalThis.open(u, "_blank")'],
      ['TypeScript source', 'window.open(url, "_blank");', 'src/main.ts']
    ])('flags %s', (_label, code, path) => {
      expect(run(code, path)).toHaveLength(1);
    });

    it.each([
      ['noopener', 'window.open(url, "_blank", "noopener");'],
      ['noopener and noreferrer', 'window.open(url, "_blank", "noopener,noreferrer");'],
      ['noreferrer alone', 'window.open(url,"_blank","noreferrer")'],
      ['minified with noopener', 'window.open(e.url,"_blank","noopener,noreferrer")'],
      ['named target', 'window.open(url, "docs");'],
      ['same-window target', 'window.open(url, "_self");'],
      ['features held in a variable', 'window.open(url, "_blank", features);'],
      ['anchor markup', '<a href="https://docs.example.com" target="_blank">Docs</a>'],
      ['object property, not the window method', 'const t = { open: "_blank" };'],
      ['a different object', 'popup.open(url, "_blank");']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('SEC-NO-SENSITIVE-TOKENS-IN-STORAGE storage-set-credential-name', () => {
    const RULE = 'SEC-NO-SENSITIVE-TOKENS-IN-STORAGE';
    const run = (code: string) => hits(RULE, 'storage-set-credential-name', code);

    it.each([
      ['quoted password', 'localStorage.setItem("password", pw);'],
      ['quoted user_password', "sessionStorage.setItem('user_password', pw);"],
      ['identifier api key', 'localStorage.setItem(STORAGE_API_KEY, value);'],
      ['identifier licenseKey', 'localStorage.setItem(licenseKey, value);'],
      ['identifier member', 'localStorage.setItem(keys.secret, value);'],
      ['minified', 'window.localStorage.setItem(PASSWORD,e)']
    ])('flags %s', (_label, code) => {
      expect(run(code)).toHaveLength(1);
    });

    it.each([
      ['theme key', 'localStorage.setItem("theme", "dark");'],
      ['identifier without a credential name', 'localStorage.setItem(THEME_KEY, "dark");'],
      ['read, not write', 'const p = localStorage.getItem("password");'],
      ['another API', 'cache.setItem("password", x);'],
      ['credential only in the value', 'localStorage.setItem("pref", "password");']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });

    it.each([
      'localStorage.setItem("apiKey", k);',
      'localStorage.setItem("api_key", k);',
      'localStorage.setItem("licenseKey", k);',
      'localStorage.setItem("license_key", k);',
      "sessionStorage.setItem('Secret', k);",
      'localStorage.setItem(`${ns}_API_KEY`, k);'
    ])('quoted credential names are already caught once by the token matcher: %s', (code) => {
      expect(hits(RULE, 'storage-set-token', code)).toHaveLength(1);
      expect(hits(RULE, 'storage-set-credential-name', code)).toHaveLength(0);
    });
  });

  describe('NET-GLOBAL-AUTH-DEFAULT client-default-authorization', () => {
    const run = (code: string) => hits('NET-GLOBAL-AUTH-DEFAULT', 'client-default-authorization', code);

    it.each([
      ['bracket on common', "axios.defaults.headers.common['Authorization'] = `Bearer ${t}`;"],
      ['dot on common', 'axios.defaults.headers.common.Authorization = token;'],
      ['dot on headers', 'axios.defaults.headers.Authorization = token;'],
      ['instance from axios.create', 'api.defaults.headers.common["Authorization"] = "Bearer " + t;'],
      ['minified', 'e.defaults.headers.common.Authorization="Bearer "+t']
    ])('flags %s', (_label, code) => {
      expect(run(code)).toHaveLength(1);
    });

    it.each([
      ['per-request header', 'axios.get(url, { headers: { Authorization: `Bearer ${t}` } });'],
      ['comparison', 'if (axios.defaults.headers.common.Authorization === token) {}'],
      ['other default header', "axios.defaults.headers.common['Accept'] = 'application/json';"],
      ['removing the default', 'delete axios.defaults.headers.common.Authorization;'],
      ['base URL default', 'axios.defaults.baseURL = "https://api.example.com";']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('PROD-NO-DEBUG-RESIDUE debug-query-switch', () => {
    const run = (code: string) => hits('PROD-NO-DEBUG-RESIDUE', 'debug-query-switch', code);

    it.each([
      ['inline get', "const d = new URLSearchParams(location.search).get('debug');"],
      ['inline get, prefixed key', 'new URLSearchParams(window.location.search).get("xyz_debug")'],
      ['inline has', 'if (new URLSearchParams(location.search).has("debug")) {}'],
      ['params variable', "const params = new URLSearchParams(location.search);\nif (params.get('mimic')) {}"],
      ['debug_ prefix', 'searchParams.get("debug_mode")'],
      ['bypass', 'url.searchParams.has("bypass")'],
      ['minified variable', 'var t=new URLSearchParams(location.search),n=t.get("debug");n&&r()'],
      ['location.search includes', "if (location.search.includes('debug=')) {}"],
      ['location.search includes, no equals', 'location.search.includes("debug")']
    ])('flags %s', (_label, code) => {
      expect(run(code)).toHaveLength(1);
    });

    it.each([
      ['unrelated key', "new URLSearchParams(location.search).get('page')"],
      ['key that only contains debug', "params.get('debugger')"],
      ['a Map named config', "config.get('debug')"],
      ['a Map, not URL params', "const m = new Map(); m.get('debug');"],
      ['unrelated search check', "location.search.includes('page=')"],
      ['variable used for another key', "const p = new URLSearchParams(s);\np.get('q');\nconfig.get('debug')"],
      ['environment flag', 'if (process.env.DEBUG) {}']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('SEC-UNTRUSTED-REDIRECT top-frame target', () => {
    const RULE = 'SEC-UNTRUSTED-REDIRECT';
    const markup = (code: string, path?: string) => hits(RULE, 'top-target-markup', code, path);
    const assign = (code: string) => hits(RULE, 'top-target-assignment', code);

    it.each([
      ['anchor _top', '<a href="https://x.example.com" target="_top">Go</a>', 'dist/index.html'],
      ['form _parent', '<form action="/save" method="post" target="_parent">', 'dist/index.html'],
      ['JSX arrow handler before target', '<a onClick={() => go()} href={u} target="_top">Go</a>', 'src/App.tsx'],
      ['markup in a JS string', 'host.innerHTML = \'<a href="/x" target="_top">x</a>\';', undefined],
      ['escaped quotes in a string', 'const h = "<form target=\\"_top\\" action=\\"/p\\">";', undefined],
      ['compiled createElement', 'React.createElement("a",{href:u,target:"_top"},"Go")', undefined],
      ['compiled jsx', 'jsx("form",{action:u,target:"_parent",children:c})', undefined]
    ])('flags markup: %s', (_label, code, path) => {
      expect(markup(code, path)).toHaveLength(1);
    });

    it.each([
      ['anchor _blank', '<a href="https://x.example.com" target="_blank" rel="noopener">Go</a>'],
      ['anchor _self', '<a href="/x" target="_self">x</a>'],
      ['iframe target', '<iframe name="_top_frame" src="/x"></iframe>'],
      ['target on another element', '<base target="_top">'],
      ['compiled _blank', 'jsx("a",{href:u,target:"_blank",rel:"noopener"})'],
      ['plain text mention', 'const doc = "use _top for the top frame";']
    ])('stays quiet on markup: %s', (_label, code) => {
      expect(markup(code)).toHaveLength(0);
    });

    it.each([
      ['target assignment', "form.target = '_top';"],
      ['formTarget assignment', 'btn.formTarget = "_parent";'],
      ['minified assignment', 'e.target="_top",e.submit()'],
      ['formTarget property', 'const props = { formTarget: "_top", type: "submit" };'],
      ['setAttribute target', 'a.setAttribute("target", "_top");'],
      ['setAttribute formtarget', "b.setAttribute('formtarget','_parent')"]
    ])('flags assignment: %s', (_label, code) => {
      expect(assign(code)).toHaveLength(1);
    });

    it.each([
      ['_blank assignment', "a.target = '_blank';"],
      ['comparison', "if (el.target === '_top') {}"],
      ['event target', 'const t = event.target;'],
      ['setAttribute _self', 'a.setAttribute("target","_self")']
    ])('stays quiet on assignment: %s', (_label, code) => {
      expect(assign(code)).toHaveLength(0);
    });

    it('does not change the existing top.location matcher', () => {
      expect(hits(RULE, 'top-nav-assignment', 'top.location.href = next;')).toHaveLength(1);
      expect(hits(RULE, 'top-nav-assignment', "form.target = '_top';")).toHaveLength(0);
    });
  });
});

// Recent review findings (ruleset 1.11.0): patterns reviewers wrote by hand in
// the November 2026 rejections. Fixtures are generic shapes, not App code.
describe('ruleset 1.11.0 recent review findings', () => {
  const MUST_IDS = [
    'style-element-inject',
    'style-tag-in-code',
    'iframe-element-create',
    'iframe-device-permissions',
    'cookie-jar-egress',
    'page-url-egress',
    'react-raw-html',
    'placeholder-link',
    'dev-build-notice'
  ];

  it('is version 1.11.0, and every new matcher is MEDIUM on a MUST rule', () => {
    expect(defaultRuleset.rulesetVersion.startsWith('1.11.0')).toBe(true);
    const found = defaultRuleset.rules.flatMap((rule) =>
      rule.matchers.filter((m) => MUST_IDS.includes(m.id)).map((m) => ({ rule, m }))
    );
    expect(found.map(({ m }) => m.id).sort()).toEqual([...MUST_IDS].sort());
    for (const { rule, m } of found) {
      expect(m.confidence, m.id).toBe('MEDIUM');
      expect(m.conditionalOverrides, m.id).toBeUndefined();
      expect(['HIGH', 'BLOCKER'], m.id).toContain(rule.severity);
      expect(AST_RAISING_MATCHERS.has(m.id), m.id).toBe(false);
    }
  });

  it('keeps native dialogs a suggestion, never a gate', () => {
    const rule = defaultRuleset.rules.find((candidate) => candidate.ruleId === 'UX-NATIVE-DIALOGS');
    expect(rule?.severity).toBe('LOW');
    expect(rule?.reviewBucket).toBe('NEEDS_EXPLANATION');
  });

  describe('SEC-CSP-INLINE style-element-inject', () => {
    const run = (code: string) => hits('SEC-CSP-INLINE', 'style-element-inject', code);

    it.each([
      ['textContent', 'const s = document.createElement("style"); s.textContent = css; document.head.appendChild(s);'],
      ['minified', 'var e=document.createElement("style");e.setAttribute("data-editor-style",""),e.innerHTML=t,document.head.appendChild(e)'],
      ['text node', "var s=d.createElement('style');s.appendChild(d.createTextNode(css));"],
      ['old IE cssText', 'var s=document.createElement("style");s.styleSheet.cssText=c;'],
      ['insertRule', 'const s=document.createElement(`style`);document.head.append(s);s.sheet.insertRule(rule);']
    ])('flags %s', (_label, code) => {
      expect(run(code)).toHaveLength(1);
    });

    it.each([
      ['creation alone', 'const s = document.createElement("style"); s.setAttribute("data-precedence", p); parent.appendChild(s);'],
      ['a comparison, not an assignment', 'var s=document.createElement("style");if(a.textContent==b)return;'],
      ['a stylesheet link', 'const l = document.createElement("link"); l.rel = "stylesheet"; l.href = url;'],
      ['text set far away', `const s=document.createElement("style");${'x();'.repeat(100)}s.textContent=css;`],
      ['a different element', 'const p = document.createElement("p"); p.textContent = label;']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('SEC-CSP-INLINE style-tag-in-code', () => {
    const run = (code: string) => hits('SEC-CSP-INLINE', 'style-tag-in-code', code);

    it.each([
      ['innerHTML string', 'root.innerHTML = "<style>.w{color:red}</style><div class=w></div>";'],
      ['template literal', 'shadow.innerHTML = `\n  <style>\n    .w { color: red }\n  </style>`;'],
      ['after other markup', "el.innerHTML='<div></div><style nonce=x>.a{}</style>';"]
    ])('flags %s', (_label, code) => {
      expect(run(code)).toHaveLength(1);
    });

    it.each([
      ['the word style', 'el.style.color = "red"; const kind = "style";'],
      ['a styled component tag name', 'const tag = "<styled-box>";'],
      ['a selector string', 'document.querySelectorAll("style, link[rel=stylesheet]");']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('IFRAME-EXTERNAL-SRC iframe-element-create', () => {
    const run = (code: string) => hits('IFRAME-EXTERNAL-SRC', 'iframe-element-create', code);

    it('flags an iframe built in code', () => {
      expect(run('const f = document.createElement("iframe"); f.src = base + "/embed/" + id; box.appendChild(f);')).toHaveLength(1);
      expect(run("var f=d.createElement('iframe');")).toHaveLength(1);
    });

    it('stays quiet on other elements and on a variable tag', () => {
      expect(run('document.createElement("div"); document.createElement(tag); const t = "iframe";')).toHaveLength(0);
    });
  });

  describe('SEC-WEBRTC-HARDWARE iframe-device-permissions', () => {
    const run = (code: string, path?: string) => hits('SEC-WEBRTC-HARDWARE', 'iframe-device-permissions', code, path);

    it.each([
      ['property assignment', 'frame.allow = "microphone; display-capture";'],
      ['setAttribute', 'f.setAttribute("allow", "autoplay; camera; microphone");'],
      ['markup', '<iframe src="https://app.vendor.com/chat" allow="microphone"></iframe>', 'dist/index.html'],
      ['markup inside a string', "el.innerHTML='<iframe allow=\"camera\"></iframe>';"]
    ])('flags %s', (_label, code, path) => {
      expect(run(code, path)).toHaveLength(1);
    });

    it.each([
      ['no device permission', 'frame.allow = "autoplay; clipboard-write; fullscreen";'],
      ['allowFullscreen', 'frame.allowFullscreen = true;'],
      ['an unrelated variable', 'const allow = ["microphone"]; if (allow.includes(x)) go();'],
      ['a sandbox attribute', 'f.setAttribute("sandbox", "allow-scripts allow-same-origin");']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('PRIV-PAGE-DATA-EGRESS cookie-jar-egress', () => {
    const run = (code: string) => hits('PRIV-PAGE-DATA-EGRESS', 'cookie-jar-egress', code);

    it.each([
      ['base64 of all cookies', 'frame.contentWindow.postMessage({ type: "sync", data: btoa(document.cookie) }, origin);'],
      ['object property', 'fetch(api, { method: "POST", body: JSON.stringify({ site: id, cookies: document.cookie }) });'],
      ['minified property', 'n({u:e,c:document.cookie})'],
      ['query value', 'img.src = base + "?c=" + encodeURIComponent(document.cookie);'],
      ['beacon argument', 'navigator.sendBeacon(url, JSON.stringify(document.cookie));']
    ])('flags %s', (_label, code) => {
      expect(run(code)).toHaveLength(1);
    });

    it.each([
      ['reading one cookie', 'const m = document.cookie.match(/(?:^|; )consent=([^;]*)/);'],
      ['split and find', 'const parts = document.cookie.split("; ").find((p) => p.startsWith("id="));'],
      ['writing a cookie', 'document.cookie = "consent=1; path=/; Secure; SameSite=Lax";'],
      ['a ternary, not a property', 'const c = ok ? cached : document.cookie;'],
      ['a local read', 'const jar = document.cookie;']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('PRIV-PAGE-DATA-EGRESS page-url-egress', () => {
    const run = (code: string) => hits('PRIV-PAGE-DATA-EGRESS', 'page-url-egress', code);

    it.each([
      ['full URL in a request body', 'fetch(api, { method: "POST", body: JSON.stringify({ subject: id, url: window.location.href }) });'],
      ['minified', 'p({t:"nav",u:location.href})'],
      ['quoted key', 'send({ "page-url": document.location.href });'],
      ['query string into another URL', 'frame.src = base + "?ref=" + encodeURIComponent(location.search);'],
      ['query string property', 'track({ event: "view", query: window.location.search });']
    ])('flags %s', (_label, code) => {
      expect(run(code)).toHaveLength(1);
    });

    it.each([
      ['origin and path only', 'send({ origin: location.origin, path: location.pathname });'],
      ['navigation', 'window.location.href = next;'],
      ['a ternary, not a property', 'const u = ok ? fallback : location.href;'],
      ['parsing the URL locally', 'const page = new URL(location.href).searchParams.get("page");'],
      ['a method call on the value', 'send({ hasQuery: location.search.length > 0, host: location.href.split("/")[2] });']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('SEC-UNSAFE-HTML react-raw-html', () => {
    const run = (code: string) => hits('SEC-UNSAFE-HTML', 'react-raw-html', code);

    it('flags a variable passed as raw HTML', () => {
      expect(run('jsx("div", { className: "preview", dangerouslySetInnerHTML: { __html: preview.html } })')).toHaveLength(1);
      expect(run('e.jsx("div",{dangerouslySetInnerHTML:{__html:t}})')).toHaveLength(1);
    });

    it.each([
      ['a static string', 'jsx("span", { dangerouslySetInnerHTML: { __html: "&nbsp;" } })'],
      ['the prop name in a renderer', 'case "dangerouslySetInnerHTML": if (null != c) { if ("object" !== typeof c || !("__html" in c)) throw Error(f(61)); }'],
      ['a property read', 'var h = p.dangerouslySetInnerHTML; null != h && null != h.__html && set(h.__html);']
    ])('stays quiet on %s', (_label, code) => {
      expect(run(code)).toHaveLength(0);
    });
  });

  describe('PROD-PLACEHOLDER-CONTENT', () => {
    it('flags placeholder links with a path', () => {
      const run = (code: string) => hits('PROD-PLACEHOLDER-CONTENT', 'placeholder-link', code);
      expect(run('const sample = `<a href="https://example.com/your-page">Read more</a>`;')).toHaveLength(1);
      expect(run('links:["http://www.example.org/press-release"]')).toHaveLength(1);
      expect(run('new URL(path, "https://example.com")')).toHaveLength(0);
      expect(run('new URL(path, "http://example.com/")')).toHaveLength(0);
      expect(run('const docs = "https://docs.example-app.io/guide";')).toHaveLength(0);
    });

    it('flags development and staging notices', () => {
      const run = (code: string) => hits('PROD-PLACEHOLDER-CONTENT', 'dev-build-notice', code);
      expect(run('jsx("p", { children: "Development build · not for production use" })')).toHaveLength(1);
      expect(run('const note = "Staging: payments are turned off";')).toHaveLength(1);
      expect(run('const step = "Build your page, then publish"; const env = "production build";')).toHaveLength(0);
      expect(run('const label = "Staging"; const hosts = { staging: url };')).toHaveLength(0);
    });
  });

  describe('UX-NATIVE-DIALOGS native-dialog', () => {
    const run = (code: string) => hits('UX-NATIVE-DIALOGS', 'native-dialog', code);

    it('flags window.prompt, window.alert and window.confirm', () => {
      expect(run('const url = window.prompt("URL"); if (!window.confirm("Discard changes?")) return; window.alert("Not supported");')).toHaveLength(3);
    });

    it('stays quiet on app functions with the same names', () => {
      expect(run('dialog.confirm("Discard?"); toast.alert(msg); const prompt = buildPrompt(); this.confirm();')).toHaveLength(0);
    });
  });
});

// Backtracking guard. A regex cannot be stopped once it starts, and the scan
// runs each matcher over whole files in the Worker and in the sandbox runner.
// So every regex matcher must stay close to linear on text that a developer,
// or a bundler, can produce. Each shape below made a 1.9.0 matcher take
// seconds before its pattern was bounded.
describe('regex matchers do not backtrack badly', () => {
  const LIMIT_MS = 300;
  const shapes: Array<[string, (token: string) => string]> = [
    ['a long identifier run', (token) => `${token} x="${'a'.repeat(120_000)}";`],
    ['an identifier run after a constructor', (token) => `new ${token}(location.search);var x="${'a'.repeat(120_000)}";`],
    ['a long run of spaces', (token) => `${token}${' '.repeat(120_000)}`],
    ['an open call and spaces', (token) => `${token}(${' '.repeat(3_000)}`],
    ['an unclosed string of one repeated word', (token) => `localStorage.${token}('${'password'.repeat(15_000)}`],
    ['an unquoted run of one repeated word', (token) => `localStorage.${token}(${'secret'.repeat(20_000)}`],
    ['the token repeated', (token) => `${token}(`.repeat(20_000)]
  ];
  const cases = defaultRuleset.rules.flatMap((rule) =>
    rule.matchers
      .filter((matcher) => matcher.type === 'regex' && matcher.pattern)
      .map((matcher) => [matcher.id, matcher] as const)
  );

  it.each(cases)('%s', (_id, matcher) => {
    // The same flags the scan loop compiles with.
    let flags = matcher.flags ?? '';
    if (!flags.includes('g')) flags += 'g';
    const tokens = matcher.triggerTokens?.length ? matcher.triggerTokens : ['x'];
    for (const token of tokens) {
      for (const [label, build] of shapes) {
        const regex = new RegExp(matcher.pattern as string, flags);
        const text = build(token);
        const started = performance.now();
        let match: RegExpExecArray | null;
        let count = 0;
        while ((match = regex.exec(text)) !== null && count < 5000) {
          count += 1;
          if (match[0] === '') regex.lastIndex += 1;
        }
        expect(performance.now() - started, `${matcher.id} on ${label} (${token})`).toBeLessThan(LIMIT_MS);
      }
    }
  });
});
