import { describe, expect, it } from 'vitest';

import { defaultRuleset } from './default-ruleset';
import { defaultConfig } from '../policy/default-config';
import { runScan } from '../scanner/scan';
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
  it('is version 1.9.0 and keeps every new matcher at MEDIUM confidence', () => {
    expect(defaultRuleset.rulesetVersion.startsWith('1.9.0')).toBe(true);
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
