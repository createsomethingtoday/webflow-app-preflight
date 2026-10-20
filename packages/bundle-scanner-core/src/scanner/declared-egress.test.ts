import { describe, expect, it } from 'vitest';

import { defaultRuleset } from '../policy/default-ruleset';
import { defaultConfig } from '../policy/default-config';
import { runScan } from './scan';
import type { FileEntry, Finding } from '../types';

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

const manifest = (egress: unknown) =>
  file('webflow.json', JSON.stringify({ name: 'Companion', apiVersion: '2', publicDir: 'dist', egress }, null, 2));

function scanLocalhost(files: FileEntry[]): Finding[] {
  const rule = defaultRuleset.rules.find((candidate) => candidate.ruleId === 'PROD-NO-LOCALHOST');
  if (!rule) throw new Error('PROD-NO-LOCALHOST is not in the default ruleset');
  return runScan(files, { ...defaultRuleset, rules: [rule] }, defaultConfig, noop);
}

const inBundle = (findings: Finding[]) => findings.filter((f) => f.filePath === 'dist/app.js');
const inManifest = (findings: Finding[]) => findings.filter((f) => f.filePath === 'webflow.json');

describe('declared egress: loopback endpoints the manifest declares go to Manual review', () => {
  it('routes a request to a declared loopback origin to MEDIUM severity and confidence', () => {
    const findings = scanLocalhost([
      manifest(['ws://localhost:2666', 'http://localhost:6699', 'https://api.example.com']),
      file('dist/app.js', 'const r = await fetch("http://localhost:6699/figma/ping", { method: "POST" });')
    ]);
    const [finding] = inBundle(findings);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('MEDIUM');
    expect(finding?.confidence).toBe('MEDIUM');
    expect(finding?.reviewBucket).toBe('NEEDS_EXPLANATION');
    expect(finding?.disposition).toBe('INFO');
    expect(finding?.confidenceReason).toContain('webflow.json egress (http://localhost:6699)');
  });

  it('treats the manifest entry itself the same way', () => {
    const findings = scanLocalhost([
      manifest(['http://localhost:6699']),
      file('dist/app.js', 'export const ok = 1;')
    ]);
    const [entry] = inManifest(findings);
    expect(entry).toBeDefined();
    expect(entry?.confidence).toBe('MEDIUM');
    expect(entry?.severity).toBe('MEDIUM');
  });

  it('leaves an undeclared port as a configured dev endpoint', () => {
    const findings = scanLocalhost([
      manifest(['http://localhost:6699']),
      file('dist/app.js', 'fetch("http://localhost:3000/api/items");')
    ]);
    const [finding] = inBundle(findings);
    expect(finding?.confidence).toBe('HIGH');
    expect(finding?.severity).toBeUndefined();
    expect(finding?.confidenceReason ?? '').not.toContain('egress');
  });

  it('requires the scheme to match: an http call is not covered by a ws declaration', () => {
    const findings = scanLocalhost([
      manifest(['ws://localhost:2666']),
      file('dist/app.js', 'fetch("http://localhost:2666/status");')
    ]);
    const [finding] = inBundle(findings);
    expect(finding?.confidence).toBe('HIGH');
    expect(finding?.severity).toBeUndefined();
  });

  it('does nothing without a manifest, with a remote-only egress list, or with a malformed one', () => {
    const call = file('dist/app.js', 'fetch("http://localhost:6699/figma/ping");');
    for (const files of [
      [call],
      [manifest(['https://api.example.com']), call],
      [manifest('http://localhost:6699'), call],
      [file('webflow.json', '{ not json'), call]
    ]) {
      const [finding] = inBundle(scanLocalhost(files));
      expect(finding?.confidence).toBe('HIGH');
      expect(finding?.severity).toBeUndefined();
    }
  });

  it('is not fooled by a remote host that merely starts with 127. or contains localhost', () => {
    const findings = scanLocalhost([
      manifest(['http://127.0.0.1.evil.com:6699', 'http://notlocalhost.example.com']),
      file('dist/app.js', 'fetch("http://127.0.0.1.evil.com:6699/x"); fetch("http://localhost:6699/y");')
    ]);
    for (const finding of inBundle(findings)) {
      expect(finding.severity).toBeUndefined();
    }
  });
});
