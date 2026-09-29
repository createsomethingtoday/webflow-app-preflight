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
