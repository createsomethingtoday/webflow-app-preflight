import { describe, expect, test } from 'vitest';
import {
  classifyRuntimeUrlMutability,
  discoverRuntimeReferences,
  mutableRuntimeUrls
} from '../src/index';

describe('discoverRuntimeReferences', () => {
  test('does not combine runtime paths with example or asset origins', () => {
    const references = discoverRuntimeReferences([
      {
        path: 'assets/index.js',
        sizeBytes: 300,
        ext: '.js',
        isTextCandidate: true,
        isIgnored: false,
        tags: [],
        content: [
          'const API = "https://api.consentpro.com";',
          'const example = "https://api.example.com/consent";',
          'const asset = "https://cdn.prod.website-files.com/file.svg";',
          'const runtime = "/v2/cdn/runtime.js";',
          'const versioned = "/v2/cdn/runtime/${id}.js";'
        ].join('\n')
      }
    ]);

    expect(references).toEqual([
      'https://api.consentpro.com/v2/cdn/runtime.js',
      'https://api.consentpro.com/v2/cdn/runtime/{id}.js'
    ]);
  });
});

describe('classifyRuntimeUrlMutability', () => {
  const cases: Array<[string, 'versioned' | 'content_hashed' | 'mutable']> = [
    // versioned
    ['https://cdn.example.com/app/v1.2.3/runtime.js', 'versioned'],
    ['https://cdn.example.com/app/1.4.0/runtime.js', 'versioned'],
    ['https://cdn.example.com/npm/widget@1.2.3/dist/run.js', 'versioned'],
    ['https://cdn.example.com/widget-1.2.3.js', 'versioned'],
    ['https://cdn.example.com/js/widget.1.2.3.min.js', 'versioned'],
    ['https://cdn.example.com/js/widget-v2.0.1-beta.4.js', 'versioned'],
    // content hashed
    ['https://cdn.example.com/widget.3f9a2c1b.js', 'content_hashed'],
    ['https://cdn.example.com/a1b2c3d4e5f6/app.js', 'content_hashed'],
    ['https://cdn.example.com/assets/index-DX7k2m9pQ.js'.toLowerCase(), 'content_hashed'],
    ['https://cdn.example.com/widget.3F9A2C1B.min.js', 'content_hashed'],
    ['https://cdn.example.com/v1.2.3/app.3f9a2c1b.js', 'content_hashed'],
    // mutable
    ['https://cdn.example.com/app/v1/runtime.js', 'mutable'],
    ['https://cdn.example.com/npm/widget@latest/dist/run.js', 'mutable'],
    ['https://cdn.example.com/npm/widget@1/dist/run.js', 'mutable'],
    ['https://cdn.example.com/npm/widget@1.2/dist/run.js', 'mutable'],
    ['https://cdn.example.com/runtime.js', 'mutable'],
    ['https://cdn.example.com/runtime.js?v=3', 'mutable'],
    ['https://cdn.example.com/runtime.js?v=1.2.3', 'mutable'],
    ['https://cdn.example.com/runtime.js?hash=3f9a2c1b4d5e', 'mutable'],
    ['https://cdn.example.com/runtime.min.js', 'mutable'],
    ['https://cdn.example.com/js/20241113/runtime.js', 'mutable'],
    ['https://cdn.example.com/dist/es2015bundle.js', 'mutable'],
    ['https://cdn.example.com/javascript-loader/latest.js', 'mutable'],
    ['https://cdn.example.com/deadbeef/runtime.js', 'mutable'],
    ['https://v1.2.3.example.com/runtime.js', 'mutable'],
    ['not a url', 'mutable']
  ];

  test.each(cases)('%s is %s', (url, expected) => {
    expect(classifyRuntimeUrlMutability(url)).toBe(expected);
  });

  test('lists only the mutable URLs, in order', () => {
    expect(
      mutableRuntimeUrls([
        'https://cdn.example.com/run.js',
        'https://cdn.example.com/v1.2.3/run.js',
        'https://cdn.example.com/v1/other.js'
      ])
    ).toEqual(['https://cdn.example.com/run.js', 'https://cdn.example.com/v1/other.js']);
  });
});
