import type {
  Ruleset,
  ScanConfig,
  FileEntry,
  Finding,
  RuleMatcher,
  ProgressCallback,
  LocationType,
  Confidence,
  Severity,
  ReviewBucket,
  Disposition
} from '../types';
import { matchesAnyGlob } from '../utils/glob';
import { applyAstConfirmation } from './ast-confirm';

/**
 * Calculate line and column from a string index
 */
function getLineCol(text: string, index: number): { line: number; col: number } {
  if (!text) return { line: 1, col: 1 };

  const upToMatch = text.substring(0, index);
  const matches = upToMatch.match(/\n/g);
  const line = (matches ? matches.length : 0) + 1;
  const lastNewline = upToMatch.lastIndexOf('\n');
  const col = index - lastNewline;

  return { line, col };
}

/**
 * Extract contextual lines around a match
 */
function getContextualSnippet(
  content: string,
  matchIndex: number,
  matchLength: number,
  contextLines = 3
): string {
  if (!content) return '';

  let start = matchIndex;
  let end = matchIndex + matchLength;
  let linesBefore = 0;
  let linesAfter = 0;

  // Find start (go back contextLines newlines)
  while (start > 0 && linesBefore <= contextLines) {
    start--;
    if (content[start] === '\n') linesBefore++;
  }

  // Adjust start to be after the newline
  if (content[start] === '\n') start++;

  // Find end (go forward contextLines newlines)
  while (end < content.length && linesAfter <= contextLines) {
    if (content[end] === '\n') linesAfter++;
    end++;
  }

  return content.substring(start, end);
}

/** Characters a `scope: 'from_match'` override may inspect after the match. */
const OVERRIDE_FROM_MATCH_WINDOW = 200;

/** `webflow.json` at the bundle root (or any directory, for nested uploads). */
const MANIFEST_PATH = /(^|\/)webflow\.json$/i;

/**
 * Hostnames that resolve to the user's own machine. Mirrors the Designer's
 * loopback test for `egress`: `.localhost` is reserved for loopback by RFC
 * 6761, `[::1]` is IPv6 loopback, and the whole 127/8 block is loopback. The
 * 127/8 test is anchored to four octets so `127.0.0.1.evil.com` stays remote.
 */
function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '[::1]' ||
    /^127(?:\.\d{1,3}){3}$/.test(hostname)
  );
}

/**
 * Loopback origins the manifest declares in `egress`. The Designer grants
 * `loopback-network` to the extension iframe only for approved versions whose
 * manifest declares such an entry (webflow/webflow EXT-1727), so a declared
 * loopback URL is a reviewed companion-software connection, not development
 * residue. Non-loopback entries and unparseable entries are ignored here.
 */
function declaredLoopbackOrigins(inventory: FileEntry[]): Set<string> {
  const origins = new Set<string>();
  const manifest = inventory.find((file) => MANIFEST_PATH.test(file.path) && file.content);
  if (!manifest?.content) return origins;
  try {
    const parsed = JSON.parse(manifest.content) as { egress?: unknown };
    if (!Array.isArray(parsed.egress)) return origins;
    for (const entry of parsed.egress) {
      if (typeof entry !== 'string') continue;
      try {
        const url = new URL(entry);
        if (isLoopbackHost(url.hostname)) origins.add(url.origin);
      } catch {
        // Not an absolute URL: declares nothing we can act on.
      }
    }
  } catch {
    // Unparseable manifest: no declarations.
  }
  return origins;
}

/** The absolute URL starting at `index`, as an origin, or null. */
function urlOriginAt(content: string, index: number): string | null {
  const window = content.slice(index, index + OVERRIDE_FROM_MATCH_WINDOW);
  const match = /^[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>)\]},;]+/i.exec(window);
  if (!match) return null;
  try {
    return new URL(match[0]).origin;
  } catch {
    return null;
  }
}

/** Character offset of a 1-based line/column pair. */
function offsetOf(content: string, line: number, col: number): number {
  let offset = 0;
  let current = 1;
  while (current < line) {
    const next = content.indexOf('\n', offset);
    if (next === -1) return -1;
    offset = next + 1;
    current++;
  }
  return offset + col - 1;
}

/**
 * Route a localhost finding whose origin the manifest declares in `egress`
 * to Manual review. Runs after the syntax-tree stage so a declared endpoint
 * is not re-raised as a configured dev endpoint. The finding keeps a MUST
 * severity (MEDIUM) at MEDIUM confidence, which the review layer labels
 * `Manual review` and reads as `needs_review`: a reviewer confirms the
 * local software authenticates callers and the listing states the
 * requirement. An undeclared localhost reference is unchanged.
 */
function applyDeclaredEgress(inventory: FileEntry[], findings: Finding[]): number {
  const declared = declaredLoopbackOrigins(inventory);
  if (declared.size === 0) return 0;
  const contentByPath = new Map<string, string>();
  for (const file of inventory) {
    if (file.content) contentByPath.set(file.path, file.content);
  }
  let routed = 0;
  for (const finding of findings) {
    if (finding.ruleId !== 'PROD-NO-LOCALHOST') continue;
    const content = contentByPath.get(finding.filePath);
    if (!content) continue;
    const offset = offsetOf(content, finding.line, finding.col);
    if (offset < 0) continue;
    const origin = urlOriginAt(content, offset);
    if (!origin || !declared.has(origin)) continue;
    finding.severity = 'MEDIUM';
    finding.reviewBucket = 'NEEDS_EXPLANATION';
    finding.disposition = 'INFO';
    if (finding.locationType !== 'COMMENT') finding.confidence = 'MEDIUM';
    finding.confidenceReason = `Declared in webflow.json egress (${origin}): a loopback endpoint for software the user installs, which the Designer grants only to approved versions that declare it. Reviewer confirms the local software authenticates callers and the listing states the requirement.`;
    routed++;
  }
  return routed;
}

/**
 * Pre-compiled matcher for performance
 */
interface CompiledMatcher {
  regex: RegExp;
  matcher: RuleMatcher;
  ruleId: string;
  ruleCategory: string;
}

/**
 * Run the scanning engine against an inventory of files
 *
 * @param inventory - File inventory to scan
 * @param ruleset - Rules to apply
 * @param config - Scanner configuration
 * @param onProgress - Progress callback
 * @returns Array of findings
 */
export function runScan(
  inventory: FileEntry[],
  ruleset: Ruleset,
  config: ScanConfig,
  onProgress: ProgressCallback
): Finding[] {
  const findings: Finding[] = [];

  // Filter to text files only
  const textFiles = inventory.filter(f => f.isTextCandidate && !f.isIgnored && f.content);

  const rules = ruleset.rules ?? [];

  // Pre-compile all regex matchers
  const compiledMatchers: CompiledMatcher[] = [];

  for (const rule of rules) {
    if (!rule.matchers) continue;

    for (const matcher of rule.matchers) {
      if (matcher.type === 'regex' && matcher.pattern) {
        try {
          // Force 'g' (the scan loop relies on lastIndex advancing; without
          // it the first match repeats until the per-file cap and starves
          // every later matcher) and 'd' for indices support.
          let flags = matcher.flags ?? '';
          if (!flags.includes('g')) flags += 'g';
          if (!flags.includes('d')) flags += 'd';
          compiledMatchers.push({
            regex: new RegExp(matcher.pattern, flags),
            matcher,
            ruleId: rule.ruleId,
            ruleCategory: rule.category
          });
        } catch (e) {
          console.error(`Failed to compile regex for ${rule.ruleId}:`, e);
        }
      }
    }
  }

  let processedCount = 0;
  const ruleMatchCounts = new Map<string, number>();

  // Scan loop
  for (const file of textFiles) {
    processedCount++;

    // Batch progress updates
    if (processedCount % 100 === 0) {
      onProgress(`Scanning ${processedCount}/${textFiles.length} files...`);
    }

    const content = file.content!;
    let fileMatchCount = 0;

    for (const cm of compiledMatchers) {
      // Early exit: check rule-level limits (read live count, not a stale capture)
      if ((ruleMatchCounts.get(cm.ruleId) ?? 0) >= config.limits.maxMatchesPerRule) continue;

      // Early exit: check file globs BEFORE regex execution
      if (!matchesAnyGlob(file.path, cm.matcher.fileGlobs)) continue;

      // Reset regex state for 'g' flag
      cm.regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      let loopCount = 0;

      while ((match = cm.regex.exec(content)) !== null) {
        loopCount++;

        // Safety: prevent infinite loops
        if (loopCount > 5000) break;

        // Config limits (per-file and per-rule, both read live)
        if (fileMatchCount >= config.limits.maxMatchesPerFile) break;
        if ((ruleMatchCounts.get(cm.ruleId) ?? 0) >= config.limits.maxMatchesPerRule) break;

        const index = match.index;
        const matchText = match[0];

        // Guard against empty matches
        if (!matchText || matchText.length === 0) {
          cm.regex.lastIndex++;
          continue;
        }

        // Extract contextual snippet
        let snippet = getContextualSnippet(content, index, matchText.length, 3);

        // Allowlist check
        if (cm.matcher.allowlistPatterns && cm.matcher.allowlistPatterns.length > 0) {
          const isAllowed = cm.matcher.allowlistPatterns.some(pattern => {
            try {
              if (matchText === pattern) return true;
              return new RegExp(pattern, 'i').test(snippet);
            } catch {
              return false;
            }
          });
          if (isAllowed) continue;
        }

        // Determine location type
        let locationType: LocationType = 'CODE';
        const lowerPath = file.path.toLowerCase();

        if (file.tags.includes('SOURCE_MAP') || lowerPath.endsWith('.map')) {
          locationType = 'SOURCE_MAP';
        } else if (lowerPath.includes('test') || lowerPath.includes('spec')) {
          locationType = 'TEST';
        } else if (lowerPath.endsWith('.md') || lowerPath.includes('readme')) {
          locationType = 'DOC';
        } else if (file.ext === '.json') {
          locationType = 'STRING';
        }

        // Check if match is in a comment
        const { line, col } = getLineCol(content, index);
        const lineStart = content.lastIndexOf('\n', index) + 1;
        const lineEnd = content.indexOf('\n', index);
        const lineContent = content.substring(lineStart, lineEnd !== -1 ? lineEnd : content.length);
        const trimmedLine = lineContent.trim();

        if (trimmedLine.startsWith('//')) {
          locationType = 'COMMENT';
        } else if (trimmedLine.startsWith('*') || trimmedLine.startsWith('/*')) {
          // Block-comment line: only a comment if the match sits before the
          // comment closes on this line (`/* note */ eval(x)` is live code).
          const closeIndex = lineContent.indexOf('*/');
          if (closeIndex === -1 || lineStart + closeIndex > index) {
            locationType = 'COMMENT';
          }
        }

        // Determine confidence
        let confidence: Confidence = cm.matcher.confidence ?? 'MEDIUM';
        let confidenceReason: string | undefined;

        // Minified or generated code is harder to read, not less real: an
        // eval() in a production bundle is still an eval(). Keep the
        // matcher's confidence and note the context for the reviewer.
        if (file.tags.includes('MINIFIED_FILE') || file.tags.includes('GENERATED_BUNDLE')) {
          confidenceReason = 'Generated/Minified Code';
        }

        if (locationType === 'COMMENT' || locationType === 'DOC') {
          confidence = 'LOW';
          confidenceReason = 'Comment/Doc Match';
        }

        // Apply conditional overrides
        let severity: Severity | undefined = undefined;
        let reviewBucket: ReviewBucket | undefined = undefined;
        let disposition: Disposition | undefined = undefined;

        if (cm.matcher.conditionalOverrides) {
          for (const override of cm.matcher.conditionalOverrides) {
            try {
              const subject =
                override.scope === 'from_match'
                  ? content.slice(index, index + OVERRIDE_FROM_MATCH_WINDOW)
                  : snippet;
              if (new RegExp(override.pattern, override.flags ?? 'i').test(subject)) {
                if (override.newSeverity) severity = override.newSeverity;
                if (override.newReviewBucket) reviewBucket = override.newReviewBucket;
                if (override.newDisposition) disposition = override.newDisposition;
                if (override.newConfidence && locationType !== 'COMMENT') confidence = override.newConfidence;
                if (override.note) confidenceReason = override.note;
                break;
              }
            } catch (e) {
              console.error('Override regex error:', e);
            }
          }
        }

        // A match inside a comment never executes. Keep it visible as an
        // advisory so a reviewer can see it, but it must not block readiness.
        if (locationType === 'COMMENT') {
          severity = 'LOW';
          reviewBucket = 'INFO';
          disposition = 'INFO';
          confidenceReason = 'Comment match: does not execute';
        }

        // Redact sensitive data in SECURITY findings
        if (cm.ruleCategory === 'SECURITY' && matchText.length > 8) {
          const maskedMatch = matchText.substring(0, 4) + '***' + matchText.substring(matchText.length - 4);
          snippet = snippet.replace(matchText, maskedMatch);
        }

        findings.push({
          ruleId: cm.ruleId,
          matcherId: cm.matcher.id,
          filePath: file.path,
          line,
          col,
          snippet,
          triggerToken: matchText.substring(0, 50),
          locationType,
          confidence,
          confidenceReason,
          tags: file.tags,
          severity,
          reviewBucket,
          disposition
        });

        fileMatchCount++;
        ruleMatchCounts.set(cm.ruleId, (ruleMatchCounts.get(cm.ruleId) ?? 0) + 1);
      }
    }
  }

  // Intentionally no completion logging here: per-upload timings and partner
  // file context must not be written to shared Worker logs. Progress surfaces
  // only through the caller-supplied onProgress callback.
  // Second stage: let the syntax tree settle what the regex could not.
  applyAstConfirmation(inventory, findings, onProgress);
  // Third stage: a declared companion-software endpoint is a review question, not a dev leftover.
  applyDeclaredEgress(inventory, findings);

  return findings;
}
