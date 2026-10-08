/**
 * Second-stage confirmation for regex findings, on the syntax tree.
 *
 * A regex sees text; several published MUSTs turn on context a regex cannot
 * read: is the value pushed into innerHTML a literal or a variable, does
 * window.open run inside a click handler or at module load, does a message
 * handler ever read event.origin, does an http:// literal flow into a
 * request. This stage parses only the files that already carry a finding
 * from a confirmable matcher (built bundles are plain JavaScript; TypeScript
 * and JSX sources are skipped) and moves the finding's confidence:
 *
 * - HIGH  when the tree proves the violation (so the finding can gate),
 * - LOW   when the tree proves the benign case (so it becomes a hint),
 * - unchanged when the tree cannot decide.
 *
 * Every adjustment records a `confidenceReason` the reviewer can read. A
 * parse failure or an unrecognised shape leaves the regex result alone: the
 * stage can only make a finding more certain in either direction, never
 * less.
 */
import { parse } from 'acorn';
import * as walk from 'acorn-walk';
import type { Confidence, FileEntry, Finding } from '../types';

type AnyNode = { type: string; start: number; end: number } & Record<string, any>;

interface Adjustment {
  confidence: Confidence;
  reason: string;
}

interface ConfirmContext {
  finding: Finding;
  offset: number;
  ast: AnyNode;
  content: string;
  index: FileIndex;
}

type Confirmer = (ctx: ConfirmContext) => Adjustment | null;

const PARSE_SIZE_LIMIT = 4 * 1024 * 1024;
const PARSEABLE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);

const USER_EVENTS = new Set([
  'click', 'dblclick', 'auxclick', 'contextmenu',
  'mousedown', 'mouseup', 'pointerdown', 'pointerup', 'touchstart', 'touchend',
  'keydown', 'keyup', 'keypress',
  'submit', 'change', 'input', 'paste', 'drop'
]);
const LOAD_EVENTS = new Set(['load', 'DOMContentLoaded', 'readystatechange', 'pageshow']);
const TIMER_CALLEES = new Set(['setTimeout', 'setInterval', 'requestAnimationFrame', 'requestIdleCallback', 'queueMicrotask']);
const MOUNT_HOOKS = new Set(['useEffect', 'useLayoutEffect', 'onMounted', 'mounted', 'ngOnInit', 'componentDidMount']);
// Calls that put a URL on the wire. `new URL()` and `new Request()` only
// parse (zod validates IPv6 with `new URL(\`http://[${v}]\`)`; fetch feature
// probes build a Request), and String#replace is not Location#replace, so
// those are handled separately below.
const REQUEST_CALLEES = new Set(['fetch', 'axios', 'get', 'post', 'put', 'patch', 'delete', 'head', 'request', 'open', 'WebSocket', 'EventSource', 'navigate']);
const LOCATION_NAVIGATION = new Set(['assign', 'replace']);
const URL_SINK_PROPERTIES = new Set(['src', 'href', 'action', 'url', 'baseURL', 'baseUrl', 'endpoint']);
const FUNCTION_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

/** Matchers this stage can move to HIGH, so their rule can gate readiness. */
export const AST_RAISING_MATCHERS: ReadonlySet<string> = new Set([
  'script-src-assignment',
  'script-tag-literal',
  'window-open',
  'designer-write-call',
  'get-user-media',
  'inline-window-message-handler',
  'http-usage'
]);

/** Every matcher this stage touches (the raw-HTML ones only ever move down). */
export const AST_CONFIRMABLE_MATCHERS: ReadonlySet<string> = new Set([
  ...AST_RAISING_MATCHERS,
  'localhost-url',
  'doc-write',
  'inner-outer-html',
  'insert-adjacent'
]);

// ---------------------------------------------------------------------------
// Per-file index: parse once, walk once, answer many questions.
// ---------------------------------------------------------------------------

interface Located {
  node: AnyNode;
  ancestors: AnyNode[];
}

class FileIndex {
  readonly nodes: Located[] = [];
  /** Identifier names bound as user-interaction handlers → the scope node that saw the binding. */
  readonly handlerNames = new Map<string, AnyNode[]>();
  readonly lineStarts: number[];

  constructor(readonly ast: AnyNode, readonly content: string) {
    this.lineStarts = [0];
    for (let i = 0; i < content.length; i += 1) {
      if (content.charCodeAt(i) === 10) this.lineStarts.push(i + 1);
    }
    walk.fullAncestor(ast as any, (node: any, _state: unknown, ancestors: any[]) => {
      const chain = ancestors.slice(0, -1) as AnyNode[];
      this.nodes.push({ node, ancestors: chain });
      this.recordHandlerBinding(node, chain);
    });
  }

  offsetOf(line: number, col: number): number {
    const start = this.lineStarts[line - 1];
    if (start === undefined) return -1;
    return start + col - 1;
  }

  /** Smallest node of one of `types` whose span covers `offset`. */
  smallestAt(offset: number, types: ReadonlySet<string>, accept?: (node: AnyNode) => boolean): Located | null {
    let best: Located | null = null;
    for (const entry of this.nodes) {
      const { node } = entry;
      if (!types.has(node.type) || node.start > offset || node.end <= offset) continue;
      if (accept && !accept(node)) continue;
      if (!best || node.end - node.start < best.node.end - best.node.start) best = entry;
    }
    return best;
  }

  private recordHandlerBinding(node: AnyNode, ancestors: AnyNode[]): void {
    const scope = enclosingScope(ancestors);
    const bind = (value: AnyNode | undefined) => {
      if (value && value.type === 'Identifier') {
        const list = this.handlerNames.get(value.name) ?? [];
        list.push(scope);
        this.handlerNames.set(value.name, list);
      }
    };
    if (node.type === 'CallExpression' && isListenerRegistration(node) && isUserEventLiteral(node.arguments[0])) {
      bind(node.arguments[1]);
    } else if (node.type === 'Property' && isUserEventPropertyKey(node)) {
      bind(node.value);
    } else if (node.type === 'AssignmentExpression' && isUserEventMemberTarget(node.left)) {
      bind(node.right);
    }
  }
}

function enclosingScope(ancestors: AnyNode[]): AnyNode {
  for (let i = ancestors.length - 1; i >= 0; i -= 1) {
    const candidate = ancestors[i];
    if (candidate && FUNCTION_TYPES.has(candidate.type)) return candidate;
  }
  // The Program node is always ancestors[0] for anything below it; a call
  // with an empty chain is the Program itself, which binds nothing.
  return ancestors[0] as AnyNode;
}

function propertyName(node: AnyNode | undefined): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0]?.value?.cooked ?? null;
  return null;
}

function memberProperty(node: AnyNode | undefined): string | null {
  if (!node || node.type !== 'MemberExpression') return null;
  return node.computed ? propertyName(node.property) : propertyName(node.property);
}

function stringValue(node: AnyNode | undefined): string | null {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0]?.value?.cooked ?? null;
  return null;
}

function isListenerRegistration(call: AnyNode): boolean {
  const prop = memberProperty(call.callee);
  return prop === 'addEventListener' || prop === 'on' || prop === 'once';
}

function isUserEventLiteral(node: AnyNode | undefined): boolean {
  const value = stringValue(node);
  return value !== null && USER_EVENTS.has(value);
}

function isLoadEventLiteral(node: AnyNode | undefined): boolean {
  const value = stringValue(node);
  return value !== null && LOAD_EVENTS.has(value);
}

function eventNameFromHandlerKey(name: string | null): string | null {
  if (!name || !/^on[A-Za-z]+$/.test(name)) return null;
  return name.slice(2).toLowerCase();
}

function isUserEventPropertyKey(property: AnyNode): boolean {
  const event = eventNameFromHandlerKey(propertyName(property.key));
  return event !== null && USER_EVENTS.has(event);
}

function isUserEventMemberTarget(target: AnyNode): boolean {
  const event = eventNameFromHandlerKey(memberProperty(target));
  return event !== null && USER_EVENTS.has(event);
}

/** Is `fn` (a function node) bound as a user-interaction handler? */
function isUserHandler(fn: AnyNode, parent: AnyNode | undefined, ancestors: AnyNode[], index: FileIndex): boolean {
  if (!parent) return false;
  if (parent.type === 'CallExpression' && isListenerRegistration(parent) && parent.arguments[1] === fn) {
    return isUserEventLiteral(parent.arguments[0]);
  }
  if (parent.type === 'Property' && parent.value === fn) return isUserEventPropertyKey(parent);
  if (parent.type === 'AssignmentExpression' && parent.right === fn) return isUserEventMemberTarget(parent.left);
  // A named function referenced from a handler position in the same scope.
  const name =
    fn.type === 'FunctionDeclaration' && fn.id
      ? fn.id.name
      : parent.type === 'VariableDeclarator' && parent.init === fn && parent.id.type === 'Identifier'
        ? parent.id.name
        : null;
  if (!name) return false;
  const bindings = index.handlerNames.get(name);
  if (!bindings) return false;
  const declaringScope = enclosingScope(ancestors);
  return bindings.includes(declaringScope);
}

function isImmediatelyInvoked(fn: AnyNode, parent: AnyNode | undefined): boolean {
  return !!parent && parent.type === 'CallExpression' && parent.callee === fn;
}

type ExecutionPath = 'handler' | 'load' | 'timer' | 'mount' | 'unknown';

/**
 * Walk outward through the enclosing functions and classify how the code at
 * `ancestors` comes to run. Immediately-invoked wrappers are transparent.
 */
function executionPath(ancestors: AnyNode[], index: FileIndex): ExecutionPath {
  for (let i = ancestors.length - 1; i >= 0; i -= 1) {
    const node = ancestors[i];
    if (!node || !FUNCTION_TYPES.has(node.type)) continue;
    const parent = ancestors[i - 1];
    if (isUserHandler(node, parent, ancestors.slice(0, i), index)) return 'handler';
    if (isImmediatelyInvoked(node, parent)) continue;
    if (parent && parent.type === 'CallExpression' && parent.arguments.includes(node)) {
      const callee = parent.callee;
      const calleeName = callee.type === 'Identifier' ? callee.name : memberProperty(callee);
      if (calleeName && TIMER_CALLEES.has(calleeName)) return 'timer';
      if (calleeName && MOUNT_HOOKS.has(calleeName)) return 'mount';
      if (isListenerRegistration(parent) && isLoadEventLiteral(parent.arguments[0])) return 'load';
    }
    return 'unknown';
  }
  return 'load';
}

// ---------------------------------------------------------------------------
// Confirmers
// ---------------------------------------------------------------------------

const CALL_TYPES = new Set(['CallExpression', 'NewExpression']);

function calleeText(call: AnyNode, content: string): string {
  return content.slice(call.callee.start, call.callee.end);
}

function confirmInteraction(pattern: RegExp): Confirmer {
  return ({ finding, offset, content, index }) => {
    const located = index.smallestAt(offset, CALL_TYPES, (node) => pattern.test(calleeText(node, content)));
    if (!located) return null;
    switch (executionPath(located.ancestors, index)) {
      case 'handler':
        return { confidence: 'LOW', reason: 'Called from a user-interaction handler' };
      case 'load':
        return { confidence: 'HIGH', reason: 'Runs at module load, outside any user-interaction handler' };
      case 'timer':
        return { confidence: 'HIGH', reason: 'Runs from a timer callback, not a user interaction' };
      case 'mount':
        return finding.confidence === 'LOW'
          ? { confidence: 'MEDIUM', reason: 'Runs from a mount effect; confirm it waits for a user action' }
          : null;
      default:
        return null;
    }
  };
}

const confirmMessageHandler: Confirmer = ({ offset, index }) => {
  const located = index.smallestAt(
    offset,
    new Set(['CallExpression', 'AssignmentExpression']),
    (node) =>
      (node.type === 'CallExpression' && isListenerRegistration(node) && stringValue(node.arguments[0]) === 'message') ||
      (node.type === 'AssignmentExpression' && memberProperty(node.left) === 'onmessage')
  );
  if (!located) return null;
  const handler: AnyNode | undefined =
    located.node.type === 'CallExpression' ? located.node.arguments[1] : located.node.right;
  if (!handler || !FUNCTION_TYPES.has(handler.type)) return null;

  const param = handler.params[0];
  if (param && param.type === 'ObjectPattern') {
    const keys = param.properties.map((p: AnyNode) => (p.type === 'Property' ? propertyName(p.key) : null));
    if (keys.includes('origin')) return { confidence: 'LOW', reason: 'Handler destructures event.origin' };
    if (param.properties.some((p: AnyNode) => p.type === 'RestElement')) return null;
    return { confidence: 'HIGH', reason: 'Handler destructures the event without origin and never reads it' };
  }
  const paramName = param && param.type === 'Identifier' ? param.name : null;

  // `location.origin` is the page's own origin, not the sender's.
  const isLocationLike = (object: AnyNode): boolean =>
    (object.type === 'Identifier' && object.name === 'location') || memberProperty(object) === 'location';

  let readsOrigin = false;
  let delegatesEvent = false;
  walk.fullAncestor(handler.body as any, (node: any, _s: unknown, ancestors: any[]) => {
    if (node.type === 'MemberExpression' && memberProperty(node) === 'origin') {
      const onEvent = paramName ? node.object.type === 'Identifier' && node.object.name === paramName : true;
      if (onEvent || (!isLocationLike(node.object) && !paramName)) readsOrigin = true;
      else if (!isLocationLike(node.object) && node.object.type !== 'Identifier') readsOrigin = true;
    }
    if (paramName && node.type === 'Identifier' && node.name === paramName) {
      const parent = ancestors[ancestors.length - 2];
      const readsSafeProperty = parent && parent.type === 'MemberExpression' && parent.object === node;
      if (!readsSafeProperty) delegatesEvent = true;
    }
  });
  if (readsOrigin) return { confidence: 'LOW', reason: 'Handler reads event.origin; confirm it is compared to an allowlist' };
  if (delegatesEvent) return null;
  return { confidence: 'HIGH', reason: 'Handler never reads event.origin and never hands the event to another function' };
};

function isRequestCall(call: AnyNode): boolean {
  const callee = call.callee;
  const name = callee.type === 'Identifier' ? callee.name : memberProperty(callee);
  if (name === null) return false;
  if (LOCATION_NAVIGATION.has(name)) {
    // location.assign(url) / location.replace(url) navigate; "a".replace() does not.
    return callee.type === 'MemberExpression' && isLocationObject(callee.object);
  }
  if (name === 'open' && callee.type === 'MemberExpression' && !isWindowLike(callee.object) && memberProperty(callee.object) === null) {
    // xhr.open('GET', url) — keep; anything.open(...) on an unknown object — keep too (XHR instances are unnamed in bundles).
    return true;
  }
  return REQUEST_CALLEES.has(name);
}

function isLocationObject(object: AnyNode): boolean {
  return (object.type === 'Identifier' && object.name === 'location') || memberProperty(object) === 'location';
}

function isWindowLike(object: AnyNode): boolean {
  return object.type === 'Identifier' && (object.name === 'window' || object.name === 'globalThis' || object.name === 'self');
}

function isUrlParseOnly(call: AnyNode): boolean {
  const callee = call.callee;
  return callee.type === 'Identifier' && (callee.name === 'URL' || callee.name === 'Request');
}

function usesIdentifierAsUrl(call: AnyNode, name: string): boolean {
  const first = call.arguments[0];
  if (!first) return false;
  if (first.type === 'Identifier') return first.name === name;
  if (first.type === 'TemplateLiteral') {
    return first.quasis[0]?.value?.cooked === '' && first.expressions[0]?.type === 'Identifier' && first.expressions[0].name === name;
  }
  if (first.type === 'BinaryExpression' && first.operator === '+') {
    let left = first;
    while (left.type === 'BinaryExpression') left = left.left;
    return left.type === 'Identifier' && left.name === name;
  }
  return false;
}

const confirmHttpLiteral: Confirmer = ({ offset, index }) => {
  const located = index.smallestAt(offset, new Set(['Literal', 'TemplateLiteral']));
  if (!located) return null;
  const { node, ancestors } = located;
  const parent = ancestors[ancestors.length - 1];
  if (!parent) return null;
  const isRegExpConstruction =
    (parent.type === 'NewExpression' || parent.type === 'CallExpression') &&
    parent.callee.type === 'Identifier' &&
    parent.callee.name === 'RegExp';
  if ((node.type === 'Literal' && node.regex) || isRegExpConstruction) {
    return { confidence: 'LOW', reason: 'Inside a regular expression, not a request' };
  }

  if ((parent.type === 'CallExpression' || parent.type === 'NewExpression') && parent.arguments.includes(node)) {
    if (isUrlParseOnly(parent)) return { confidence: 'LOW', reason: 'Parsed or validated, not requested' };
    if (isRequestCall(parent)) return { confidence: 'HIGH', reason: 'Plaintext URL passed to a request' };
  }
  if (parent.type === 'AssignmentExpression' && parent.right === node && URL_SINK_PROPERTIES.has(memberProperty(parent.left) ?? '')) {
    return { confidence: 'HIGH', reason: 'Plaintext URL assigned to a resource location' };
  }
  if (parent.type === 'Property' && parent.value === node && URL_SINK_PROPERTIES.has(propertyName(parent.key) ?? '')) {
    return { confidence: 'HIGH', reason: 'Plaintext URL configured as a request target' };
  }
  if (parent.type === 'VariableDeclarator' && parent.init === node && parent.id.type === 'Identifier') {
    const name = parent.id.name;
    const scope = enclosingScope(ancestors);
    const used = index.nodes.some(
      ({ node: candidate, ancestors: chain }) =>
        (candidate.type === 'CallExpression' || candidate.type === 'NewExpression') &&
        isRequestCall(candidate) &&
        usesIdentifierAsUrl(candidate, name) &&
        chain.includes(scope)
    );
    if (used) return { confidence: 'HIGH', reason: `Plaintext URL bound to \`${name}\` and passed to a request` };
  }
  return null;
};

function isStaticMarkup(node: AnyNode | undefined): boolean {
  if (!node) return false;
  if (node.type === 'Literal') return typeof node.value === 'string';
  if (node.type === 'TemplateLiteral') return node.expressions.length === 0;
  if (node.type === 'BinaryExpression' && node.operator === '+') return isStaticMarkup(node.left) && isStaticMarkup(node.right);
  return false;
}

function staticMarkupText(node: AnyNode): string {
  if (node.type === 'Literal') return String(node.value);
  if (node.type === 'TemplateLiteral') return node.quasis[0]?.value?.cooked ?? '';
  return staticMarkupText(node.left) + staticMarkupText(node.right);
}

function confirmRawHtml(kind: 'assignment' | 'doc-write' | 'insert-adjacent'): Confirmer {
  return ({ offset, index }) => {
    let value: AnyNode | undefined;
    if (kind === 'assignment') {
      const located = index.smallestAt(offset, new Set(['AssignmentExpression']), (node) => {
        const prop = memberProperty(node.left);
        return prop === 'innerHTML' || prop === 'outerHTML';
      });
      value = located?.node.right;
    } else {
      const located = index.smallestAt(offset, new Set(['CallExpression']), (node) => {
        const prop = memberProperty(node.callee);
        return kind === 'doc-write' ? prop === 'write' || prop === 'writeln' : prop === 'insertAdjacentHTML';
      });
      value = located?.node.arguments[kind === 'doc-write' ? 0 : 1];
    }
    if (!value || !isStaticMarkup(value)) return null;
    if (/<script\b/i.test(staticMarkupText(value))) return null;
    return { confidence: 'LOW', reason: 'Static markup literal, no untrusted data' };
  };
}

/**
 * A localhost literal that only ever serves as a fallback (`options.url ??
 * "http://localhost:9999"`, gotrue-js style) is a library default, not a dev
 * endpoint. One that reaches a request or a client config is the real thing.
 */
const confirmLocalhost: Confirmer = ({ finding, offset, index }) => {
  if (finding.severity === 'LOW') return null; // the bare-literal override already settled it
  const located = index.smallestAt(offset, new Set(['Literal', 'TemplateLiteral']));
  if (!located) return null;
  const { node, ancestors } = located;
  const parent = ancestors[ancestors.length - 1];
  if (!parent) return null;
  const isFallbackPosition = (p: AnyNode, child: AnyNode) =>
    (p.type === 'LogicalExpression' && (p.operator === '??' || p.operator === '||') && p.right === child) ||
    (p.type === 'ConditionalExpression' && p.alternate === child) ||
    (p.type === 'AssignmentPattern' && p.right === child);
  if (isFallbackPosition(parent, node)) return { confidence: 'LOW', reason: 'Fallback value, not a configured endpoint' };

  // A property of an object literal: configured (object handed to a client
  // factory) or a library default (constant later spread under user options,
  // gotrue-js style: `{...DEFAULTS, ...options}`).
  const classifyObjectProperty = (property: AnyNode, chain: AnyNode[]): Adjustment | null => {
    const object = chain[chain.length - 1];
    const owner = chain[chain.length - 2];
    if (!object || object.type !== 'ObjectExpression' || !owner) return null;
    if ((owner.type === 'CallExpression' || owner.type === 'NewExpression') && owner.arguments.includes(object)) {
      return { confidence: 'HIGH', reason: 'Configured endpoint passed to a client' };
    }
    if (owner.type === 'VariableDeclarator' && owner.init === object && owner.id.type === 'Identifier') {
      const constant = owner.id.name;
      const scope = enclosingScope(chain);
      const spread = index.nodes.some(
        ({ node: c, ancestors: ch }) => c.type === 'SpreadElement' && c.argument.type === 'Identifier' && c.argument.name === constant && ch.includes(scope)
      );
      if (spread) return { confidence: 'LOW', reason: `Default option in \`${constant}\`, spread under caller options` };
    }
    return null;
  };
  if (parent.type === 'Property' && parent.value === node) {
    return classifyObjectProperty(parent, ancestors.slice(0, -1));
  }

  if (parent.type === 'VariableDeclarator' && parent.init === node && parent.id.type === 'Identifier') {
    const name = parent.id.name;
    const scope = enclosingScope(ancestors);
    let fallbackUse = false;
    let requestUse = false;
    let propertyVerdict: Adjustment | null = null;
    for (const { node: candidate, ancestors: chain } of index.nodes) {
      if (!chain.includes(scope)) continue;
      if (candidate.type === 'Identifier' && candidate.name === name) {
        const p = chain[chain.length - 1];
        if (p && isFallbackPosition(p, candidate)) fallbackUse = true;
        if (p && p.type === 'Property' && p.value === candidate) {
          const verdict = classifyObjectProperty(p, chain.slice(0, -1));
          if (verdict?.confidence === 'HIGH') propertyVerdict = verdict;
          else if (verdict && !propertyVerdict) propertyVerdict = verdict;
        }
      }
      if ((candidate.type === 'CallExpression' || candidate.type === 'NewExpression') && isRequestCall(candidate) && usesIdentifierAsUrl(candidate, name)) requestUse = true;
    }
    if (requestUse) return { confidence: 'HIGH', reason: `Bound to \`${name}\` and passed to a request` };
    if (propertyVerdict?.confidence === 'HIGH') return propertyVerdict;
    if (fallbackUse) return { confidence: 'LOW', reason: `Bound to \`${name}\` and used only as a fallback` };
    if (propertyVerdict) return propertyVerdict;
  }
  return null;
};

/**
 * `createElement('script')` followed by `.src =` on one minified line is
 * React DOM 19's resource hoisting in almost every React bundle (the `.src =`
 * belongs to unrelated code further along the line). Runtime script
 * injection is the element that was created receiving a src.
 */
const confirmScriptSrc: Confirmer = ({ offset, index }) => {
  const located = index.smallestAt(
    offset,
    new Set(['CallExpression']),
    (node) => memberProperty(node.callee) === 'createElement' && (stringValue(node.arguments[0]) ?? '').toLowerCase() === 'script'
  );
  if (!located) return null;
  const { node, ancestors } = located;
  const parent = ancestors[ancestors.length - 1];
  let name: string | null = null;
  if (parent?.type === 'VariableDeclarator' && parent.init === node && parent.id.type === 'Identifier') name = parent.id.name;
  else if (parent?.type === 'AssignmentExpression' && parent.right === node && parent.left.type === 'Identifier') name = parent.left.name;
  if (!name) return null;
  const scope = enclosingScope(ancestors);
  const receivesSrc = index.nodes.some(({ node: candidate, ancestors: chain }) => {
    if (candidate.start < node.end || !chain.includes(scope)) return false;
    if (candidate.type === 'AssignmentExpression' && candidate.left.type === 'MemberExpression') {
      const target = candidate.left;
      return target.object.type === 'Identifier' && target.object.name === name && memberProperty(target) === 'src';
    }
    if (candidate.type === 'CallExpression' && candidate.callee.type === 'MemberExpression') {
      const callee = candidate.callee;
      return (
        callee.object.type === 'Identifier' &&
        callee.object.name === name &&
        memberProperty(callee) === 'setAttribute' &&
        stringValue(candidate.arguments[0]) === 'src'
      );
    }
    return false;
  });
  if (receivesSrc) return { confidence: 'HIGH', reason: `Script element \`${name}\` is given a src at runtime` };
  return { confidence: 'LOW', reason: `Script element \`${name}\` never receives a src in this scope (framework resource hoisting)` };
};

const DOM_HTML_SINKS = new Set(['innerHTML', 'outerHTML']);
const DOM_HTML_SINK_CALLS = new Set(['insertAdjacentHTML', 'write', 'writeln']);
const TRANSPARENT_WRAPPERS = new Set(['BinaryExpression', 'TemplateLiteral', 'ConditionalExpression', 'LogicalExpression']);

/**
 * A `<script src>` string is injection only when it reaches a DOM sink. Apps
 * also render such strings as copy-paste install snippets (Prism-highlighted
 * or as JSX text), which is display, not execution.
 */
const confirmScriptTagLiteral: Confirmer = ({ offset, index }) => {
  const located = index.smallestAt(offset, new Set(['Literal', 'TemplateLiteral']));
  if (!located) return null;
  let child: AnyNode = located.node;
  let depth = located.ancestors.length - 1;
  while (depth >= 0) {
    const parent = located.ancestors[depth];
    if (!parent) break;
    if (TRANSPARENT_WRAPPERS.has(parent.type)) {
      child = parent;
      depth -= 1;
      continue;
    }
    if (parent.type === 'AssignmentExpression' && parent.right === child && DOM_HTML_SINKS.has(memberProperty(parent.left) ?? '')) {
      return { confidence: 'HIGH', reason: 'Script markup assigned to innerHTML/outerHTML at runtime' };
    }
    if (parent.type === 'CallExpression' && parent.arguments.includes(child) && DOM_HTML_SINK_CALLS.has(memberProperty(parent.callee) ?? '')) {
      return { confidence: 'HIGH', reason: 'Script markup inserted into the document at runtime' };
    }
    return null;
  }
  return null;
};

const CONFIRMERS: Record<string, Confirmer> = {
  'script-src-assignment': confirmScriptSrc,
  'script-tag-literal': confirmScriptTagLiteral,
  'localhost-url': confirmLocalhost,
  'window-open': confirmInteraction(/^(?:window|globalThis|self)?\.?open$|\bopen$/),
  'designer-write-call': confirmInteraction(/\bwebflow\.(?:create|remove)\w+$/),
  'get-user-media': confirmInteraction(/mediaDevices\.(?:getUserMedia|getDisplayMedia|enumerateDevices)$/),
  'inline-window-message-handler': confirmMessageHandler,
  'http-usage': confirmHttpLiteral,
  'doc-write': confirmRawHtml('doc-write'),
  'inner-outer-html': confirmRawHtml('assignment'),
  'insert-adjacent': confirmRawHtml('insert-adjacent')
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function parseFile(content: string): AnyNode | null {
  const base = { ecmaVersion: 'latest' as const, allowHashBang: true, allowAwaitOutsideFunction: true, allowReturnOutsideFunction: true, allowImportExportEverywhere: true };
  try {
    return parse(content, { ...base, sourceType: 'module' }) as unknown as AnyNode;
  } catch {
    try {
      return parse(content, { ...base, sourceType: 'script' }) as unknown as AnyNode;
    } catch {
      return null;
    }
  }
}

/**
 * Mutates `findings` in place: confirmable findings in parseable files get a
 * HIGH or LOW confidence with a reason when the tree decides; everything
 * else is untouched. Returns the number of findings adjusted.
 */
export function applyAstConfirmation(
  inventory: FileEntry[],
  findings: Finding[],
  log: (message: string) => void = () => {}
): number {
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (!AST_CONFIRMABLE_MATCHERS.has(finding.matcherId)) continue;
    if (finding.locationType === 'COMMENT' || finding.locationType === 'DOC') continue;
    const list = byFile.get(finding.filePath) ?? [];
    list.push(finding);
    byFile.set(finding.filePath, list);
  }
  if (byFile.size === 0) return 0;

  let adjusted = 0;
  for (const file of inventory) {
    const pending = byFile.get(file.path);
    if (!pending || !file.content || !PARSEABLE_EXTENSIONS.has(file.ext) || file.sizeBytes > PARSE_SIZE_LIMIT) continue;
    const ast = parseFile(file.content);
    if (!ast) {
      log(`ast-confirm: could not parse ${file.path}; regex results stand`);
      continue;
    }
    const index = new FileIndex(ast, file.content);
    for (const finding of pending) {
      const offset = index.offsetOf(finding.line, finding.col);
      if (offset < 0) continue;
      const confirmer = CONFIRMERS[finding.matcherId];
      if (!confirmer) continue;
      let adjustment: Adjustment | null = null;
      try {
        adjustment = confirmer({ finding, offset, ast, content: file.content, index });
      } catch (error) {
        log(`ast-confirm: ${finding.matcherId} in ${file.path} failed: ${String(error)}`);
      }
      if (!adjustment) continue;
      // The reason is worth keeping even when the level does not move: the
      // reviewer sees why the tree agreed with the regex.
      finding.confidenceReason = adjustment.reason;
      if (adjustment.confidence !== finding.confidence) {
        finding.confidence = adjustment.confidence;
        adjusted += 1;
      }
    }
  }
  return adjusted;
}
