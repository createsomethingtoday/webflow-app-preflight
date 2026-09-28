import type { Ruleset } from '../types';

/**
 * Default Webflow Marketplace Ruleset
 *
 * This ruleset covers security, network, privacy, and UX concerns
 * for Webflow App bundles submitted to the Marketplace.
 *
 * Version: 1.3.0-checklist-complete
 */
export const defaultRuleset: Ruleset = {
  schemaVersion: 'wf-marketplace-scanner-ruleset@1.0.0',
  rulesetVersion: '1.4.0-guidelines-2026-09-28',
  generatedAt: '2026-01-16T14:00:00Z',
  rules: [
    // ========================================================================
    // SECURITY RULES
    // ========================================================================

    {
      ruleId: 'SEC-NO-DCE',
      name: 'Dynamic Code Execution',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'BLOCKER',
      disposition: 'REJECTED',
      description: 'Disallow runtime compilation/execution of JavaScript (eval, new Function, string timers).',
      matchers: [
        {
          id: 'eval-call',
          type: 'regex',
          pattern: '\\beval\\s*\\(',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['eval('],
          confidence: 'HIGH'
        },
        {
          id: 'new-function',
          type: 'regex',
          pattern: '\\bnew\\s+Function\\s*\\(',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['new Function'],
          confidence: 'HIGH'
        },
        {
          id: 'string-timer',
          type: 'regex',
          pattern: '(setTimeout|setInterval)\\s*\\(\\s*[\'"`]',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['setTimeout', 'setInterval'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'SEC-NO-HOST-DOM',
      name: 'Unauthorized Host DOM Access',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'BLOCKER',
      disposition: 'REJECTED',
      description: 'Do not access parent/top document or host UI (sandbox escape).',
      matchers: [
        {
          id: 'parent-doc-access',
          type: 'regex',
          pattern: '(parent|top|window\\.parent|window\\.top)\\.document',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['parent.document', 'top.document'],
          confidence: 'HIGH'
        },
        {
          id: 'frame-owner',
          type: 'regex',
          pattern: 'frameElement\\.(ownerDocument|contentWindow)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['frameElement'],
          confidence: 'HIGH'
        }
      ]
    },

    {
      ruleId: 'SEC-NO-CLIENT-SECRETS',
      name: 'Hardcoded API Secrets',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'BLOCKER',
      disposition: 'REJECTED',
      description: 'Zero tolerance for hardcoded keys (Stripe, AWS, Slack, GitHub, PEM keys).',
      matchers: [
        {
          id: 'aws-keys',
          type: 'regex',
          pattern: '\\bAKIA[0-9A-Z]{16}\\b',
          flags: 'g',
          fileGlobs: ['**/*'],
          triggerTokens: ['AKIA'],
          confidence: 'HIGH'
        },
        {
          id: 'stripe-slack-keys',
          type: 'regex',
          pattern: '\\b(sk_live_[0-9a-zA-Z]+|xox[baprs]-[0-9A-Za-z\\-]{10,})\\b',
          flags: 'g',
          fileGlobs: ['**/*'],
          triggerTokens: ['sk_live', 'xox'],
          confidence: 'HIGH'
        },
        {
          id: 'github-tokens',
          type: 'regex',
          pattern: '\\b(ghp|gho|ghs)_[A-Za-z0-9]{36}\\b',
          flags: 'g',
          fileGlobs: ['**/*'],
          triggerTokens: ['ghp_', 'gho_', 'ghs_'],
          confidence: 'HIGH'
        },
        {
          id: 'pem-private-key',
          type: 'regex',
          pattern: '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
          flags: 'g',
          fileGlobs: ['**/*'],
          triggerTokens: ['-----BEGIN'],
          confidence: 'HIGH'
        },
        {
          id: 'google-api-key',
          type: 'regex',
          pattern: '\\bAIza[0-9A-Za-z\\-_]{35}\\b',
          flags: 'g',
          fileGlobs: ['**/*'],
          triggerTokens: ['AIza'],
          confidence: 'MEDIUM',
          notes: 'Verify if restricted.'
        },
        {
          id: 'generic-secret-assignment',
          type: 'regex',
          pattern: '(clientSecret|apiSecret|privateKey)\\s*[:=]\\s*[\'"`][A-Za-z0-9_\\-]{20,}[\'"`]',
          flags: 'gi',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['clientSecret', 'apiSecret'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'SEC-CODE-TRANSPARENCY',
      name: 'Obfuscated Source Code',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'BLOCKER',
      disposition: 'REJECTED',
      description: 'Code must be reviewable. Obfuscation (packers, anti-debug, flattening) is prohibited.',
      matchers: [
        {
          id: 'packer-sig',
          type: 'regex',
          pattern: 'eval\\(function\\(p,a,c,k,e,d\\)',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['eval(function(p,a,c,k,e,d)'],
          confidence: 'HIGH'
        },
        {
          id: 'hex-storm',
          type: 'regex',
          pattern: '(\\\\x[0-9a-fA-F]{2}){10,}',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['\\x'],
          confidence: 'HIGH'
        },
        {
          id: 'control-flow-flattening',
          type: 'regex',
          pattern: 'while\\s*\\(\\s*!!\\[\\]\\s*\\)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['while(!![])'],
          confidence: 'HIGH'
        },
        {
          id: 'string-array-rotation',
          type: 'regex',
          pattern: '\\(function\\(_0x[a-f0-9]+,_0x[a-f0-9]+\\)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['_0x'],
          confidence: 'MEDIUM'
        },
        {
          id: 'anti-debug',
          type: 'regex',
          pattern: '(debugger|setInterval\\s*\\(\\s*function\\s*\\(\\)\\s*\\{\\s*debugger)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['debugger'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'SEC-NO-SENSITIVE-TOKENS-IN-STORAGE',
      name: 'Insecure Token Storage',
      category: 'SECURITY',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'HIGH',
      disposition: 'ACTION_REQUIRED',
      description: 'Do not persist sensitive tokens (JWT, access_token) in localStorage.',
      matchers: [
        {
          id: 'storage-set-token',
          type: 'regex',
          pattern: '(localStorage|sessionStorage)\\.setItem\\s*\\(\\s*[\'"`]([^\'"`]*?(token|auth|key|secret)[^\'"`]*?)[\'"`]',
          flags: 'gi',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['setItem'],
          confidence: 'MEDIUM'
        },
        {
          id: 'jwt-literal',
          type: 'regex',
          pattern: '\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['eyJ'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'SEC-UNSAFE-HTML',
      name: 'Unsafe HTML Injection',
      category: 'SECURITY',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'HIGH',
      disposition: 'ACTION_REQUIRED',
      description: 'Avoid document.write, innerHTML, outerHTML interactions that bypass React/safe DOM methods.',
      matchers: [
        {
          id: 'doc-write',
          type: 'regex',
          pattern: 'document\\.write(ln)?\\s*\\(',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['document.write'],
          confidence: 'HIGH'
        },
        {
          id: 'inner-outer-html',
          type: 'regex',
          pattern: '\\.(innerHTML|outerHTML)\\s*=',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['.innerHTML', '.outerHTML'],
          confidence: 'MEDIUM'
        },
        {
          id: 'insert-adjacent',
          type: 'regex',
          pattern: '\\.insertAdjacentHTML\\s*\\(',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['insertAdjacentHTML'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'SEC-SCRIPT-INJECTION',
      name: 'Dynamic Script Injection',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'BLOCKER',
      disposition: 'REJECTED',
      description: 'Do not inject dynamic script tags with remote sources.',
      matchers: [
        {
          id: 'script-src-assignment',
          type: 'regex',
          pattern: 'createElement\\([\'"]script[\'"]\\).*?\\.src\\s*=',
          flags: 'gs',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['createElement'],
          confidence: 'MEDIUM'
        },
        {
          id: 'script-tag-literal',
          type: 'regex',
          pattern: '<script[^>]+src=[\'"]https?:\\/\\/',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,html,mjs,cjs}'],
          triggerTokens: ['<script'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'SEC-UNTRUSTED-REDIRECT',
      name: 'Forced/Untrusted Redirect',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'BLOCKER',
      disposition: 'REJECTED',
      description: 'Do not navigate the top frame or force redirects away from Designer.',
      matchers: [
        {
          id: 'top-nav-assignment',
          type: 'regex',
          pattern: '(top|parent|window\\.top|window\\.parent)\\.location\\s*=',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['top.location', 'parent.location'],
          confidence: 'HIGH'
        }
      ]
    },

    // ========================================================================
    // NETWORK RULES
    // ========================================================================

    {
      ruleId: 'NET-EXTERNAL-EGRESS',
      name: 'External API Calls',
      category: 'NETWORK',
      reviewBucket: 'INFO',
      severity: 'INFO',
      disposition: 'INFO',
      description:
        'Network calls found. Every endpoint must use HTTPS and point to production, and credential headers must never go to non-Webflow domains.',
      matchers: [
        {
          id: 'fetch-xhr',
          type: 'regex',
          pattern: '(\\bfetch\\s*\\(|new\\s+XMLHttpRequest)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['fetch', 'XMLHttpRequest'],
          confidence: 'LOW'
        }
      ]
    },

    {
      ruleId: 'NET-URL-HYGIENE',
      name: 'Insecure Protocols',
      category: 'NETWORK',
      reviewBucket: 'AUTO_REJECT',
      severity: 'HIGH',
      disposition: 'REJECTED',
      description: 'Disallow http://, ws://, javascript: protocols. Exception for W3C/Schema URIs.',
      matchers: [
        {
          id: 'http-usage',
          type: 'regex',
          pattern: '\\b(http:|ws:|javascript:)\\/\\/',
          flags: 'gi',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,html,css}'],
          triggerTokens: ['http:', 'ws:', 'javascript:'],
          confidence: 'MEDIUM',
          allowlistPatterns: [
            'http://www.w3.org',
            'http://schema.org',
            'http://localhost',
            'http://www.google.com'
          ]
        }
      ]
    },

    // ========================================================================
    // IFRAME RULES
    // ========================================================================

    {
      ruleId: 'IFRAME-EXTERNAL-SRC',
      name: 'Externally Hosted Iframe',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'HIGH',
      disposition: 'REJECTED',
      description: 'External iframes are allowed for Auth only. Remote UI loading is prohibited.',
      matchers: [
        {
          id: 'iframe-http-src',
          type: 'regex',
          pattern: '<iframe[^>]+src=[\'"](http|\\/\\/)',
          flags: 'i',
          fileGlobs: ['**/*.{html,js,ts,jsx,tsx}'],
          triggerTokens: ['<iframe'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'IFRAME-SANDBOX',
      name: 'Weak Iframe Sandbox',
      category: 'SECURITY',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'HIGH',
      disposition: 'ACTION_REQUIRED',
      description: 'Iframe sandboxes must not allow top-navigation or popup escapes.',
      matchers: [
        {
          id: 'allow-top-nav',
          type: 'regex',
          pattern: 'allow-top-navigation',
          flags: 'i',
          fileGlobs: ['**/*.{html,js,ts,jsx,tsx}'],
          triggerTokens: ['allow-top-navigation'],
          confidence: 'HIGH'
        }
      ]
    },

    {
      ruleId: 'IFRAME-MESSAGING',
      name: 'Insecure postMessage',
      category: 'SECURITY',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'MEDIUM',
      disposition: 'ACTION_REQUIRED',
      description: 'Wildcard targetOrigin (\'*\') is risky, especially for auth.',
      matchers: [
        {
          id: 'postmessage-wildcard',
          type: 'regex',
          pattern: '\\.postMessage\\s*\\(.*?[\'"`]\\*[\'"`]',
          flags: 'gs',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['postMessage'],
          confidence: 'MEDIUM',
          conditionalOverrides: [
            {
              pattern: '(token|auth|key|secret)',
              newSeverity: 'BLOCKER',
              newReviewBucket: 'AUTO_REJECT',
              newDisposition: 'REJECTED',
              note: 'Sending secrets via wildcard postMessage is a blocker.'
            }
          ]
        }
      ]
    },

    // ========================================================================
    // PRIVACY RULES
    // ========================================================================

    {
      ruleId: 'SEC-WEBRTC-HARDWARE',
      name: 'Hardware Access (Mic/Cam)',
      category: 'PRIVACY',
      reviewBucket: 'NEEDS_EXPLANATION',
      severity: 'LOW',
      disposition: 'INFO',
      description:
        'Camera, microphone, and screen capture may start only on direct user interaction, after clear disclosure UI. Confirm both.',
      matchers: [
        {
          id: 'get-user-media',
          type: 'regex',
          pattern: 'navigator\\.mediaDevices\\.(getUserMedia|getDisplayMedia|enumerateDevices)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['getUserMedia', 'getDisplayMedia', 'enumerateDevices'],
          confidence: 'HIGH'
        },
        {
          id: 'input-capture',
          type: 'regex',
          pattern: '<input[^>]+capture',
          flags: 'i',
          fileGlobs: ['**/*.{html,js,ts,jsx,tsx}'],
          triggerTokens: ['capture'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'PRIV-NO-FINGERPRINTING',
      name: 'Session Replay',
      category: 'PRIVACY',
      reviewBucket: 'NEEDS_EXPLANATION',
      severity: 'LOW',
      disposition: 'INFO',
      description:
        'Session replay found. Data collection must be disclosed clearly in the listing, and visitor data must never go beyond what the listing states.',
      matchers: [
        {
          id: 'replay-libs',
          type: 'regex',
          pattern: '\\b(rrweb|FullStory|LogRocket|Hotjar)\\b',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs,json}'],
          triggerTokens: ['rrweb', 'FullStory'],
          confidence: 'MEDIUM'
        }
      ]
    },

    // ========================================================================
    // UX RULES
    // ========================================================================

    {
      ruleId: 'UX-NO-SILENT-MUTATIONS',
      name: 'Silent Canvas Mutations',
      category: 'UX',
      reviewBucket: 'NEEDS_EXPLANATION',
      severity: 'LOW',
      disposition: 'INFO',
      description:
        'Every state-changing action must trace to a direct user interaction. Confirm this observer does not write to the site on its own.',
      matchers: [
        {
          id: 'mutation-observer',
          type: 'regex',
          pattern: 'new\\s+MutationObserver',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['MutationObserver'],
          confidence: 'LOW'
        }
      ]
    },

    {
      ruleId: 'UX-NO-POPUPS',
      name: 'Prohibited Popups',
      category: 'UX',
      reviewBucket: 'NEEDS_EXPLANATION',
      severity: 'LOW',
      disposition: 'INFO',
      description:
        'Popups and new windows are allowed only on direct user interaction, never on load or a timer. Confirm this opens from a click or other user action.',
      matchers: [
        {
          id: 'window-open',
          type: 'regex',
          pattern: 'window\\.open\\s*\\(',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['window.open'],
          confidence: 'MEDIUM',
          notes: 'Allowed only for user-initiated docs/auth with _blank.'
        }
      ]
    },

    // ========================================================================
    // PRODUCTION READINESS
    // ========================================================================

    {
      ruleId: 'PROD-NO-LOCALHOST',
      name: 'Non-Production Endpoints',
      category: 'PRODUCTION_READINESS',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'MEDIUM',
      disposition: 'ACTION_REQUIRED',
      description:
        'Every embedded URL must point to production. Remove localhost, loopback, private network, cloud metadata, and tunnel references.',
      matchers: [
        {
          id: 'localhost-url',
          type: 'regex',
          pattern: 'https?:\\/\\/(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|.*\\.ngrok\\.io|.*\\.localtunnel\\.me)',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs,json}'],
          triggerTokens: ['localhost', '127.0.0.1', 'ngrok'],
          confidence: 'HIGH'
        },
        {
          id: 'private-network-or-metadata',
          type: 'regex',
          pattern: 'https?:\\/\\/(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|169\\.254\\.\\d{1,3}\\.\\d{1,3}|\\[::1\\]|metadata\\.google\\.internal)',
          flags: 'gi',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs,json,html}'],
          triggerTokens: ['10.', '192.168.', '172.', '169.254.', '[::1]'],
          confidence: 'HIGH'
        }
      ]
    },

    {
      ruleId: 'SEC-NO-TOKEN-IN-URL',
      name: 'Credential in URL',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'BLOCKER',
      disposition: 'REJECTED',
      description:
        'Tokens and credentials must never travel in URL query strings — URLs land in server logs, browser history, and analytics. Send credentials in an Authorization header or request body (Marketplace Guidelines: token security / Webflow-authenticated endpoints).',
      matchers: [
        {
          id: 'token-query-param',
          type: 'regex',
          pattern: '[?&](access_token|id_token|auth_token|jwt|bearer|apikey|api_key)=',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['access_token', 'id_token', 'auth_token', 'jwt=', 'bearer=', 'apikey', 'api_key'],
          confidence: 'HIGH'
        },
        {
          id: 'generic-token-query-interpolation',
          type: 'regex',
          pattern: '[?&]token=(\\$\\{|["\'`]\\s*\\+)',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['token='],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'PROD-NO-DEBUG-RESIDUE',
      name: 'Debug and Bypass Residue',
      category: 'PRODUCTION_READINESS',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'HIGH',
      disposition: 'ACTION_REQUIRED',
      description:
        'Production bundles must not contain debug routes, onboarding or auth bypass flags, or other development shortcuts. Remove them and rebuild the exact production artifact before submitting (Marketplace submission artifacts).',
      matchers: [
        {
          id: 'debug-route-literal',
          type: 'regex',
          pattern: '["\'`][^"\'`]*\\/debug\\/[^"\'`]*["\'`]',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['/debug/'],
          confidence: 'HIGH'
        },
        {
          id: 'bypass-flag',
          type: 'regex',
          pattern: '\\b(bypass|skip)[_-]?(onboarding|auth|review|verification|validation)\\b',
          flags: 'i',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['bypass', 'skip'],
          confidence: 'MEDIUM'
        }
      ]
    },

    {
      ruleId: 'UX-NO-MUTATION-ON-LOAD',
      name: 'Site Mutation Without User Action',
      category: 'UX',
      reviewBucket: 'NEEDS_EXPLANATION',
      severity: 'LOW',
      disposition: 'INFO',
      description:
        'Creating or removing site resources (styles, variables, assets, components) must follow a deliberate user action — opening the extension must not mutate the site. If these calls only run after an explicit user choice, explain that in your review notes (Marketplace Guidelines: user interaction).',
      matchers: [
        {
          id: 'designer-write-call',
          type: 'regex',
          pattern: 'webflow\\.(create(Style|Variable|VariableCollection|Asset|Component|Page)|remove(Style|Variable|Asset|Component))\\s*\\(',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['webflow.create', 'webflow.remove'],
          confidence: 'MEDIUM'
        }
      ]
    },

    // ========================================================================
    // MARKETPLACE GUIDELINES ALIGNMENT (developers.webflow.com, read 2026-09-28)
    // ========================================================================

    {
      ruleId: 'PROD-STAGING-HOST',
      name: 'Possible Staging or Development Host',
      category: 'PRODUCTION_READINESS',
      reviewBucket: 'NEEDS_EXPLANATION',
      severity: 'LOW',
      disposition: 'INFO',
      description:
        'This URL looks like a staging or development host. Every embedded URL must point to production, so confirm it does or remove it.',
      matchers: [
        {
          id: 'staging-or-dev-host',
          type: 'regex',
          pattern: 'https?:\\/\\/([a-z0-9-]+\\.)*(staging|stage|stg|dev|qa|uat)[.-][a-z0-9.-]*[a-z0-9]',
          flags: 'gi',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs,json,html}'],
          triggerTokens: ['staging', 'stage', 'dev', 'qa', 'uat'],
          confidence: 'LOW'
        }
      ]
    },

    {
      ruleId: 'SEC-MESSAGE-ORIGIN',
      name: 'Unvalidated message Handler',
      category: 'SECURITY',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'HIGH',
      disposition: 'ACTION_REQUIRED',
      description:
        'Every message event handler in the extension UI must check event.origin against an explicit allowlist before processing the message.',
      matchers: [
        {
          id: 'message-listener-without-origin',
          type: 'regex',
          pattern: '(addEventListener\\s*\\(\\s*[\'"`]message[\'"`]|\\bonmessage\\s*=(?!=))',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs,html}'],
          triggerTokens: ['message', 'onmessage'],
          confidence: 'MEDIUM',
          // The allowlist is tested against the match plus three lines of
          // context, so a handler that reads .origin nearby is not flagged.
          allowlistPatterns: ['\\.origin\\b']
        }
      ]
    },

    {
      ruleId: 'SEC-NO-NATIVE-OVERRIDE',
      name: 'Native Function Override',
      category: 'SECURITY',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'HIGH',
      disposition: 'ACTION_REQUIRED',
      description:
        'Do not override, proxy, or reassign native browser functions, native prototypes, or Webflow globals.',
      matchers: [
        {
          id: 'prototype-assignment',
          type: 'regex',
          pattern: '\\b(Array|Object|String|Function|Promise|Element|HTMLElement|Node|EventTarget|Document|Window|XMLHttpRequest)\\.prototype\\.[A-Za-z_$][\\w$]*\\s*=(?!=)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['.prototype.'],
          confidence: 'MEDIUM'
        },
        {
          id: 'global-function-assignment',
          type: 'regex',
          pattern: '\\b(window|globalThis|self)\\.(fetch|XMLHttpRequest|open|postMessage|setTimeout|setInterval|addEventListener|webflow)\\s*=(?!=)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['window.', 'globalThis.'],
          confidence: 'HIGH'
        }
      ]
    },

    {
      ruleId: 'SEC-CSP-INLINE',
      name: 'CSP-Incompatible Markup',
      category: 'SECURITY',
      reviewBucket: 'AUTO_REJECT',
      severity: 'BLOCKER',
      disposition: 'REJECTED',
      description:
        'Inline event handler attributes and javascript: URIs are incompatible with the Designer Content Security Policy and will not pass review.',
      matchers: [
        {
          id: 'inline-event-handler',
          type: 'regex',
          pattern: '<[a-zA-Z][^>]*\\son[a-z]+\\s*=\\s*[\'"]',
          flags: 'g',
          fileGlobs: ['**/*.{html,htm}'],
          triggerTokens: ['on'],
          confidence: 'HIGH'
        },
        {
          id: 'javascript-uri',
          type: 'regex',
          pattern: '[\'"`]\\s*javascript:',
          flags: 'gi',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs,html,htm}'],
          triggerTokens: ['javascript:'],
          confidence: 'HIGH'
        }
      ]
    },

    {
      ruleId: 'SEC-RUNTIME-DECODING',
      name: 'Runtime Base64 Decoding',
      category: 'SECURITY',
      reviewBucket: 'NEEDS_EXPLANATION',
      severity: 'LOW',
      disposition: 'INFO',
      description:
        'Decoding code at runtime with atob or btoa counts as obfuscation. Confirm this decodes data, such as a token payload or image, and never code.',
      matchers: [
        {
          id: 'atob-btoa',
          type: 'regex',
          pattern: '\\b(atob|btoa)\\s*\\(',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['atob', 'btoa'],
          confidence: 'LOW'
        }
      ]
    },

    {
      ruleId: 'UX-NO-KEYBOARD-SHORTCUTS',
      name: 'Keyboard Shortcut',
      category: 'UX',
      reviewBucket: 'ACTION_REQUIRED',
      severity: 'HIGH',
      disposition: 'ACTION_REQUIRED',
      description:
        'Do not use keyboard shortcuts to invoke the app or any of its functionality.',
      matchers: [
        {
          id: 'modifier-plus-key',
          type: 'regex',
          pattern: '(\\b(metaKey|ctrlKey|altKey)\\s*&&\\s*[\\w$.]*\\.(key|code|keyCode)\\s*===?\\s*[\'"`\\d]|\\.(key|code)\\s*===?\\s*[\'"`][^\'"`]{1,12}[\'"`]\\s*&&\\s*[\\w$.]*\\.(metaKey|ctrlKey|altKey)\\b)',
          flags: 'g',
          fileGlobs: ['**/*.{js,ts,jsx,tsx,mjs,cjs}'],
          triggerTokens: ['metaKey', 'ctrlKey', 'altKey'],
          confidence: 'MEDIUM'
        }
      ]
    }
  ]
};

export default defaultRuleset;
