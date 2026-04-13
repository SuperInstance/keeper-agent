/**
 * Secret Scanner — The "double-checker" that ensures no secrets leave the SuperInstance.
 *
 * This is the core security innovation: every request and response that passes through
 * the keeper-agent is scanned for potential secret leakage. If any secrets are detected,
 * the request is blocked before it reaches the external API.
 *
 * Detection methods:
 *   1. Pattern matching: Known secret formats (API keys, PATs, tokens)
 *   2. Entropy analysis: High-entropy strings that look like secrets
 *   3. Vault comparison: Check if any string matches a vault secret
 *   4. Header inspection: Check for accidentally forwarded auth headers
 */

export interface ScanResult {
  safe: boolean;
  findings: SecretFinding[];
  sanitized: string | null;
}

export interface SecretFinding {
  type: 'api-key' | 'github-pat' | 'bearer-token' | 'high-entropy' | 'vault-match' | 'auth-header';
  location: string;
  preview: string;
  confidence: 'high' | 'medium' | 'low';
  description: string;
}

/**
 * Known secret patterns. Each pattern has:
 *   - name: human-readable identifier
 *   - pattern: regex to match
 *   - confidence: how certain we are it's a real secret
 */
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; confidence: 'high' | 'medium' }> = [
  {
    name: 'github-pat',
    pattern: /ghp_[a-zA-Z0-9]{30,}/g,
    confidence: 'high',
  },
  {
    name: 'github-oauth',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    confidence: 'high',
  },
  {
    name: 'github-app-token',
    pattern: /ghs_[a-zA-Z0-9]{36}/g,
    confidence: 'high',
  },
  {
    name: 'openai-api-key',
    pattern: /sk-[a-zA-Z0-9]{20,}([a-zA-Z0-9]{4})?/g,
    confidence: 'high',
  },
  {
    name: 'openai-proj-key',
    pattern: /sk-proj-[a-zA-Z0-9]{20,}([a-zA-Z0-9]{4})?/g,
    confidence: 'high',
  },
  {
    name: 'anthropic-key',
    pattern: /sk-ant-api03-[a-zA-Z0-9\-_]{90,}/g,
    confidence: 'high',
  },
  {
    name: 'aws-access-key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    confidence: 'high',
  },
  {
    name: 'aws-secret-key',
    pattern: /[aA][wW][sS]_[sS]ecret_[aA]ccess_[kK]ey\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/g,
    confidence: 'high',
  },
  {
    name: 'slack-token',
    // Pattern: xox[bpras]- followed by 10+ alphanumeric chars
    pattern: new RegExp('xox[bpras]-[a-zA-Z0-9\\\\-]{10,}', 'g'),
    confidence: 'high',
  },
  {
    name: 'stripe-key',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    confidence: 'high',
  },
  {
    name: 'private-key-pem',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    confidence: 'high',
  },
  {
    name: 'generic-bearer',
    pattern: /Bearer [a-zA-Z0-9\-._~+/]+=*/gi,
    confidence: 'medium',
  },
  {
    name: 'generic-api-key-header',
    pattern: /(?:api[_-]?key|apikey|authorization)\s*[=:]\s*['"][a-zA-Z0-9\-_]{20,}['"]/gi,
    confidence: 'medium',
  },
];

export class SecretScanner {
  private vaultSecrets: Map<string, string> = new Map();
  private enabledPatterns: Set<string>;

  constructor(options?: { disabledPatterns?: string[] }) {
    this.enabledPatterns = new Set(
      SECRET_PATTERNS
        .filter(p => !options?.disabledPatterns?.includes(p.name))
        .map(p => p.name)
    );
  }

  /**
   * Register vault secrets for comparison scanning.
   * The scanner checks if any payload text matches these values.
   */
  setVaultSecrets(secrets: Map<string, string>): void {
    this.vaultSecrets = secrets;
  }

  /**
   * Scan a string for potential secret leakage.
   * Returns findings and a sanitized version.
   */
  scan(input: string, context: string = 'unknown'): ScanResult {
    const findings: SecretFinding[] = [];
    let sanitized = input;

    // 1. Pattern matching
    for (const { name, pattern, confidence } of SECRET_PATTERNS) {
      if (!this.enabledPatterns.has(name)) continue;
      const matches = input.matchAll(pattern);
      for (const match of matches) {
        const found = match[0];
        findings.push({
          type: this.classifyFinding(name),
          location: context,
          preview: this.maskValue(found),
          confidence,
          description: `Detected ${name} pattern: ${this.maskValue(found)}`,
        });
        // Sanitize: replace the secret with a placeholder
        sanitized = sanitized.replace(found, `[REDACTED:${name}]`);
      }
    }

    // 2. Vault comparison — check if any vault secret appears in the input
    for (const [provider, secretValue] of this.vaultSecrets) {
      if (secretValue && input.includes(secretValue)) {
        findings.push({
          type: 'vault-match',
          location: context,
          preview: this.maskValue(secretValue),
          confidence: 'high',
          description: `Input contains a vault secret for provider: ${provider}`,
        });
        sanitized = sanitized.replace(secretValue, `[REDACTED:vault:${provider}]`);
      }
    }

    // 3. High-entropy detection (simplified)
    const highEntropyStrings = this.detectHighEntropy(input);
    for (const { value, score } of highEntropyStrings) {
      findings.push({
        type: 'high-entropy',
        location: context,
        preview: this.maskValue(value),
        confidence: score > 4.5 ? 'high' : 'low',
        description: `High-entropy string detected (score: ${score.toFixed(2)}): ${this.maskValue(value)}`,
      });
    }

    // 4. Auth header inspection for outbound requests
    if (context.includes('request') || context.includes('header')) {
      const authFindings = this.checkAuthHeaders(input);
      findings.push(...authFindings);
    }

    return {
      safe: findings.filter(f => f.confidence === 'high').length === 0,
      findings,
      sanitized: findings.length > 0 ? sanitized : null,
    };
  }

  /**
   * Scan an object (converted to JSON string first).
   */
  scanObject(obj: unknown, context: string = 'unknown'): ScanResult {
    return this.scan(JSON.stringify(obj), context);
  }

  /**
   * Scan HTTP headers specifically for auth leakage.
   */
  scanHeaders(headers: Record<string, string>): ScanResult {
    const findings: SecretFinding[] = [];

    // Check for sensitive headers that shouldn't be forwarded
    const sensitiveHeaders = [
      'authorization', 'x-api-key', 'x-auth-token',
      'cookie', 'set-cookie', 'proxy-authorization',
    ];

    for (const [key, value] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();
      if (sensitiveHeaders.includes(lowerKey)) {
        findings.push({
          type: 'auth-header',
          location: `header:${key}`,
          preview: this.maskValue(value),
          confidence: 'high',
          description: `Sensitive auth header detected in outbound request: ${key}`,
        });
      }

      // Also scan header values for secret patterns
      const valueScan = this.scan(value, `header:${key}`);
      findings.push(...valueScan.findings);
    }

    return {
      safe: findings.filter(f => f.confidence === 'high').length === 0,
      findings,
      sanitized: null,
    };
  }

  /**
   * Simple Shannon entropy calculation for high-entropy detection.
   */
  private shannonEntropy(str: string): number {
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    const len = str.length;
    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / len;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }

  /**
   * Detect high-entropy strings in input.
   * These are strings that look like randomly generated secrets.
   */
  private detectHighEntropy(input: string): Array<{ value: string; score: number }> {
    const results: Array<{ value: string; score: number }> = [];

    // Look for long alphanumeric strings (potential secrets)
    const pattern = /[a-zA-Z0-9\-_+/=]{32,}/g;
    const matches = input.matchAll(pattern);
    for (const match of matches) {
      const value = match[0];
      const score = this.shannonEntropy(value);

      // Threshold: most English text is 3-4 bits, secrets are 4.5+
      if (score > 4.2 && value.length >= 32) {
        // Skip if already matched by a known pattern
        const alreadyMatched = SECRET_PATTERNS.some(p => p.pattern.test(value));
        if (!alreadyMatched) {
          results.push({ value, score });
        }
      }
    }

    return results;
  }

  /**
   * Check HTTP headers for auth-related patterns.
   */
  private checkAuthHeaders(input: string): SecretFinding[] {
    const findings: SecretFinding[] = [];

    // Look for Authorization headers being set
    const authHeaderPattern = /['"](?:authorization|auth)['"]\s*[:=]\s*['"]([^'"]+)['"]/gi;
    const matches = input.matchAll(authHeaderPattern);
    for (const match of matches) {
      findings.push({
        type: 'auth-header',
        location: 'body',
        preview: this.maskValue(match[1]),
        confidence: 'medium',
        description: 'Potential auth header injection in request body',
      });
    }

    return findings;
  }

  /**
   * Mask a value for safe display.
   */
  private maskValue(value: string): string {
    if (value.length <= 8) return '***';
    return `${value.slice(0, 6)}...${value.slice(-3)}`;
  }

  /**
   * Classify a finding type from a pattern name.
   */
  private classifyFinding(patternName: string): SecretFinding['type'] {
    if (patternName.includes('github') || patternName.includes('pat')) return 'github-pat';
    if (patternName.includes('bearer')) return 'bearer-token';
    if (patternName.includes('key') || patternName.includes('token')) return 'api-key';
    if (patternName.includes('pem') || patternName.includes('private')) return 'api-key';
    return 'api-key';
  }
}
