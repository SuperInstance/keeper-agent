/**
 * Proxy Engine — The core of the keeper-agent.
 *
 * Receives API requests from standalone agents, validates tokens,
 * scans for secret leakage, injects real credentials from the vault,
 * forwards to the actual API, and scans the response.
 *
 * Flow for every request:
 *   1. Extract and validate JWT token
 *   2. Check scope permissions
 *   3. Scan incoming request for leaked secrets
 *   4. If unsafe: BLOCK and log
 *   5. If safe: inject real API key from vault
 *   6. Forward to target API
 *   7. Scan response for leaked secrets
 *   8. If response unsafe: REDACT and log warning
 *   9. Return response to agent
 *   10. Audit log everything
 */

import { AuthManager, parseScope } from './auth.js';
import { Vault } from './vault.js';
import { SecretScanner } from './scanner.js';
import { AuditLog, AuditEventType } from './audit.js';

export interface ProxyRequest {
  provider: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: unknown;
}

export interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface ProxyResult {
  allowed: boolean;
  reason?: string;
  request?: ProxyResponse;
  scanFindings?: number;
  responseScanFindings?: number;
}

export class ProxyEngine {
  private auth: AuthManager;
  private vault: Vault;
  private scanner: SecretScanner;
  private audit: AuditLog;

  constructor(auth: AuthManager, vault: Vault, scanner: SecretScanner, audit: AuditLog) {
    this.auth = auth;
    this.vault = vault;
    this.scanner = scanner;
    this.audit = audit;

    // Sync vault secrets to scanner for comparison
    this.syncVaultToScanner();
  }

  /**
   * Process a proxied API request from an agent.
   */
  async proxy(token: string, request: ProxyRequest): Promise<ProxyResult> {
    // Step 1: Validate token
    const payload = await this.auth.validateToken(token);
    if (!payload) {
      this.audit.log('token.validated', { success: false, reason: 'invalid_token' }, { risk: 1 });
      return { allowed: false, reason: 'Invalid or expired token' };
    }

    // Step 2: Check agent not revoked
    if (this.auth.isAgentRevoked(payload.sub)) {
      this.audit.log('token.validated', { success: false, reason: 'agent_revoked' }, {
        agentId: payload.sub, risk: 2,
      });
      return { allowed: false, reason: 'Agent has been revoked' };
    }

    // Step 3: Check scope
    const requiredScope = `${request.provider}:*`;
    if (!this.auth.hasScope(payload, `${request.provider}:*`) &&
        !this.auth.hasScope(payload, `${request.provider}:${request.method.toLowerCase()}`)) {
      this.audit.log('proxy.request', {
        blocked: true,
        reason: 'insufficient_scope',
        requiredScope,
        agentScopes: payload.scopes,
      }, { agentId: payload.sub, provider: request.provider, risk: 1 });
      return { allowed: false, reason: `Insufficient scope. Need ${request.provider}:* or ${request.provider}:${request.method.toLowerCase()}` };
    }

    // Step 4: Scan incoming request for secret leakage
    const requestStr = JSON.stringify({ headers: request.headers, body: request.body });
    const scanResult = this.scanner.scan(requestStr, `request:${request.provider}:${request.path}`);

    if (!scanResult.safe) {
      this.audit.log('scan.blocked', {
        findings: scanResult.findings.length,
        provider: request.provider,
        path: request.path,
        findingTypes: scanResult.findings.map(f => f.type),
      }, { agentId: payload.sub, provider: request.provider, risk: 2 });

      return {
        allowed: false,
        reason: `Request blocked: potential secret leakage detected (${scanResult.findings.length} findings)`,
        scanFindings: scanResult.findings.length,
      };
    }

    // Step 5: Get real credentials from vault
    const secret = this.vault.get(request.provider, payload.sub);
    if (!secret) {
      this.audit.log('vault.access', {
        success: false,
        provider: request.provider,
      }, { agentId: payload.sub, provider: request.provider, risk: 1 });
      return { allowed: false, reason: `No vault secret for provider: ${request.provider}` };
    }

    this.audit.log('vault.access', {
      success: true,
      provider: request.provider,
    }, { agentId: payload.sub, provider: request.provider });

    // Step 6: Forward to target API
    const response = await this.forwardRequest(request, secret.value, request.provider);

    // Step 7: Scan response for leaked secrets
    const responseStr = JSON.stringify(response.body);
    const responseScan = this.scanner.scan(responseStr, `response:${request.provider}:${request.path}`);

    const responseFindings = responseScan.findings.length;
    if (responseFindings > 0) {
      this.audit.log('scan.passed', {
        warning: true,
        findings: responseScan.findings.length,
        provider: request.provider,
      }, { agentId: payload.sub, provider: request.provider, risk: 1 });

      // Redact if there are high-confidence findings in response
      if (responseScan.sanitized) {
        try {
          response.body = JSON.parse(responseScan.sanitized);
        } catch {
          // If parsing fails, keep original
        }
      }
    }

    // Step 8: Audit log the successful proxy
    this.audit.log('proxy.request', {
      provider: request.provider,
      path: request.path,
      method: request.method,
      status: response.status,
      requestScanFindings: 0,
      responseScanFindings: responseFindings,
    }, { agentId: payload.sub, provider: request.provider });

    return {
      allowed: true,
      request: response,
      scanFindings: 0,
      responseScanFindings: responseFindings,
    };
  }

  /**
   * Forward a request to the target API.
   * This is where the real API key gets injected.
   */
  private async forwardRequest(
    request: ProxyRequest,
    apiKey: string,
    provider: string
  ): Promise<ProxyResponse> {
    const baseUrl = this.getBaseUrl(provider);
    const url = `${baseUrl}${request.path}`;

    // Build headers with injected API key
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...this.stripAuthHeaders(request.headers), // Remove any auth from agent
    };

    // Inject real credentials based on provider
    switch (provider.toLowerCase()) {
      case 'openai':
        headers['Authorization'] = `Bearer ${apiKey}`;
        break;
      case 'anthropic':
        headers['x-api-key'] = apiKey;
        headers['anthropic-version'] = '2023-06-01';
        break;
      case 'github':
        headers['Authorization'] = `Bearer ${apiKey}`;
        headers['Accept'] = 'application/vnd.github.v3+json';
        break;
      default:
        headers['Authorization'] = `Bearer ${apiKey}`;
    }

    try {
      const fetchOptions: RequestInit = {
        method: request.method,
        headers,
      };

      if (request.body && request.method !== 'GET' && request.method !== 'HEAD') {
        fetchOptions.body = JSON.stringify(request.body);
      }

      const resp = await fetch(url, fetchOptions);
      const body = await resp.json().catch(() => ({}));

      return {
        status: resp.status,
        headers: Object.fromEntries(resp.headers.entries()),
        body,
      };
    } catch (error) {
      return {
        status: 502,
        headers: {},
        body: { error: `Proxy error: ${error instanceof Error ? error.message : 'Unknown'}` },
      };
    }
  }

  /**
   * Strip any authentication headers from the agent's request.
   * The keeper provides its own auth — we never forward the agent's.
   */
  private stripAuthHeaders(headers: Record<string, string>): Record<string, string> {
    const stripped: Record<string, string> = {};
    const authHeaders = [
      'authorization', 'x-api-key', 'x-auth-token',
      'cookie', 'proxy-authorization', 'www-authenticate',
    ];

    for (const [key, value] of Object.entries(headers)) {
      if (!authHeaders.includes(key.toLowerCase())) {
        stripped[key] = value;
      }
    }
    return stripped;
  }

  /**
   * Get the base URL for a provider.
   */
  private getBaseUrl(provider: string): string {
    const urls: Record<string, string> = {
      openai: 'https://api.openai.com/v1',
      anthropic: 'https://api.anthropic.com/v1',
      github: 'https://api.github.com',
    };

    // Check environment for custom URLs
    const envUrl = process.env[`KEEPER_PROXY_${provider.toUpperCase()}_URL`];
    return envUrl || urls[provider.toLowerCase()] || `https://api.${provider}.com`;
  }

  /**
   * Sync vault secrets to the scanner for comparison detection.
   */
  private syncVaultToScanner(): void {
    const secrets = new Map<string, string>();
    // The vault's list() only returns masked values, so we need a direct method
    // In production, the vault would expose this to the scanner only
    this.scanner.setVaultSecrets(secrets);
  }
}
