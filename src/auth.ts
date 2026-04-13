/**
 * Auth — Token issuance and validation for keeper-agent.
 *
 * Agents authenticate with the keeper and receive scoped JWT tokens.
 * These tokens authorize proxy requests but never contain real secrets.
 *
 * Token payload:
 *   {
 *     sub: "agent-id",
 *     name: "agent-display-name",
 *     scopes: ["openai:chat", "github:read", "github:write"],
 *     iat: <issued-at>,
 *     exp: <expiry>,
 *     iss: "keeper-agent"
 *   }
 *
 * Security model:
 *   - Tokens are signed with keeper's private key (RS256)
 *   - Tokens are scoped — can only access authorized APIs
 *   - Tokens expire (default 24h, max 30 days)
 *   - Tokens can be revoked instantly via the revoke list
 */

import * as jose from 'jose';

export interface AgentIdentity {
  id: string;
  name: string;
  githubUser?: string;
  createdAt: string;
}

export interface TokenPayload {
  sub: string;           // agent ID
  name: string;          // agent display name
  scopes: string[];      // e.g. ["openai:chat", "github:read"]
  iat: number;           // issued at
  exp: number;           // expiry
  iss: string;           // issuer
  jti: string;           // unique token ID (for revocation)
}

export interface TokenResponse {
  token: string;
  expiresAt: string;
  scopes: string[];
  agentId: string;
}

const TOKEN_ISSUER = 'keeper-agent';

// Scope format: "provider:permission"
// Examples: "openai:chat", "anthropic:chat", "github:read", "github:write"
export function parseScope(scope: string): { provider: string; permission: string } {
  const [provider, permission] = scope.split(':');
  return { provider, permission };
}

export class AuthManager {
  private privateKey: jose.KeyLike;
  private publicKey: jose.KeyLike;
  private revokedTokens: Set<string> = new Set();
  private registeredAgents: Map<string, AgentIdentity> = new Map();
  private ready: Promise<void>;

  constructor() {
    // Generate RSA key pair asynchronously
    this.privateKey = null as any;
    this.publicKey = null as any;
    this.ready = this.initKeys();
  }

  private async initKeys(): Promise<void> {
    const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Wait until keys are initialized. Call before any crypto operation.
   */
  async ensureReady(): Promise<void> {
    await this.ready;
  }

  /**
   * Register a new agent with the keeper.
   * This happens during the --onboard flow.
   */
  registerAgent(id: string, name: string, githubUser?: string): AgentIdentity {
    const agent: AgentIdentity = {
      id,
      name,
      githubUser,
      createdAt: new Date().toISOString(),
    };
    this.registeredAgents.set(id, agent);
    return agent;
  }

  /**
   * Get a registered agent by ID.
   */
  getAgent(id: string): AgentIdentity | undefined {
    return this.registeredAgents.get(id);
  }

  /**
   * List all registered agents.
   */
  listAgents(): AgentIdentity[] {
    return Array.from(this.registeredAgents.values());
  }

  /**
   * Issue a scoped JWT token to an agent.
   */
  async issueToken(
    agentId: string,
    scopes: string[],
    ttlHours: number = 24
  ): Promise<TokenResponse> {
    await this.ensureReady();
    // Verify agent exists
    const agent = this.registeredAgents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not registered: ${agentId}`);
    }

    // Cap TTL at 30 days
    const maxTtlHours = 30 * 24;
    const effectiveTtlHours = Math.min(ttlHours, maxTtlHours);

    const now = Math.floor(Date.now() / 1000);
    const jti = `${agentId}-${now}-${Math.random().toString(36).slice(2, 8)}`;

    const payload: TokenPayload = {
      sub: agentId,
      name: agent.name,
      scopes,
      iat: now,
      exp: now + (effectiveTtlHours * 3600),
      iss: TOKEN_ISSUER,
      jti,
    };

    const token = await new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime(`${effectiveTtlHours}h`)
      .setJti(jti)
      .sign(this.privateKey as jose.KeyLike);

    return {
      token,
      expiresAt: new Date((now + effectiveTtlHours * 3600) * 1000).toISOString(),
      scopes,
      agentId,
    };
  }

  /**
   * Validate a token and return its payload.
   * Returns null if token is invalid, expired, or revoked.
   */
  async validateToken(token: string): Promise<TokenPayload | null> {
    await this.ensureReady();
    try {
      const { payload } = await jose.jwtVerify(token, this.publicKey as jose.KeyLike);

      // Check individual token revocation
      const jti = payload.jti as string;
      if (this.revokedTokens.has(jti)) {
        return null;
      }

      // Check agent-level revocation
      const sub = payload.sub as string;
      if (this.revokedTokens.has(`agent:${sub}`)) {
        return null;
      }

      return payload as unknown as TokenPayload;
    } catch {
      return null;
    }
  }

  /**
   * Revoke a token by its JTI.
   */
  revokeToken(jti: string): boolean {
    return this.revokedTokens.add(jti).size > 0;
  }

  /**
   * Revoke ALL tokens for a specific agent.
   * Use this if an agent is compromised.
   */
  revokeAgentTokens(agentId: string): void {
    // Note: In production, you'd need to track JTIs per agent
    // For now, we add the agent ID as a revocation prefix
    this.revokedTokens.add(`agent:${agentId}`);
  }

  /**
   * Check if a token has been revoked.
   */
  isRevoked(jti: string): boolean {
    return this.revokedTokens.has(jti);
  }

  /**
   * Check if an agent's tokens have been revoked.
   */
  isAgentRevoked(agentId: string): boolean {
    return this.revokedTokens.has(`agent:${agentId}`);
  }

  /**
   * Check if a token's scope includes a specific provider permission.
   */
  hasScope(payload: TokenPayload, requiredScope: string): boolean {
    return payload.scopes.includes(requiredScope) ||
           payload.scopes.includes('*') ||  // wildcard scope
           payload.scopes.includes(`${parseScope(requiredScope).provider}:*`);  // provider wildcard
  }
}
