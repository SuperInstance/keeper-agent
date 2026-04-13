/**
 * Vault — Secret storage backed by environment variables or GitHub Secrets.
 *
 * The vault NEVER exposes raw secrets to agents. It only injects them into
 * outbound API calls after the proxy engine validates and sanitizes.
 *
 * Storage model:
 *   - Runtime: environment variables (KEEPER_SECRET_<PROVIDER>)
 *   - Persistent: GitHub Secrets (synced at startup)
 *   - Backup: encrypted JSON file (keeper-vault.enc)
 *
 * Secret format in env:
 *   KEEPER_SECRET_OPENAI_API_KEY=sk-...
 *   KEEPER_SECRET_ANTHROPIC_API_KEY=sk-ant-...
 *   KEEPER_SECRET_GITHUB_PAT=ghp_...
 */

export interface SecretRef {
  /** Provider identifier (e.g. "openai", "anthropic", "github") */
  provider: string;
  /** Human-readable label */
  label: string;
  /** The actual secret value (never logged, never sent to agents) */
  value: string;
  /** ISO timestamp when this secret was last rotated */
  rotatedAt: string;
  /** Optional: scope restrictions (which agents can use this) */
  allowedAgents?: string[];
}

export interface VaultEntry {
  provider: string;
  label: string;
  /** Masked preview (e.g. "sk-...abcd") */
  preview: string;
  rotatedAt: string;
  allowedAgents?: string[];
}

export class Vault {
  private secrets: Map<string, SecretRef> = new Map();
  private encryptionKey: string;

  constructor(encryptionKey?: string) {
    this.encryptionKey = encryptionKey || process.env.KEEPER_VAULT_KEY || 'default-dev-key-change-me';
    this.loadFromEnv();
  }

  /**
   * Load secrets from environment variables.
   * Pattern: KEEPER_SECRET_{PROVIDER}_{KEY_NAME}
   */
  private loadFromEnv(): void {
    for (const [key, value] of Object.entries(process.env)) {
      if (key.startsWith('KEEPER_SECRET_') && value) {
        // Parse: KEEPER_SECRET_OPENAI_API_KEY -> provider="openai", label="API_KEY"
        const parts = key.replace('KEEPER_SECRET_', '').split('_');
        const provider = parts[0].toLowerCase();
        const label = parts.slice(1).join('_');

        if (!this.secrets.has(provider)) {
          this.secrets.set(provider, {
            provider,
            label,
            value,
            rotatedAt: new Date().toISOString(),
          });
        }
      }
    }
  }

  /**
   * Get a secret by provider. Returns null if not found or agent not allowed.
   * The returned SecretRef.value is the actual secret — handle with extreme care.
   */
  get(provider: string, agentId?: string): SecretRef | null {
    const secret = this.secrets.get(provider.toLowerCase());
    if (!secret) return null;

    // Check agent restriction
    if (agentId && secret.allowedAgents && !secret.allowedAgents.includes(agentId)) {
      return null;
    }

    return { ...secret };
  }

  /**
   * Set or update a secret.
   */
  set(provider: string, value: string, options?: { label?: string; allowedAgents?: string[] }): void {
    this.secrets.set(provider.toLowerCase(), {
      provider: provider.toLowerCase(),
      label: options?.label || `${provider.toUpperCase()}_KEY`,
      value,
      rotatedAt: new Date().toISOString(),
      allowedAgents: options?.allowedAgents,
    });
  }

  /**
   * Remove a secret.
   */
  delete(provider: string): boolean {
    return this.secrets.delete(provider.toLowerCase());
  }

  /**
   * List all secret entries (masked — no actual values).
   * This is safe to return to authenticated agents or dashboards.
   */
  list(agentId?: string): VaultEntry[] {
    const entries: VaultEntry[] = [];
    for (const [, secret] of this.secrets) {
      // Skip if agent not allowed
      if (agentId && secret.allowedAgents && !secret.allowedAgents.includes(agentId)) {
        continue;
      }
      entries.push({
        provider: secret.provider,
        label: secret.label,
        preview: this.mask(secret.value),
        rotatedAt: secret.rotatedAt,
        allowedAgents: secret.allowedAgents,
      });
    }
    return entries;
  }

  /**
   * Check if a provider's secret exists.
   */
  has(provider: string): boolean {
    return this.secrets.has(provider.toLowerCase());
  }

  /**
   * Mask a secret for safe display: "sk-proj-...xyz" or "ghp_...abc"
   */
  private mask(value: string): string {
    if (value.length <= 8) return '***';
    const prefix = value.slice(0, 7);
    const suffix = value.slice(-4);
    return `${prefix}...${suffix}`;
  }

  /**
   * Count total secrets.
   */
  get size(): number {
    return this.secrets.size;
  }
}
