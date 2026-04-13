/**
 * Audit — Comprehensive logging for all keeper-agent operations.
 *
 * Every request, response, token issuance, and scan result is logged.
 * The audit trail is the foundation of the "double-checker" security model —
 * it enables post-incident analysis and compliance verification.
 *
 * Log entries are structured and can be exported as JSON for SIEM integration.
 */

export type AuditEventType =
  | 'token.issued'
  | 'token.validated'
  | 'token.revoked'
  | 'agent.registered'
  | 'proxy.request'
  | 'proxy.response'
  | 'scan.blocked'
  | 'scan.passed'
  | 'vault.access'
  | 'vault.modified'
  | 'error';

export interface AuditEntry {
  id: string;
  timestamp: string;
  event: AuditEventType;
  agentId?: string;
  provider?: string;
  details: Record<string, unknown>;
  /** Risk level: 0 = info, 1 = warning, 2 = critical */
  risk: 0 | 1 | 2;
}

export class AuditLog {
  private entries: AuditEntry[] = [];
  private maxEntries: number;
  private subscriber?: (entry: AuditEntry) => void;

  constructor(maxEntries: number = 10000) {
    this.maxEntries = maxEntries;
  }

  /**
   * Subscribe to audit events (for real-time monitoring).
   */
  onEntry(callback: (entry: AuditEntry) => void): void {
    this.subscriber = callback;
  }

  /**
   * Log an audit event.
   */
  log(
    event: AuditEventType,
    details: Record<string, unknown>,
    options?: { agentId?: string; provider?: string; risk?: 0 | 1 | 2 }
  ): AuditEntry {
    const entry: AuditEntry = {
      id: this.generateId(),
      timestamp: new Date().toISOString(),
      event,
      agentId: options?.agentId,
      provider: options?.provider,
      details,
      risk: options?.risk ?? 0,
    };

    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }

    this.subscriber?.(entry);
    return entry;
  }

  /**
   * Get recent entries, optionally filtered.
   */
  getRecent(options?: {
    limit?: number;
    agentId?: string;
    event?: AuditEventType;
    minRisk?: number;
  }): AuditEntry[] {
    let filtered = this.entries;
    if (options?.agentId) {
      filtered = filtered.filter(e => e.agentId === options.agentId);
    }
    if (options?.event) {
      filtered = filtered.filter(e => e.event === options.event);
    }
    if (options?.minRisk !== undefined) {
      filtered = filtered.filter(e => e.risk >= (options.minRisk ?? 0));
    }
    const limit = options?.limit ?? 100;
    return filtered.slice(-limit);
  }

  /**
   * Get all high-risk entries (risk >= 1).
   */
  getHighRisk(): AuditEntry[] {
    return this.entries.filter(e => e.risk >= 1);
  }

  /**
   * Export audit log as JSON.
   */
  exportJSON(): string {
    return JSON.stringify(this.entries, null, 2);
  }

  /**
   * Clear the audit log.
   */
  clear(): void {
    this.entries = [];
  }

  /**
   * Get total entry count.
   */
  get size(): number {
    return this.entries.length;
  }

  private generateId(): string {
    return `aud-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }
}
