/**
 * Keeper-Agent — HTTP API Server
 *
 * Routes:
 *   POST /api/v1/auth/register   — Register a new agent
 *   POST /api/v1/auth/token      — Issue a scoped token
 *   POST /api/v1/auth/revoke     — Revoke a token
 *   POST /api/v1/proxy/{provider}/{path}  — Proxy API calls
 *   GET  /api/v1/vault           — List vault entries (masked)
 *   GET  /api/v1/agents          — List registered agents
 *   GET  /api/v1/audit           — Get audit log
 *   GET  /api/v1/health          — Health check
 *   GET  /api/v1/status          — Keeper status
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { AuthManager } from './auth.js';
import { Vault } from './vault.js';
import { SecretScanner } from './scanner.js';
import { AuditLog } from './audit.js';
import { ProxyEngine } from './proxy.js';

export async function createApp(options?: {
  encryptionKey?: string;
  port?: number;
}) {
  const app = new Hono();

  // Initialize components
  const vault = new Vault(options?.encryptionKey);
  const auth = new AuthManager();
  const scanner = new SecretScanner();
  const audit = new AuditLog();

  // Ensure auth keys are ready before accepting requests
  await auth.ensureReady();

  const proxy = new ProxyEngine(auth, vault, scanner, audit);

  app.use('*', cors());

  // --- Health / Status ---

  app.get('/api/v1/health', (c) => {
    return c.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    });
  });

  app.get('/api/v1/status', (c) => {
    return c.json({
      status: 'operational',
      agents: auth.listAgents().length,
      secrets: vault.size,
      auditEntries: audit.size,
      highRiskEvents: audit.getHighRisk().length,
    });
  });

  // --- Auth: Agent Registration ---

  app.post('/api/v1/auth/register', async (c) => {
    const body = await c.req.json();
    const { agentId, agentName, githubUser } = body;

    if (!agentId || !agentName) {
      return c.json({ error: 'agentId and agentName are required' }, 400);
    }

    const agent = auth.registerAgent(agentId, agentName, githubUser);
    audit.log('agent.registered', { agentId: agent.id, agentName: agent.name });

    return c.json({
      message: 'Agent registered successfully',
      agent: {
        id: agent.id,
        name: agent.name,
        createdAt: agent.createdAt,
      },
    });
  });

  // --- Auth: Token Issuance ---

  app.post('/api/v1/auth/token', async (c) => {
    const body = await c.req.json();
    const { agentId, ttlHours, scopes } = body;

    if (!agentId) {
      return c.json({ error: 'agentId is required' }, 400);
    }

    // Default scopes if not specified
    const defaultScopes = scopes || ['openai:chat', 'github:read'];

    try {
      const token = await auth.issueToken(agentId, defaultScopes, ttlHours || 24);
      audit.log('token.issued', {
        agentId,
        scopes: token.scopes,
        expiresAt: token.expiresAt,
      });

      return c.json({
        message: 'Token issued',
        token: token.token,
        expiresAt: token.expiresAt,
        scopes: token.scopes,
        agentId: token.agentId,
      });
    } catch (error) {
      return c.json({
        error: error instanceof Error ? error.message : 'Token issuance failed',
      }, 400);
    }
  });

  // --- Auth: Token Revocation ---

  app.post('/api/v1/auth/revoke', async (c) => {
    const body = await c.req.json();
    const { jti, agentId } = body;

    if (agentId) {
      auth.revokeAgentTokens(agentId);
      audit.log('token.revoked', { agentId, scope: 'all' }, { risk: 1 });
      return c.json({ message: `All tokens for agent ${agentId} revoked` });
    }

    if (jti) {
      auth.revokeToken(jti);
      audit.log('token.revoked', { jti }, { risk: 1 });
      return c.json({ message: 'Token revoked' });
    }

    return c.json({ error: 'jti or agentId required' }, 400);
  });

  // --- Auth: Token Validation (for agents to check their token) ---

  app.post('/api/v1/auth/validate', async (c) => {
    const body = await c.req.json();
    const { token } = body;

    if (!token) {
      return c.json({ error: 'token is required' }, 400);
    }

    const payload = await auth.validateToken(token);
    if (!payload) {
      return c.json({ valid: false, reason: 'Invalid or expired token' }, 401);
    }

    return c.json({
      valid: true,
      agentId: payload.sub,
      name: payload.name,
      scopes: payload.scopes,
      expiresAt: new Date(payload.exp * 1000).toISOString(),
    });
  });

  // --- Proxy: API Call Forwarding ---

  app.post('/api/v1/proxy/:provider/*path', async (c) => {
    const provider = c.req.param('provider');
    const path = c.req.param('path');
    const body = await c.req.json();

    const { token, method, headers, requestBody } = body;

    if (!token) {
      return c.json({ error: 'Authentication token required' }, 401);
    }

    const result = await proxy.proxy(token, {
      provider,
      method: method || 'POST',
      path: `/${path}`,
      headers: headers || {},
      body: requestBody,
    });

    if (!result.allowed) {
      return c.json({ error: result.reason, scanFindings: result.scanFindings }, 403);
    }

    return c.json({
      status: result.request?.status,
      body: result.request?.body,
      responseScanFindings: result.responseScanFindings,
    });
  });

  // --- Vault: List Secrets (masked) ---

  app.get('/api/v1/vault', (c) => {
    // In a real deployment, this would require admin auth
    const entries = vault.list();
    return c.json({
      secrets: entries,
      total: entries.length,
    });
  });

  app.post('/api/v1/vault', async (c) => {
    const body = await c.req.json();
    const { provider, value, label, allowedAgents } = body;

    if (!provider || !value) {
      return c.json({ error: 'provider and value are required' }, 400);
    }

    vault.set(provider, value, { label, allowedAgents });
    audit.log('vault.modified', { action: 'set', provider });

    return c.json({ message: `Secret set for ${provider}` });
  });

  app.delete('/api/v1/vault/:provider', (c) => {
    const provider = c.req.param('provider');
    const deleted = vault.delete(provider);
    audit.log('vault.modified', { action: 'delete', provider, success: deleted });
    return c.json({ message: deleted ? `Secret deleted for ${provider}` : 'Not found' });
  });

  // --- Agents: List ---

  app.get('/api/v1/agents', (c) => {
    return c.json({ agents: auth.listAgents() });
  });

  // --- Audit: Log Access ---

  app.get('/api/v1/audit', (c) => {
    const agentId = c.req.query('agentId');
    const event = c.req.query('event') as AuditLog['getRecent'] extends (o?: infer O) => void ? O extends { event?: infer E } ? E : never : never;
    const minRisk = c.req.query('minRisk') ? parseInt(c.req.query('minRisk')!) : undefined;

    const entries = audit.getRecent({
      limit: 200,
      agentId: agentId || undefined,
      event: event as any,
      minRisk,
    });

    return c.json({ entries, total: entries.length });
  });

  // --- Scanner: Test endpoint ---

  app.post('/api/v1/scan', async (c) => {
    const body = await c.req.json();
    const { text, context } = body;

    const result = scanner.scan(text || '', context || 'test');
    return c.json(result);
  });

  return { app, vault, auth, scanner, audit, proxy };
}
