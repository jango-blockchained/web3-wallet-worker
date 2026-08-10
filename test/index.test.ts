/**
 * Copyright (c) 2026 HOOX · HOOX · jango-blockchained (hoox-sh)
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, beforeEach, afterAll } from "bun:test";
import type { Env } from "../src/index";
import worker from "../src/index";

// Mock Request and ExecutionContext
const mockRequest = (url = "http://localhost", method = "GET"): Request =>
  new Request(url, {
    method,
    headers: { "X-Internal-Auth-Key": "test-internal-key" },
  });

// Mock ExecutionContext
const mockCtx: any = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn(),
};

// Test mnemonic and private key (replace with actual test values if needed, but keep them non-production)
const TEST_MNEMONIC =
  "test test test test test test test test test test test junk";
const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // Default Anvil/Hardhat key
const EXPECTED_ADDRESS_FROM_PK = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const EXPECTED_ADDRESS_FROM_MNEMONIC =
  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"; // Mnemonic above corresponds to this PK/address

describe("Web3 Wallet Worker with Secrets Store", () => {
  // Reset mocks before each test
  beforeEach(() => {
    (mockCtx.waitUntil as any).mockClear();
    (mockCtx.passThroughOnException as any).mockClear();
  });

  // Helper to create mock Env with specific secrets
  const createMockEnv = (secrets: {
    pk?: string | null;
    mnemonic?: string | null;
  }): Env => {
    return {
      INTERNAL_KEY_BINDING: "test-internal-key",
      WALLET_PK_SECRET:
        secrets.pk !== undefined
          ? (secrets.pk as string | undefined)
          : undefined,
      WALLET_MNEMONIC_SECRET:
        secrets.mnemonic !== undefined
          ? (secrets.mnemonic as string | undefined)
          : undefined,
      TELEGRAM_SERVICE: {
        fetch: vi
          .fn()
          .mockResolvedValue(
            new Response(JSON.stringify({ success: true }), { status: 200 })
          ),
        connect: vi.fn(),
      },
      WALLET_CONFIG_KV: {
        get: vi.fn().mockResolvedValue(null),
        put: vi.fn(),
        delete: vi.fn(),
        list: vi.fn().mockResolvedValue({ keys: [] }),
        getWithMetadata: vi.fn(),
      },
      CONFIG_KV: {
        get: vi.fn().mockResolvedValue(null),
        put: vi.fn().mockResolvedValue(undefined),
        delete: vi.fn(),
        list: vi.fn().mockResolvedValue({ keys: [] }),
        getWithMetadata: vi.fn(),
      },
      TRANSACTIONS_DB: {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            run: vi.fn().mockResolvedValue({ success: true }),
            first: vi.fn().mockResolvedValue(null),
            all: vi.fn().mockResolvedValue({ results: [] }),
          }),
          run: vi.fn().mockResolvedValue({ success: true }),
          first: vi.fn().mockResolvedValue(null),
          all: vi.fn().mockResolvedValue({ results: [] }),
        }),
      },
    };
  };

  it("should initialize with PRIVATE_KEY and return correct address", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = mockRequest();
    const res = await worker.fetch(req, env, mockCtx); // Get the actual Response

    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(json.message).toBe(
      "Worker initialized successfully using Secrets Store."
    );
    expect(json.walletAddress).toBe(EXPECTED_ADDRESS_FROM_PK);
  });

  it("should initialize with MNEMONIC_PHRASE and return correct address", async () => {
    const env = createMockEnv({ mnemonic: TEST_MNEMONIC }); // Only provide mnemonic
    const req = mockRequest();
    const res = await worker.fetch(req, env, mockCtx);

    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(json.message).toBe(
      "Worker initialized successfully using Secrets Store."
    );
    expect(json.walletAddress).toBe(EXPECTED_ADDRESS_FROM_MNEMONIC);
  });

  it("should prioritize PRIVATE_KEY over MNEMONIC_PHRASE", async () => {
    const env = createMockEnv({
      pk: TEST_PRIVATE_KEY,
      mnemonic: "other mnemonic",
    });
    const req = mockRequest();
    const res = await worker.fetch(req, env, mockCtx);

    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(json.walletAddress).toBe(EXPECTED_ADDRESS_FROM_PK); // PK address expected
  });

  it("should return 500 if no secrets are configured/retrieved", async () => {
    const env = createMockEnv({}); // No secrets provided to mock
    const req = mockRequest();
    const res = await worker.fetch(req, env, mockCtx);

    expect(res.status).toBe(500);
    const text = await res.text();
    expect(text).toContain(
      "Required wallet secret binding not configured or accessible."
    );
  });

  it("should return 500 if secrets retrieved are null", async () => {
    const env = createMockEnv({ pk: null, mnemonic: null }); // Explicitly null secrets
    const req = mockRequest();
    const res = await worker.fetch(req, env, mockCtx);

    expect(res.status).toBe(500);
    const text = await res.text();
    expect(text).toContain(
      "Required wallet secret binding not configured or accessible."
    );
  });

  it("should return 400 for invalid PRIVATE_KEY format", async () => {
    const env = createMockEnv({ pk: "invalid-key" });
    const req = mockRequest();
    const res = await worker.fetch(req, env, mockCtx);

    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("Configured private key secret is invalid.");
  });

  it("should return 400 for invalid MNEMONIC_PHRASE format", async () => {
    const env = createMockEnv({ mnemonic: "invalid phrase" });
    const req = mockRequest();
    const res = await worker.fetch(req, env, mockCtx);

    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("Configured mnemonic phrase secret is invalid.");
  });

  // ── GET /config ──

  it("GET /config returns config when authenticated", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/config", {
      headers: { "X-Internal-Auth-Key": "test-internal-key" },
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(json.enabled).toBe(true);
    expect(json.defaultChain).toBe("ethereum");
    expect(json.dex).toBeDefined();
    expect(json.security).toBeDefined();
    expect(json.updatedAt).toBeGreaterThan(0);
  });

  it("GET /config returns 401 without auth header", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/config", { method: "GET" });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(401);
    const json: any = await res.json();
    expect(json.success).toBe(false);
    expect(json.error).toBe("Unauthorized");
  });

  // ── PUT /config ──

  it("PUT /config updates config and returns it", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/config", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({ enabled: false, defaultChain: "polygon" }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(json.message).toBe("Configuration updated");
    expect(json.config.enabled).toBe(false);
    expect(json.config.defaultChain).toBe("polygon");
  });

  // ── POST /transfer ──

  it("POST /transfer rejects with missing required fields", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/transfer", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({ chain: "ethereum" }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
    const json: any = await res.json();
    expect(json.success).toBe(false);
    expect(json.error).toContain("Missing required fields");
  });

  // ── POST /approve ──

  it("POST /approve rejects with missing required fields", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/approve", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({ chain: "ethereum" }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
    const json: any = await res.json();
    expect(json.success).toBe(false);
    expect(json.error).toContain("Missing required fields");
  });

  // ── POST /swap ──

  it("POST /swap rejects missing required fields", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/swap", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({ chain: "ethereum" }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
    const json: any = await res.json();
    expect(json.success).toBe(false);
    expect(json.error).toContain("Missing required fields");
  });

  // ── GET /transactions ──

  it("GET /transactions returns list", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/transactions", {
      headers: { "X-Internal-Auth-Key": "test-internal-key" },
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(Array.isArray(json.transactions)).toBe(true);
    expect(json.count).toBe(0);
  });

  // ── GET /status ──

  it("GET /status returns wallet status", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/status", {
      headers: { "X-Internal-Auth-Key": "test-internal-key" },
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(json.address).toBe(EXPECTED_ADDRESS_FROM_PK);
    expect(json.source).toBe("private_key");
    expect(json.enabled).toBe(true);
    expect(json.defaultChain).toBe("ethereum");
    expect(Array.isArray(json.availableChains)).toBe(true);
    expect(json.security).toBeDefined();
    expect(json.security.maxTransactionValueUsd).toBe(10000);
    expect(json.updatedAt).toBeGreaterThan(0);
  });

  // ── GET /health ──

  it("GET /health returns ok without auth", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/health", { method: "GET" });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(json.result?.service || json.service || json.worker).toBeDefined();
  });

  // ── PUT /config validation ──

  it("PUT /config returns 400 for invalid JSON body", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/config", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: "not-json",
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
  });

  it("PUT /config deep-merges security without clobbering siblings", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/config", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({
        security: { whitelistedContractsOnly: true },
      }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(200);
    const json: any = await res.json();
    expect(json.config.security.whitelistedContractsOnly).toBe(true);
    // maxTransactionValueUsd should still be present from defaults
    expect(json.config.security.maxTransactionValueUsd).toBeDefined();
  });

  // ── GET /balance validation ──

  it("GET /balance requires chain param", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/balance", {
      headers: { "X-Internal-Auth-Key": "test-internal-key" },
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
  });

  it("GET /balance rejects unsupported chain", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/balance?chain=notachain", {
      headers: { "X-Internal-Auth-Key": "test-internal-key" },
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
  });

  // ── GET /quote validation ──

  it("GET /quote requires all params", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/quote?chain=ethereum", {
      headers: { "X-Internal-Auth-Key": "test-internal-key" },
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
    const json: any = await res.json();
    expect(String(json.error)).toMatch(/Missing required params/i);
  });

  it("GET /quote rejects invalid token addresses", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request(
      "http://localhost/quote?chain=ethereum&tokenIn=bad&tokenOut=also-bad&amountIn=1",
      { headers: { "X-Internal-Auth-Key": "test-internal-key" } }
    );
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
  });

  // ── POST /swap validation ──

  it("POST /swap rejects missing fields", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/swap", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({ chain: "ethereum" }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
  });

  it("POST /swap rejects invalid token addresses", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/swap", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({
        chain: "ethereum",
        tokenIn: "0xbad",
        tokenOut: "0xbad",
        amountIn: "1",
      }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
  });

  // ── POST /transfer more edges ──

  it("POST /transfer rejects invalid recipient address", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/transfer", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({
        chain: "ethereum",
        tokenAddress: "0x0000000000000000000000000000000000000000",
        to: "not-an-address",
        amount: "1",
      }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
  });

  it("POST /transfer rejects zero amount", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/transfer", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Auth-Key": "test-internal-key",
      },
      body: JSON.stringify({
        chain: "ethereum",
        tokenAddress: "0x0000000000000000000000000000000000000000",
        to: EXPECTED_ADDRESS_FROM_PK,
        amount: "0",
      }),
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(400);
  });

  it("returns 404 for unknown routes", async () => {
    const env = createMockEnv({ pk: TEST_PRIVATE_KEY });
    const req = new Request("http://localhost/nope", {
      headers: { "X-Internal-Auth-Key": "test-internal-key" },
    });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(404);
  });

});

// Restore original Response and Headers after all tests in this file
afterAll(() => {
  // Restore is no longer needed since we removed global mocking
});
