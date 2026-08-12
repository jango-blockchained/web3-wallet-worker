/**
 * Copyright (c) 2026 HOOX · HOOX · jango-blockchained (hoox-sh)
 * SPDX-License-Identifier: Apache-2.0
 */

// workers/web3-wallet-worker/src/pricing.ts
// Server-side USD notional estimation — never trust client valueUsd alone.

import { ethers } from "ethers";
import type { ChainName } from "./types";
import { DEFAULT_CHAIN_CONFIGS, DEX_ROUTER_ABI } from "./constants";
import { getTokenInfo } from "./tokens";
import { getReadOnlyProvider } from "./providers";

/** Well-known USD stablecoins (1:1 for limit enforcement). */
const STABLECOIN_ADDRESSES = new Set(
  [
    // USDT
    "0xdac17f958d2ee523a2206206994597c13d831ec7", // eth
    "0x55d398326f99059ff775485246999027b3197955", // bsc
    "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", // polygon
    "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", // arbitrum
    // USDC
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // eth
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", // bsc
    "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", // polygon
    "0xaf88d065e77c8cc2239327c5edb3a432268e5831", // arbitrum
    // DAI
    "0x6b175474e89094c44da98b954eedeac495271d0f",
    "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3", // bsc dai
  ].map((a) => a.toLowerCase())
);

/** Preferred USD quote tokens per chain (try in order). */
const CHAIN_QUOTE_STABLES: Record<ChainName, string[]> = {
  ethereum: [
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
    "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
    "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
  ],
  bsc: [
    "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", // USDC
    "0x55d398326f99059fF775485246999027B3197955", // USDT
  ],
  polygon: [
    "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", // USDC
    "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", // USDT
  ],
  arbitrum: [
    "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", // USDC
    "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", // USDT
  ],
  optimism: [
    "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", // USDC
    "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", // USDT
  ],
};

const NATIVE_ZERO = "0x0000000000000000000000000000000000000000";

/** Map chain native currency to a Binance USDT pair symbol. */
const NATIVE_BINANCE_PAIR: Record<ChainName, string | null> = {
  ethereum: "ETHUSDT",
  bsc: "BNBUSDT",
  polygon: "MATICUSDT",
  arbitrum: "ETHUSDT",
  optimism: "ETHUSDT",
};

/** In-memory price cache (per isolate) — short TTL to limit external calls. */
const priceCache = new Map<string, { usd: number; expiresAt: number }>();
const PRICE_CACHE_TTL_MS = 60_000;

async function fetchBinancePriceUsd(pair: string): Promise<number | null> {
  const cached = priceCache.get(pair);
  if (cached && Date.now() < cached.expiresAt) return cached.usd;

  try {
    const res = await fetch(
      `https://api.binance.com/api/v3/ticker/price?symbol=${pair}`,
      { signal: AbortSignal.timeout(5_000) }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as { price?: string };
    const usd = data.price ? parseFloat(data.price) : NaN;
    if (!Number.isFinite(usd) || usd <= 0) return null;
    priceCache.set(pair, { usd, expiresAt: Date.now() + PRICE_CACHE_TTL_MS });
    return usd;
  } catch {
    return null;
  }
}

/**
 * Quote token amount → preferred stable via Uniswap-V2-compatible router.
 *
 * Path search (multi-stable + multi-hop):
 *  1. token → stable (each preferred stable)
 *  2. token → WNATIVE → stable
 *  3. token → stableA → stableB (cross-stable hop for thin markets)
 */
async function quoteTokenToStableUsd(
  chain: ChainName,
  tokenAddress: string,
  amountRaw: bigint
): Promise<number | null> {
  const chainConfig = DEFAULT_CHAIN_CONFIGS[chain];
  const routerAddr = chainConfig?.dexRouterAddress;
  const wNative = chainConfig?.wrappedNativeAddress;
  const stables = CHAIN_QUOTE_STABLES[chain] ?? [];
  if (!routerAddr || !wNative || stables.length === 0 || amountRaw <= 0n) {
    return null;
  }

  const token = tokenAddress.toLowerCase();
  if (stables.some((s) => s.toLowerCase() === token)) {
    return null; // handled as stablecoin earlier
  }

  const cacheKey = `dex:${chain}:${token}:${amountRaw.toString()}`;
  const cached = priceCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) return cached.usd;

  try {
    const provider = getReadOnlyProvider(chain);
    const router = new ethers.Contract(routerAddr, DEX_ROUTER_ABI, provider);
    const tokenIn = ethers.getAddress(tokenAddress);
    const wrapped = ethers.getAddress(wNative);

    type PathAttempt = { path: string[]; stableOut: string };
    const attempts: PathAttempt[] = [];

    for (const stable of stables) {
      const stableOut = ethers.getAddress(stable);
      attempts.push({ path: [tokenIn, stableOut], stableOut });
      attempts.push({ path: [tokenIn, wrapped, stableOut], stableOut });
    }
    // Cross-stable hop: token → USDC → USDT (or reverse) for thin pairs
    if (stables.length >= 2) {
      const stableA = stables[0];
      const stableB = stables[1];
      if (!stableA || !stableB) return null;
      const a = ethers.getAddress(stableA);
      const b = ethers.getAddress(stableB);
      attempts.push({ path: [tokenIn, a, b], stableOut: b });
      attempts.push({ path: [tokenIn, b, a], stableOut: a });
      attempts.push({ path: [tokenIn, wrapped, a, b], stableOut: b });
    }

    for (const { path, stableOut } of attempts) {
      const ends = path.map((p) => p.toLowerCase());
      if (ends[0] === ends[ends.length - 1]) continue;
      // Drop paths with duplicate consecutive hops
      if (ends.some((p, i) => i > 0 && p === ends[i - 1])) continue;

      try {
        const getAmountsOut = router.getAmountsOut;
        if (!getAmountsOut) continue;
        const amounts: bigint[] = await getAmountsOut(amountRaw, path);
        const out = amounts[amounts.length - 1];
        if (out === undefined || out <= 0n) continue;

        const stableInfo = await getTokenInfo(provider, stableOut);
        const usd = Number(ethers.formatUnits(out, stableInfo.decimals));
        if (!Number.isFinite(usd) || usd <= 0) continue;

        priceCache.set(cacheKey, {
          usd,
          expiresAt: Date.now() + PRICE_CACHE_TTL_MS,
        });
        return usd;
      } catch {
        // pair missing — try next path
      }
    }

    return null;
  } catch {
    return null;
  }
}

export interface ValueEstimate {
  valueUsd: number;
  source: "stablecoin" | "native-oracle" | "dex-quote" | "unavailable";
  decimals: number;
  amountHuman: number;
}

/**
 * Estimate USD notional for a token amount using server-side data only.
 *
 * Priority:
 * 1. Known USD stables → 1:1
 * 2. Native currency (or wrapped native) → Binance public ticker
 * 3. Other ERC-20 → DEX quote to chain stable (USDC), direct or via WNATIVE
 * 4. Otherwise unavailable (caller should fail closed)
 *
 * Client-supplied valueUsd is ignored.
 */
export async function estimateTokenValueUsd(params: {
  chain: ChainName;
  tokenAddress: string;
  amountRaw: bigint;
}): Promise<ValueEstimate> {
  const { chain, tokenAddress, amountRaw } = params;
  const addr = tokenAddress.toLowerCase();
  const chainConfig = DEFAULT_CHAIN_CONFIGS[chain];
  const wrapped = chainConfig?.wrappedNativeAddress?.toLowerCase();

  // Native (zero address) or wrapped native
  const isNative =
    addr === NATIVE_ZERO || (wrapped !== undefined && addr === wrapped);

  if (isNative) {
    const pair = NATIVE_BINANCE_PAIR[chain];
    const unitPrice = pair ? await fetchBinancePriceUsd(pair) : null;
    const amountHuman = Number(ethers.formatEther(amountRaw));
    if (unitPrice === null || !Number.isFinite(amountHuman)) {
      return {
        valueUsd: 0,
        source: "unavailable",
        decimals: 18,
        amountHuman,
      };
    }
    return {
      valueUsd: amountHuman * unitPrice,
      source: "native-oracle",
      decimals: 18,
      amountHuman,
    };
  }

  // Stablecoins
  if (STABLECOIN_ADDRESSES.has(addr)) {
    try {
      const provider = getReadOnlyProvider(chain);
      const info = await getTokenInfo(provider, tokenAddress);
      const amountHuman = Number(ethers.formatUnits(amountRaw, info.decimals));
      return {
        valueUsd: amountHuman,
        source: "stablecoin",
        decimals: info.decimals,
        amountHuman,
      };
    } catch {
      // Fall through
    }
  }

  // ERC-20 via DEX quote → stable
  try {
    const provider = getReadOnlyProvider(chain);
    const info = await getTokenInfo(provider, tokenAddress);
    const amountHuman = Number(ethers.formatUnits(amountRaw, info.decimals));
    const dexUsd = await quoteTokenToStableUsd(chain, tokenAddress, amountRaw);
    if (dexUsd !== null && dexUsd > 0) {
      return {
        valueUsd: dexUsd,
        source: "dex-quote",
        decimals: info.decimals,
        amountHuman,
      };
    }
    return {
      valueUsd: 0,
      source: "unavailable",
      decimals: info.decimals,
      amountHuman,
    };
  } catch {
    return {
      valueUsd: 0,
      source: "unavailable",
      decimals: 18,
      amountHuman: 0,
    };
  }
}

/**
 * Resolve the USD notional used for policy checks.
 * Fail closed when the server cannot price the asset (unless amount is 0).
 */
export async function resolveEnforcedValueUsd(params: {
  chain: ChainName;
  tokenAddress: string;
  amountRaw: bigint;
}): Promise<
  | { ok: true; valueUsd: number; source: ValueEstimate["source"] }
  | { ok: false; reason: string }
> {
  if (params.amountRaw === 0n) {
    return { ok: true, valueUsd: 0, source: "stablecoin" };
  }

  const estimate = await estimateTokenValueUsd(params);
  if (estimate.source === "unavailable" || !(estimate.valueUsd > 0)) {
    return {
      ok: false,
      reason:
        "Unable to price token server-side (stable, native oracle, or DEX quote to USDC failed). Transfer blocked until a price path is available.",
    };
  }
  return {
    ok: true,
    valueUsd: estimate.valueUsd,
    source: estimate.source,
  };
}
