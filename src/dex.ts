/**
 * Copyright (c) 2026 HOOX · HOOX · jango-blockchained (hoox-sh)
 * SPDX-License-Identifier: Apache-2.0
 */

// workers/web3-wallet-worker/src/dex.ts

import { ethers } from "ethers";
import type { ChainName, SwapRequest, WalletConfig } from "./types";
import { ERC20_ABI, DEX_ROUTER_ABI } from "./constants";
import { getChainConfig } from "./config";

/** Native token sentinel address (router replaces with WETH/WBNB internally) */
const NATIVE_TOKEN = ethers.ZeroAddress;

/**
 * Get a swap quote from the DEX router.
 * Returns the expected output amount in wei.
 */
export async function getQuote(
  provider: ethers.Provider,
  chain: ChainName,
  tokenIn: string,
  tokenOut: string,
  amountIn: bigint
): Promise<bigint> {
  const chainConfig = getChainConfig(chain);
  const routerAddr = chainConfig.dexRouterAddress;
  if (!routerAddr) {
    throw new Error(`No DEX router configured for chain: ${chain}`);
  }

  const router = new ethers.Contract(routerAddr, DEX_ROUTER_ABI, provider);
  const path = buildPath(chain, tokenIn, tokenOut);

  const getAmountsOut = router.getAmountsOut;
  if (!getAmountsOut) throw new Error("Router getAmountsOut method unavailable");
  const amounts: bigint[] = await getAmountsOut(amountIn, path);
  const out = amounts[amounts.length - 1];
  if (out === undefined) throw new Error("Empty amounts from getAmountsOut");
  return out;
}

/**
 * Execute a swap via the DEX router.
 *
 * Steps:
 * 1. Validate the swap request against security config
 * 2. Check and request token approval if needed (for non-native input)
 * 3. Compute minAmountOut from slippage tolerance
 * 4. Execute the swap and return the tx hash
 */
export async function executeSwap(
  wallet: ethers.Wallet,
  chain: ChainName,
  request: SwapRequest,
  config: WalletConfig
): Promise<string> {
  const chainConfig = getChainConfig(chain);
  const routerAddr = chainConfig.dexRouterAddress;
  if (!routerAddr) {
    throw new Error(`No DEX router configured for chain: ${chain}`);
  }

  const isNativeIn = request.tokenIn === NATIVE_TOKEN;
  const isNativeOut = request.tokenOut === NATIVE_TOKEN;

  // Build the swap path
  const path = buildPath(chain, request.tokenIn, request.tokenOut);

  // Compute minAmountOut from slippage
  const provider = wallet.provider!;
  const quote = await getQuote(
    provider,
    chain,
    request.tokenIn,
    request.tokenOut,
    BigInt(request.amountIn)
  );
  const slippageBasis = Math.floor(config.dex.slippageTolerance * 100);
  const minAmountOut =
    request.minAmountOut ?? (quote * BigInt(10000 - slippageBasis)) / 10000n;

  const recipient = request.recipient || wallet.address;
  const deadline = request.deadline ?? Math.floor(Date.now() / 1000) + 1200; // 20 min

  const router = new ethers.Contract(routerAddr, DEX_ROUTER_ABI, wallet);

  let tx: ethers.TransactionResponse;

  if (isNativeIn) {
    // Native → Token: swapExactETHForTokens (payable)
    const swapExactETHForTokens = router.swapExactETHForTokens;
    if (!swapExactETHForTokens) {
      throw new Error("Router swapExactETHForTokens method unavailable");
    }
    tx = await swapExactETHForTokens(
      minAmountOut,
      path,
      recipient,
      deadline,
      {
        value: BigInt(request.amountIn),
      }
    );
  } else {
    // Token in: need approval first
    await checkAllowanceAndApprove(
      wallet,
      provider,
      request.tokenIn,
      routerAddr,
      BigInt(request.amountIn)
    );

    if (isNativeOut) {
      // Token → Native: swapExactTokensForETH
      const swapExactTokensForETH = router.swapExactTokensForETH;
      if (!swapExactTokensForETH) {
        throw new Error("Router swapExactTokensForETH method unavailable");
      }
      tx = await swapExactTokensForETH(
        BigInt(request.amountIn),
        minAmountOut,
        path,
        recipient,
        deadline
      );
    } else {
      // Token → Token: swapExactTokensForTokens
      const swapExactTokensForTokens = router.swapExactTokensForTokens;
      if (!swapExactTokensForTokens) {
        throw new Error("Router swapExactTokensForTokens method unavailable");
      }
      tx = await swapExactTokensForTokens(
        BigInt(request.amountIn),
        minAmountOut,
        path,
        recipient,
        deadline
      );
    }
  }

  const receipt = await tx.wait();
  return receipt?.hash ?? tx.hash;
}

/**
 * Check token allowance for the router and approve if insufficient.
 * Returns the approval tx hash if an approve was sent, or null if not needed.
 * For native token input, always returns null (no approval needed).
 */
export async function checkAllowanceAndApprove(
  wallet: ethers.Wallet,
  provider: ethers.Provider,
  tokenAddress: string,
  spender: string,
  amount: bigint
): Promise<string | null> {
  // Native token never needs approval
  if (tokenAddress === ethers.ZeroAddress) return null;

  const checksummedToken = ethers.getAddress(tokenAddress);
  const checksummedSpender = ethers.getAddress(spender);
  const owner = wallet.address;

  const contract = new ethers.Contract(checksummedToken, ERC20_ABI, provider);
  const allowanceFn = contract.allowance;
  if (!allowanceFn) throw new Error("ERC20 allowance method unavailable");
  const currentAllowance: bigint = await allowanceFn(
    owner,
    checksummedSpender
  );

  if (currentAllowance >= amount) {
    return null; // Allowance is sufficient
  }

  // Send approve transaction
  const signerContract = new ethers.Contract(
    checksummedToken,
    ERC20_ABI,
    wallet
  );
  const approve = signerContract.approve;
  if (!approve) throw new Error("ERC20 approve method unavailable");
  const tx = await approve(checksummedSpender, amount);
  const receipt = await tx.wait();
  return receipt?.hash ?? tx.hash;
}

// ── Internal helpers ──

/**
 * Build a swap path array from token addresses.
 * For native token input/output, replace with wrapped native address.
 */
function buildPath(
  chain: ChainName,
  tokenIn: string,
  tokenOut: string
): string[] {
  const chainConfig = getChainConfig(chain);
  const wNative = chainConfig.wrappedNativeAddress;

  if (!wNative) {
    throw new Error(`No wrapped native address configured for chain: ${chain}`);
  }

  const resolvedIn = tokenIn === NATIVE_TOKEN ? wNative : tokenIn;
  const resolvedOut = tokenOut === NATIVE_TOKEN ? wNative : tokenOut;

  return [resolvedIn, resolvedOut];
}
