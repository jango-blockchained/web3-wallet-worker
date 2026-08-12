/**
 * Copyright (c) 2026 HOOX · HOOX · jango-blockchained (hoox-sh)
 * SPDX-License-Identifier: Apache-2.0
 */

// workers/web3-wallet-worker/src/tokens.ts

import { ethers } from "ethers";
import type { ChainName, TokenInfo, BalanceResult } from "./types";
import { ERC20_ABI } from "./constants";

/**
 * Fetch ERC20 token metadata (name, symbol, decimals) from on-chain.
 */
export async function getTokenInfo(
  provider: ethers.Provider,
  address: string
): Promise<TokenInfo> {
  const checksummed = ethers.getAddress(address);
  const contract = new ethers.Contract(checksummed, ERC20_ABI, provider);
  const nameFn = contract.name;
  const symbolFn = contract.symbol;
  const decimalsFn = contract.decimals;
  if (!nameFn || !symbolFn || !decimalsFn) {
    throw new Error("ERC20 metadata methods unavailable");
  }
  const [name, symbol, decimals] = await Promise.all([
    nameFn(),
    symbolFn(),
    decimalsFn(),
  ]);
  return {
    address: checksummed,
    chain: "" as ChainName, // filled by caller
    symbol: symbol as string,
    name: name as string,
    decimals: decimals as number,
  };
}

/**
 * Get native currency balance for an address (ETH, BNB, MATIC, etc.).
 */
export async function getNativeBalance(
  provider: ethers.Provider,
  address: string
): Promise<bigint> {
  const checksummed = ethers.getAddress(address);
  return await provider.getBalance(checksummed);
}

/**
 * Get ERC20 token balance for an address.
 */
export async function getTokenBalance(
  provider: ethers.Provider,
  tokenAddress: string,
  ownerAddress: string
): Promise<bigint> {
  const checksummedToken = ethers.getAddress(tokenAddress);
  const checksummedOwner = ethers.getAddress(ownerAddress);
  const contract = new ethers.Contract(checksummedToken, ERC20_ABI, provider);
  const balanceOf = contract.balanceOf;
  if (!balanceOf) throw new Error("ERC20 balanceOf method unavailable");
  return await balanceOf(checksummedOwner);
}

/**
 * Get ERC20 token allowance for a spender.
 */
export async function getAllowance(
  provider: ethers.Provider,
  tokenAddress: string,
  owner: string,
  spender: string
): Promise<bigint> {
  const checksummedToken = ethers.getAddress(tokenAddress);
  const checksummedOwner = ethers.getAddress(owner);
  const checksummedSpender = ethers.getAddress(spender);
  const contract = new ethers.Contract(checksummedToken, ERC20_ABI, provider);
  const allowance = contract.allowance;
  if (!allowance) throw new Error("ERC20 allowance method unavailable");
  return await allowance(checksummedOwner, checksummedSpender);
}

/**
 * Approve a spender to spend tokens on behalf of the wallet.
 * Returns the transaction hash.
 */
export async function approveToken(
  wallet: ethers.Wallet,
  tokenAddress: string,
  spender: string,
  amount: bigint
): Promise<string> {
  const checksummedToken = ethers.getAddress(tokenAddress);
  const checksummedSpender = ethers.getAddress(spender);
  const contract = new ethers.Contract(checksummedToken, ERC20_ABI, wallet);
  const approve = contract.approve;
  if (!approve) throw new Error("ERC20 approve method unavailable");
  const tx = await approve(checksummedSpender, amount);
  const receipt = await tx.wait();
  return receipt?.hash ?? tx.hash;
}

/**
 * Transfer tokens from the wallet to another address.
 * Returns the transaction hash.
 */
export async function transferToken(
  wallet: ethers.Wallet,
  tokenAddress: string,
  to: string,
  amount: bigint
): Promise<string> {
  const checksummedToken = ethers.getAddress(tokenAddress);
  const checksummedTo = ethers.getAddress(to);
  const contract = new ethers.Contract(checksummedToken, ERC20_ABI, wallet);
  const transfer = contract.transfer;
  if (!transfer) throw new Error("ERC20 transfer method unavailable");
  const tx = await transfer(checksummedTo, amount);
  const receipt = await tx.wait();
  return receipt?.hash ?? tx.hash;
}

/**
 * Format a bigint balance into a BalanceResult with both wei and human-readable strings.
 */
export function formatBalance(
  chain: ChainName,
  token: TokenInfo,
  balance: bigint
): BalanceResult {
  return {
    chain,
    token,
    balance: balance.toString(),
    balanceFormatted: ethers.formatUnits(balance, token.decimals),
  };
}
