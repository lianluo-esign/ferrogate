/**
 * Shared golden fixtures for the payments wire-contract tests. Mirrors the
 * checked-in `crates/ferrogate-payments/fixtures/*.json` so the TS port is
 * exercised against the same frozen shapes (regenerated to headers via the
 * ported base64 encoder rather than committed as pre-encoded blobs).
 */
import { encodeBase64Std } from "../src/index.js";

export const USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
export const USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
export const PAY_TO = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
export const OTHER_MERCHANT = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
export const FEE_PAYER = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";
export const CAIP2_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
export const CAIP2_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
export const RESOURCE = "https://pay.example.com/weather";

const enc = new TextEncoder();

/** Base64-encode a JSON object into an x402 header value. */
export function toHeader(doc: unknown): string {
  return encodeBase64Std(enc.encode(JSON.stringify(doc)));
}

/** Deep clone a plain JSON value (fixtures are pure JSON). */
export function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export function paymentRequiredMainnet(): Record<string, unknown> {
  return {
    x402Version: 2,
    error: "PAYMENT-SIGNATURE header is required",
    resource: {
      url: "https://pay.example.com/premium-data",
      description: "Access to premium market data",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:84532",
        amount: "10000",
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        maxTimeoutSeconds: 60,
        extra: { name: "USDC", version: "2" },
      },
      {
        scheme: "exact",
        network: CAIP2_MAINNET,
        amount: "1000",
        asset: USDC_MAINNET,
        payTo: PAY_TO,
        maxTimeoutSeconds: 60,
        extra: { feePayer: FEE_PAYER, memo: "pi_3abc123def456" },
      },
    ],
  };
}

export function paymentRequiredDevnet(): Record<string, unknown> {
  return {
    x402Version: 2,
    resource: { url: RESOURCE, mimeType: "application/json" },
    accepts: [
      {
        scheme: "exact",
        network: CAIP2_DEVNET,
        amount: "2500",
        asset: USDC_DEVNET,
        payTo: PAY_TO,
        maxTimeoutSeconds: 120,
        extra: { feePayer: FEE_PAYER },
      },
    ],
  };
}

export function paymentRequiredSponsored(): Record<string, unknown> {
  return {
    x402Version: 2,
    resource: { url: "https://pay.example.com/sponsored-feed", mimeType: "application/json" },
    accepts: [
      {
        scheme: "exact",
        network: CAIP2_DEVNET,
        amount: "750",
        asset: USDC_DEVNET,
        payTo: PAY_TO,
        maxTimeoutSeconds: 90,
        extra: {
          feePayer: FEE_PAYER,
          memo: "inv_2026_07_0001",
          recentBlockhash: "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k",
          lastValidBlockHeight: "291470237",
        },
      },
    ],
    extensions: {
      bazaar: { info: { category: "market-data" }, schema: { type: "object" } },
    },
  };
}

export function paymentResponseSuccess(): Record<string, unknown> {
  return {
    success: true,
    transaction:
      "2Ana1pUpv2ZbMVkwF5FXapYeBEjdxDatLn7nvJkhgTSXbs59SyZSx866bXirPgj8QQVB57uxHJBG1YFvkRbFj4T",
    network: CAIP2_MAINNET,
    payer: FEE_PAYER,
    amount: "1000",
  };
}

export function paymentResponseFailure(): Record<string, unknown> {
  return {
    success: false,
    errorReason: "insufficient_funds",
    transaction: "",
    network: CAIP2_MAINNET,
    payer: FEE_PAYER,
  };
}
