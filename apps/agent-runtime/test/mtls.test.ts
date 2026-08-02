/**
 * The mutual-TLS APPROXIMATION, pinned.
 *
 * Rust terminates mutual TLS itself (`self_hosted_mtls::SelfHostedMtlsServer`):
 * it owns the CA bundle, builds the chain, and checks revocation in process. A
 * Worker never sees the TLS handshake and `crypto.subtle` has no chain builder,
 * so that server has NO Cloudflare equivalent — see the PORT-TODO on
 * `admitTransport` in `src/middleware/auth.ts`.
 *
 * What IS implemented is the consuming half: the ZONE validates the client
 * certificate and the Worker reads the verdict off `request.cf.tlsClientAuth`.
 * This file exists because the substitute is the ONLY thing standing between
 * the production posture and an unverifiable claim, and an approximation
 * nobody tests is indistinguishable from a stub.
 *
 * `units.test.ts` already covers `admitTransport`'s decision table. What was
 * NOT covered anywhere — and is covered here — is the verdict READ itself:
 * every one of the three `tlsClientAuth` fields, and the upgrade rule that
 * turns a declared marker into a verified channel.
 */
import { describe, expect, it } from "vitest";
import {
  TRANSPORT_SECURITY_HEADER,
  admitTransport,
  resolveTransportChannel,
  verifiedMutualTls,
} from "../src/middleware/auth.js";

/**
 * A request carrying an edge mTLS verdict.
 *
 * workerd honours `cf` on `RequestInit`, so this is the REAL property the
 * production code reads — not a stubbed accessor. `cf` is omitted entirely
 * when `tls` is undefined, which is exactly what a local/dev request looks
 * like.
 */
function request(
  tls: Record<string, string> | undefined,
  headers: Record<string, string> = {},
): Request {
  const init: RequestInit & { cf?: unknown } = { headers };
  if (tls !== undefined) init.cf = { tlsClientAuth: tls };
  return new Request("https://agent-runtime.test/v1/self-hosted-workers/heartbeat", init);
}

const VERIFIED = { certPresented: "1", certVerified: "SUCCESS", certRevoked: "0" };

describe("verifiedMutualTls — reading the edge verdict", () => {
  it("accepts only a presented, verified, unrevoked certificate", () => {
    expect(verifiedMutualTls(request(VERIFIED))).toBe(true);
  });

  it("fails closed when the edge reported no verdict at all", () => {
    // `request.cf` is absent under `wrangler dev --local` and in this offline
    // pool. The production posture must therefore refuse locally rather than
    // assume a channel it cannot observe.
    expect(verifiedMutualTls(request(undefined))).toBe(false);
    expect(verifiedMutualTls(request({}))).toBe(false);
  });

  it("requires certPresented — a verdict about no certificate is not a certificate", () => {
    expect(verifiedMutualTls(request({ ...VERIFIED, certPresented: "0" }))).toBe(false);
    const { certPresented: _omitted, ...withoutPresented } = VERIFIED;
    expect(verifiedMutualTls(request(withoutPresented))).toBe(false);
  });

  it("requires certVerified === SUCCESS, and treats every other value as failure", () => {
    // Cloudflare reports `FAILED`, `NONE`, and assorted `CERT_*` reasons here.
    // A truthiness check would admit all of them.
    for (const verdict of ["FAILED", "NONE", "CERT_EXPIRED", "SUCCESS_BUT_NOT_REALLY", ""]) {
      expect(verifiedMutualTls(request({ ...VERIFIED, certVerified: verdict })), verdict).toBe(
        false,
      );
    }
  });

  it("REJECTS a revoked certificate the edge still reported as SUCCESS", () => {
    // The subtle one, and the reason `certRevoked` is checked separately:
    // Cloudflare reports `certVerified: "SUCCESS"` together with
    // `certRevoked: "1"` for a revoked-but-otherwise-valid certificate, so a
    // check that stopped at `certVerified` would admit a revoked client.
    expect(verifiedMutualTls(request({ ...VERIFIED, certRevoked: "1" }))).toBe(false);
  });
});

describe("resolveTransportChannel — the upgrade rule", () => {
  it("upgrades the mutual_tls MARKER to a verified channel when the edge agrees", () => {
    const channel = resolveTransportChannel(
      request(VERIFIED, { [TRANSPORT_SECURITY_HEADER]: "mutual_tls" }),
    );
    expect(channel).toBe("verified_mutual_tls");
  });

  it("leaves the marker unverified when the edge did not verify anything", () => {
    const channel = resolveTransportChannel(
      request(undefined, { [TRANSPORT_SECURITY_HEADER]: "mutual_tls" }),
    );
    expect(channel).toBe("unverified_mutual_tls_marker");
  });

  it("NEVER upgrades a declared symmetric_aead downgrade, even over verified mTLS", () => {
    // The header is the worker's own statement about which transport contract
    // it speaks. Silently promoting a declared downgrade would let a
    // misconfigured worker pass the production posture it was meant to fail.
    const channel = resolveTransportChannel(
      request(VERIFIED, { [TRANSPORT_SECURITY_HEADER]: "symmetric_aead" }),
    );
    expect(channel).toBe("symmetric_aead");
  });

  it("an absent or unknown marker is no channel at all", () => {
    expect(resolveTransportChannel(request(VERIFIED))).toBeNull();
    expect(
      resolveTransportChannel(request(VERIFIED, { [TRANSPORT_SECURITY_HEADER]: "tls" })),
    ).toBeNull();
  });
});

describe("the approximation, end to end", () => {
  it("under the production posture ONLY the edge-verified channel is admitted", () => {
    // Joins the two halves: the verdict read decides the channel, and the
    // channel decides admission. Neither half alone is the invariant.
    const posture = "require_production_mtls" as const;
    const verified = resolveTransportChannel(
      request(VERIFIED, { [TRANSPORT_SECURITY_HEADER]: "mutual_tls" }),
    );
    expect(verified).not.toBeNull();
    expect(admitTransport(posture, verified as Exclude<typeof verified, null>)).toBeNull();

    const revoked = resolveTransportChannel(
      request({ ...VERIFIED, certRevoked: "1" }, { [TRANSPORT_SECURITY_HEADER]: "mutual_tls" }),
    );
    // A revoked certificate falls back to the bare marker, which the
    // production posture refuses as an unverified CLAIM (501).
    expect(revoked).toBe("unverified_mutual_tls_marker");
    expect(admitTransport(posture, revoked as Exclude<typeof revoked, null>)?.status).toBe(501);
  });

  it("a LOCAL run can never reach the verified channel, and that is correct", () => {
    // The stated consequence of the platform limit: `request.cf` is absent
    // offline, so the production posture is unsatisfiable locally. This test
    // pins that as intended behavior rather than a gap someone should "fix"
    // by trusting the header.
    const local = resolveTransportChannel(
      request(undefined, { [TRANSPORT_SECURITY_HEADER]: "mutual_tls" }),
    );
    expect(local).toBe("unverified_mutual_tls_marker");
    expect(admitTransport("require_production_mtls", "unverified_mutual_tls_marker")?.status).toBe(
      501,
    );
  });
});
