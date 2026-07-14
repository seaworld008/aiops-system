# Host Identity Attestor v1

Status: confirmed private production contract for Phase 5 AWX enrollment and diagnostics.

This contract defines when the system may call a Host identity key TPM-sealed, platform-attested and hardware-bound. It does not misstate a seed released to measured process memory as a hardware-native non-exportable signing key. A software key, fixture key, unverified vTPM clone or unsigned local agent is only continuity evidence and cannot open AWX diagnostic admission.

## 1. Deployment and support gate

`host-attestor` is a fixed signed Go service deployed on the managed Host. Linux and Windows use the same protocol and Ed25519 challenge key, but a production Asset is eligible only when one release-approved profile verifies:

```text
LINUX_TPM2_SEALED_ED25519_PLATFORM_V1
WINDOWS_TPM2_SEALED_ED25519_PLATFORM_V1
```

The Ed25519 seed is generated inside the attestor, encrypted under a TPM-sealed wrapping key, released only to the measured service identity, held briefly in locked process memory for signing, zeroized, and never returned by an API. Because plaintext exists inside that measured process, the signed attestor binary、process isolation、debug/ptrace/core-dump denial and memory-zeroization path are explicit TCB and must be verified；the contract claims sealed-at-rest and API non-disclosure, not physical non-exportability against a compromised attestor process. Linux uses reviewed TPM2/TSS sealing and Windows uses the Microsoft Platform Crypto Provider for the sealing/wrapping key. The platform statement must also bind a release-approved bare-metal or VM instance-attestation identity; a vTPM without clone-resistant platform identity is unsupported. Unsupported OS/TPM/firmware/hypervisor/cloud/boot state, missing EK/AK chain, any seed export/debug/core-dump path or software fallback returns `UNAVAILABLE`.

The compatibility matrix is an immutable signed release artifact keyed by OS family/version, TPM manufacturer/firmware, secure/measured boot profile, hypervisor/cloud attestation provider and attestor build digest. Each Provider/Capability is gated independently; Host Probe support does not imply AWX attestor support.

## 2. Fixed local transport

The signed AWX module calls only `https://127.0.0.1:9443/v1/attest` over TLS 1.3 mTLS. The attestor binds loopback only, disables proxy/redirect/cookie/compression/keepalive, requires a purpose-specific client SPIFFE certificate (`.../awx-enrollment-module` or `.../awx-diagnostic-module`), and caps body/time at 4 KiB/2 seconds. Network namespace/firewall denies non-loopback access. Client certificates, endpoint and CA are fixed inside the signed AWX Project/Credential release closure and never enter Task/model/Runner payloads.

Request is RFC 8785, `additionalProperties:false`, and has exactly:

```text
challenge_digest
expires_at
module_build_digest
nonce
purpose
schema
```

`schema=host-identity-attestor-request.v1`; purpose is enrollment or diagnostic; nonce/challenge are lowercase 64-hex; expiry is UTC microsecond, in the future and ≤30 seconds. The service rejects replay using a TPM-backed monotonic/replay window plus an in-memory bounded nonce cache; restart changes boot measurement and requires fresh proof.

## 3. Attestation response

The response is strict RFC 8785 `host-identity-attestor-response.v1`, ≤60 KiB, with exactly:

```text
attestation_profile
attestation_statement
attestation_statement_sha256
attestor_build_digest
attestor_key_id
challenge_digest
expires_at
identity_algorithm
identity_key
identity_signature
module_build_digest
nonce
platform_instance_digest
schema
workload_measurement_digest
```

`identity_algorithm=ED25519_HOST_ATTESTATION_V1`; key/signature are raw lowercase hex. The signature is over the caller's exact framed challenge. `attestation_statement` is a canonical signed envelope containing TPM quote nonce, EK/AK chain digests, PCR selection/values, secure/measured-boot result, sealed-key public metadata/SPKI binding, boot counter, platform instance attestation/token digest, validity and provider profile. Its SHA, platform/workload/build/profile/key IDs are independently bound into enrollment fact/artifact and Runtime trust closure. Private platform tokens/certificates remain in the private enrollment Attempt, never public/Audit/model/Task.

Verification uses release-pinned manufacturer/platform roots, revocation data, compatibility matrix and attestor image/SBOM/signature. It checks nonce/freshness, chain, quote, expected PCR/workload measurement, platform instance identity, sealed wrapping-key/SPKI binding, Ed25519 challenge, key status and anti-replay. Any unknown/revoked/stale/clone/mismatched evidence rejects before identity publication.

## 4. Rotation, revocation and provenance

Attestor and signed AWX modules are built reproducibly; OCI/package digest, source revision, dependency lock, SBOM, signature, expected workload measurement and module build digest are one release artifact. The enrollment authority signs those digests. Production has no development key or unsigned module fallback.

Key rotation creates a new attestor key ID/platform statement and requires a complete new enrollment/Runtime/contract revision. Emergency key, build, platform-root or compatibility revocation closes affected live admission through the Runtime trust gate before new work. Old public verification material and private statements remain through audit retention; old private keys are destroyed after drain. A key may rotate for the same exact Integration/inventory/Host/Asset binding, but cannot bind another Asset/Host.

## 5. Required proof

Real tests cover Linux and Windows supported profiles, physical/approved VM identity, reboot, service upgrade, key rotation and revocation. Negative tests include software key, copied sealed blob/vTPM, wrong platform instance, altered PCR/boot/module, expired/replayed nonce, wrong client SPIFFE, non-loopback access, debug/export endpoint, bad EK/AK chain and revoked root. Any required test Skip or unavailable attestation dependency keeps that platform/provider/capability `UNAVAILABLE`; test fixtures can never produce production acceptance.
