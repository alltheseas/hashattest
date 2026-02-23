# hashattest

Nostr-based attestation tool for software dependency integrity. Guards against DNS-based supply chain attacks on libraries.

## The Problem

A malicious actor can hijack DNS for a dependency's binary host domain. Developers compiling from that region silently receive a tampered library baked into their app. Even if the final app is hash-verified at distribution time, the compromised dependency is already inside.

Existing tools help — lockfile hash pinning (npm, Cargo, pub), Sigstore provenance, SLSA frameworks — but they share two blind spots:

- **Native/binary dependencies fetched at build time bypass lockfile protections.** When `flutter build apk` triggers Gradle, it downloads native artifacts from Maven Central, Google's Maven repo, and other hosts. These fetches are not covered by `pubspec.lock` hashes. Same applies to pre-built `.so` files, NDK downloads, and binary host dependencies across ecosystems.
- **No system cross-checks dependencies across independent builders in different geographic regions.** A state actor hijacking DNS in one region goes undetected if every builder is in that region.

## The Idea

Use nostr to create a decentralized, cross-builder attestation layer for software dependencies — especially the native/binary fetches that existing tools miss:

1. **Builders** independently download and hash dependencies, publishing signed attestation events to nostr relays
2. **Developers** verify their dependencies against attestations from builders they trust (web-of-trust)
3. **Disagreement = alarm** — if builders in different regions get different hashes for the same dependency, something is wrong

Nostr gives us:
- **Identity without DNS** — builder identity is a keypair, not a domain or email
- **Censorship-resistant distribution** — attestations live on multiple relays, not one server
- **Web-of-trust** — you trust builders your trusted contacts trust, not a central authority
- **Interoperability** — any nostr client can verify attestations, not just one tool

## How It Works

A builder runs hashattest against a project's dependency lockfile:

```
hashattest attest pubspec.lock
```

For each dependency, it:
1. Resolves and downloads the package
2. Computes the SHA-256 hash
3. Compares against the hash recorded in the lockfile
4. Publishes a signed nostr attestation event per dependency

```json
{
  "kind": 30301,
  "tags": [
    ["d", "pub:sqlite3_flutter_libs:0.5.34"],
    ["x", "sha256-of-package-archive"],
    ["source", "https://pub.dev"],
    ["version", "0.5.34"],
    ["platform", "hosted"],
    ["status", "match"],
    ["lockfile_hash", "sha256-from-lockfile"]
  ],
  "content": "",
  "pubkey": "<builder-npub>"
}
```

Consumers query for attestations:

```
hashattest check pubspec.lock
```

This fetches attestation events from relays, filtered by builders in your web-of-trust, and reports:
- Which dependencies have been attested by trusted builders
- Which dependencies have conflicting hashes across builders (potential DNS attack)
- Which dependencies have no attestations yet

**The lockfile bootstrap problem:** If your lockfile was generated on a compromised network, the poisoned hash is already pinned — and builders will attest "match" against it. hashattest addresses this by cross-checking against a second trust anchor: prior attestations from trusted builders for the same package version. If your lockfile hash disagrees with what builders in clean regions previously attested, that's a flag. First-seen hashes with no prior attestations are marked as unverified.

## Nostr Events

hashattest builds on the nostr event model defined in [NIP-82 (Software Applications)](https://github.com/nostr-protocol/nips/pull/1336):

| Kind | NIP-82 Purpose | hashattest Purpose |
|------|---------------|-------------------|
| **32267** | Software Application | The app whose dependencies are being attested |
| **30063** | Software Release | A specific release version with its dependency tree |
| **3063** | Software Asset (`x` = SHA-256 hash) | Individual dependency artifacts |
| **30301** | *(Attestation, per WalletScrutiny)* | Builder's attestation that a dependency hash is correct |

NIP-82's kind 3063 (Software Asset) already carries the `x` tag (SHA-256 hash) that hashattest verifies against. The attestation event (kind 30301) references the asset hash and adds a builder's independent verification.

## Supported Package Managers

Planned support:

- [ ] **pub** (Dart/Flutter) — `pubspec.lock`
- [ ] **npm** (Node.js) — `package-lock.json`
- [ ] **Cargo** (Rust) — `Cargo.lock`
- [ ] **pip** (Python) — requirements with hashes
- [ ] **Gradle/Maven** (Java/Android) — `verification-metadata.xml`
- [ ] **Go modules** — `go.sum`

## Relationship to Existing Work

- **[NIP-82](https://github.com/nostr-protocol/nips/pull/1336)** — Nostr event kinds for software applications, releases, and assets. hashattest uses these as the foundation for dependency identity and hash verification.
- **[Zapstore](https://github.com/zapstore/zapstore)** — Nostr-based app store that verifies app hashes at install time. hashattest extends this concept from apps to libraries.
- **[WalletScrutiny](https://walletscrutiny.com)** — Reproducible build attestations for Bitcoin wallets using nostr events (kind 30301). hashattest builds on their [attestation format](https://gitlab.com/walletscrutiny/walletScrutinyCom/-/blob/master/docs/verifications.md).
- **[Sigstore](https://sigstore.dev)** — Transparency logs for software signing. Complementary — sigstore proves who signed, hashattest proves what was built.
- **[SLSA](https://slsa.dev)** — Supply chain security framework. hashattest can help projects achieve SLSA levels by providing verifiable build provenance.

## Why Not Just Reproducible Builds?

Reproducible builds verify **source → binary**. hashattest verifies **dependency downloads are untampered**. They're complementary.

If a builder's DNS is hijacked and they download a poisoned `ring` or `libcrux`, their build is still "reproducible" — same poisoned input, same poisoned output, every time. Reproducible builds only catch this if multiple builders in different regions compare results. That's what hashattest does, but at the dependency level — catching the problem *before* it enters the build. Cheaper, easier, and doesn't require the entire ecosystem to achieve build determinism (which <10% of F-Droid apps have managed).

## Geographic Diversity

Detection depends on having builders in different DNS regions. Each attestation event includes a geohash tag (`g`) per [NIP-52](https://github.com/nostr-protocol/nips/blob/master/52.md), so consumers can verify geographic diversity of their attestation sources.

**How many regions matter?**

A DNS attack is regional — a state actor controls DNS within their jurisdiction. Detection requires at least one builder inside the affected region and one outside it. The more regions you cover, the harder the attack becomes:

| Regions hijacked | Builders in 3 regions | Builders in 5 regions | Builders in 7 regions |
|-----------------|----------------------|----------------------|----------------------|
| 1 (likely) | Detected | Detected | Detected |
| 2 (coordinated) | Detected | Detected | Detected |
| 3 (very unlikely) | Undetected | Detected | Detected |

Each additional region the attacker must compromise is a massive escalation in cost and coordination. Hijacking 1 region (e.g., China's Great Firewall) is demonstrated capability. Hijacking 3+ independent regions simultaneously requires coordination between hostile state actors — a qualitatively different threat.

**Recommendation: minimum 3 geo-diverse regions.** This catches any single-region attack and most coordinated attacks. 5+ regions is ideal.

**Suggested builder regions:**
1. North America
2. Western Europe
3. East Asia (outside China)
4. Behind the Great Firewall (where attacks are most likely)
5. South America
6. Southeast Asia
7. Africa / Middle East

## Trust

Anyone can publish attestation events. That's the point — but it also means malicious actors can publish false ones.

The defense is **web-of-trust filtering**. When you run `hashattest check`, you don't see all attestations — only attestations from builders in your web-of-trust (people you follow, and people they follow). A malicious attestor outside your trust graph is invisible. Same model nostr uses to filter spam.

Builders build reputation over time. Accurate attestations earn trust. Inaccurate ones get you unfollowed.

## Incentives

**On-demand: DVMs** — A developer needs attestations now. They post a [DVM](https://github.com/nostr-protocol/nips/blob/master/90.md) job request ("attest these 47 dependencies"), builder DVMs pick it up, do the work, get paid in sats. Clear exchange — pay upfront, get attestations back.

**Ongoing: Sponsorship** — A company or project pays a builder to attest their dependency tree on a schedule (weekly, before each release, on every lockfile change). Builders accept Lightning or fiat via [payments-rs](https://github.com/v0l/payments-rs). Predictable income for builders, predictable coverage for projects.

## Status

Early stage. This project grew from a discussion about DNS-based supply chain attacks on nostr client dependencies ([context](https://github.com/zapstore/zapstore/issues/23)).

## License

MIT
