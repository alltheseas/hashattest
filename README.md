# libwatch

Nostr-based attestation tool for software dependency integrity. Guards against DNS-based supply chain attacks on libraries.

## The Problem

A malicious actor can hijack DNS for a dependency's binary host domain. Developers compiling from that region silently receive a tampered library baked into their app. Even if the final app is hash-verified at distribution time, the compromised dependency is already inside.

Existing tools help — lockfile hash pinning (npm, Cargo, pub), Sigstore provenance, SLSA frameworks — but they share two blind spots:

- **Native/binary dependencies fetched at build time bypass lockfile protections.** When `flutter build apk` triggers Gradle, it downloads native artifacts from Maven Central, Google's Maven repo, and other hosts. These fetches are not covered by `pubspec.lock` hashes. Same applies to pre-built `.so` files, NDK downloads, and binary host dependencies across ecosystems.
- **No system cross-checks dependencies across independent builders in different geographic regions.** A state actor hijacking DNS in one region goes undetected if every builder is in that region.

## Why libwatch? A History of Library Attacks

This isn't theoretical. Supply chain attacks on libraries are accelerating — 3x increase in the past year alone.

### DNS & Network-Level Attacks (what libwatch directly detects)

| Attack | Year | What happened | Regions affected |
|--------|------|--------------|-----------------|
| **PlushDaemon / EdgeStepper** | 2018–present | China-linked APT compromises routers, redirects DNS queries for software update domains to attacker-controlled servers. Active for 7+ years before public disclosure. | US, Taiwan, South Korea, New Zealand, Cambodia |
| **Sea Turtle** | 2017–2023 | State-sponsored group hijacked DNS registrars to redirect victims to credential-harvesting servers. Targeted IT and telecom infrastructure. | Europe (Netherlands), Middle East, North Africa |
| **MavenGate** | 2024 | 18% of Java/Android library domains on Maven Central had expired — attackers could purchase them and inject malicious code into Gradle/Maven builds. Most apps don't verify dependency signatures. | Global — Google, Facebook, Amazon, Microsoft, Netflix affected |
| **Polyfill.io** | 2024 | Attackers acquired the domain of a widely-used JavaScript CDN library, then altered the hosted script to redirect users to malicious sites. | Global — 385,000 websites across all regions |

### Build System & Dependency Compromise (broader context)

These attacks poison the package at the source — every region downloads the same malicious artifact. libwatch's cross-region hash comparison alone doesn't catch these (see [Limitations](#limitations)), but they show why dependency integrity matters.

| Attack | Year | What happened | Regions affected |
|--------|------|--------------|-----------------|
| **XZ Utils backdoor** | 2024 | State actor spent 3 years social-engineering maintainer access to a core Linux compression library, then injected a backdoor giving remote root via SSH. CVSS 10.0. Caught by accident (500ms latency anomaly). | Global — every Linux distribution |
| **SolarWinds / SUNBURST** | 2020 | State actor injected malware into SolarWinds' build system — not in source code, only in compiled binaries distributed via updates. 18,000 orgs compromised. | US, Europe, Australia, Japan |
| **Lazarus Group** | 2024–present | 234+ malicious npm and PyPI packages mimicking trusted developer tools. Japan's government formally attributed PyPI attacks to North Korea. | Japan, US, Europe, South Korea, Australia |
| **Codecov** | 2021 | Attackers modified a CI script to exfiltrate secrets from thousands of build pipelines. Undetected for 2 months — caught when a customer noticed the script hash didn't match GitHub. | US, Europe, Brazil, global CI/CD pipelines |
| **event-stream** | 2018 | Volunteer took over maintenance of npm package (1.5M weekly downloads), injected encrypted malware targeting cryptocurrency wallets. | Global — all npm users |
| **Shai-Hulud** | 2025 | First self-propagating npm worm — harvested maintainer tokens to automatically push malicious versions of other packages. 500+ versions before takedown. | Global — all npm users |
| **Prettier/ESLint hijack** | 2025 | Phished maintainer accounts of two of npm's most popular packages, injected info-stealers exfiltrating encryption keys and auth tokens. 2 billion weekly downloads affected. | US, Europe, Japan, Brazil, global |
| **PyPI mass poisoning** | 2024 | 500+ typosquatted packages forced PyPI to suspend all new registrations. Targeted crypto wallets and browser credentials. | Global — all PyPI users |
| **F5 Networks breach** | 2025 | China-linked group stole BIG-IP source code including encryption keys, creating risk of future malicious injection into global network infrastructure. | US, Europe, Japan, Australia, Africa — F5 runs everywhere |

**The pattern:** No region is safe. State-sponsored DNS attacks target specific regions (East Asia, Europe, Middle East), while dependency poisoning attacks (npm, PyPI, Maven) hit every developer globally. These are different attack vectors that require different defenses — libwatch addresses the first directly, and complements other tools for the second.

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

A builder runs libwatch against a project's dependency lockfile:

```
libwatch attest pubspec.lock
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
libwatch check pubspec.lock
```

This fetches attestation events from relays, filtered by builders in your web-of-trust, and reports:
- Which dependencies have been attested by trusted builders
- Which dependencies have conflicting hashes across builders (potential DNS attack)
- Which dependencies have no attestations yet

**The lockfile bootstrap problem:** If your lockfile was generated on a compromised network, the poisoned hash is already pinned — and builders will attest "match" against it. libwatch addresses this by cross-checking against a second trust anchor: prior attestations from trusted builders for the same package version. If your lockfile hash disagrees with what builders in clean regions previously attested, that's a flag. First-seen hashes with no prior attestations are marked as unverified.

## Nostr Events

libwatch builds on the nostr event model defined in [NIP-82 (Software Applications)](https://github.com/nostr-protocol/nips/pull/1336):

| Kind | NIP-82 Purpose | libwatch Purpose |
|------|---------------|-------------------|
| **32267** | Software Application | The app whose dependencies are being attested |
| **30063** | Software Release | A specific release version with its dependency tree |
| **3063** | Software Asset (`x` = SHA-256 hash) | Individual dependency artifacts |
| **30301** | *(Attestation, per WalletScrutiny)* | Builder's attestation that a dependency hash is correct |

NIP-82's kind 3063 (Software Asset) already carries the `x` tag (SHA-256 hash) that libwatch verifies against. The attestation event (kind 30301) references the asset hash and adds a builder's independent verification.

## Supported Package Managers

Planned support:

- [ ] **pub** (Dart/Flutter) — `pubspec.lock`
- [ ] **npm** (Node.js) — `package-lock.json`
- [ ] **Cargo** (Rust) — `Cargo.lock`
- [ ] **pip** (Python) — requirements with hashes
- [ ] **Gradle/Maven** (Java/Android) — `verification-metadata.xml`
- [ ] **Go modules** — `go.sum`

## Relationship to Existing Work

- **[NIP-82](https://github.com/nostr-protocol/nips/pull/1336)** — Nostr event kinds for software applications, releases, and assets. libwatch uses these as the foundation for dependency identity and hash verification.
- **[Zapstore](https://github.com/zapstore/zapstore)** — Nostr-based app store that verifies app hashes at install time. libwatch extends this concept from apps to libraries.
- **[WalletScrutiny](https://walletscrutiny.com)** — Reproducible build attestations for Bitcoin wallets using nostr events (kind 30301). libwatch builds on their [attestation format](https://gitlab.com/walletscrutiny/walletScrutinyCom/-/blob/master/docs/verifications.md).
- **[Sigstore](https://sigstore.dev)** — Transparency logs for software signing. Complementary — sigstore proves who signed, libwatch proves what was built.
- **[SLSA](https://slsa.dev)** — Supply chain security framework. libwatch can help projects achieve SLSA levels by providing verifiable build provenance.

## Why Not Just Reproducible Builds?

Reproducible builds verify **source → binary**. libwatch verifies **dependency downloads are untampered**. They're complementary.

If a builder's DNS is hijacked and they download a poisoned `ring` or `libcrux`, their build is still "reproducible" — same poisoned input, same poisoned output, every time. Reproducible builds only catch this if multiple builders in different regions compare results. That's what libwatch does, but at the dependency level — catching the problem *before* it enters the build. Cheaper, easier, and doesn't require the entire ecosystem to achieve build determinism (which <10% of F-Droid apps have managed).

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

The defense is **web-of-trust filtering**. When you run `libwatch check`, you don't see all attestations — only attestations from builders in your web-of-trust (people you follow, and people they follow). A malicious attestor outside your trust graph is invisible. Same model nostr uses to filter spam.

Builders build reputation over time. Accurate attestations earn trust. Inaccurate ones get you unfollowed.

## Incentives

**On-demand: DVMs** — A developer needs attestations now. They post a [DVM](https://github.com/nostr-protocol/nips/blob/master/90.md) job request ("attest these 47 dependencies"), builder DVMs pick it up, do the work, get paid in sats. Clear exchange — pay upfront, get attestations back.

**Ongoing: Sponsorship** — A company or project pays a builder to attest their dependency tree on a schedule (weekly, before each release, on every lockfile change). Builders accept Lightning or fiat via [payments-rs](https://github.com/v0l/payments-rs). Predictable income for builders, predictable coverage for projects.

## Limitations

### What libwatch catches

**Regional DNS/network attacks** — where builders in different regions get different binaries for the same dependency. This is libwatch's core strength and the blind spot that existing tools (Sigstore, SLSA, lockfile pinning) all share.

### What libwatch does NOT catch

**Global registry poisoning** — if an attacker compromises a maintainer account and publishes a malicious version to npm/PyPI/crates.io, every builder in every region downloads the same poisoned package. All hashes match. Cross-region comparison produces no disagreement.

Attacks in this category:
- **Maintainer account takeover** (event-stream, Prettier/ESLint, Shai-Hulud) — malicious new versions, not modified existing ones
- **Typosquatting** (PyPI mass poisoning) — different package name entirely
- **Social-engineering to maintainer** (XZ Utils) — malicious code baked into release artifacts
- **Malicious source commits** — if the attack is in the source repo itself, even source-to-archive verification shows a clean match

These require different defenses: Sigstore/transparency logs, registry-level 2FA enforcement, code review, and reproducible builds.

### Known design gaps (open problems)

**Nostr relays can show different data to different people.** Unlike Go's [checksum database](https://sum.golang.org) or [Certificate Transparency](https://certificate.transparency.dev/), nostr relays have no consistency guarantees. A relay can hide conflicting attestations, drop old events, or serve different history depending on who's asking. If libwatch says "this hash has been stable for 6 months," that claim is only as trustworthy as the relays you queried — not a cryptographic fact. Querying multiple relays reduces this risk but does not eliminate it. Solving this likely requires witness cosigning, consistency proofs, or integration with existing transparency logs like [Rekor](https://docs.sigstore.dev/logging/overview/) or [Go sumdb](https://go.dev/ref/mod#checksum-database).

**First-seen anchoring is vulnerable to poisoning.** If an attacker controls the network when the first builder hashes a package, the "anchor hash" is permanently poisoned. Trust-on-first-use (TOFU) alone is insufficient. Threshold anchoring — requiring k-of-n independent builders to agree on a first-seen hash — is necessary but not yet designed.

**Builder independence is unproven.** Web-of-trust filtering prevents unknown attestors from influencing you, but doesn't prove that 5 "trusted builders" aren't 5 keys controlled by one operator. Anti-Sybil measures are needed: ASN/geo diversity requirements, key age, operator identity verification, reputation decay.

**Absence is ambiguous.** "A builder stopped attesting" could mean the package was compromised, or the relay dropped the event, or the builder went offline. Without signed expiry semantics (like [TUF](https://theupdateframework.io/)'s timestamp role), you cannot distinguish attack from noise.

**Artifact identity is underspecified.** A dependency can have different artifacts per platform, classifier, and file type. Canonical coordinates (registry, name, version, filename, platform, algorithm, digest) must be precisely defined per ecosystem to avoid false conflicts.

**Privacy leakage.** Publishing dependency attestations reveals a project's full technology stack and patch cadence. No mitigation is currently described for projects that consider their dependency choices sensitive.

## Roadmap

Two research directions could extend libwatch beyond regional attacks. Both are validated by prior art but have unsolved design problems on nostr.

### Path 1: Temporal attestation (hash-over-time)

If trusted builders attested `package@1.2.3` with hash X before an attack, and the registry later serves hash Y for the same version, the change is detectable. This catches in-place modifications like [Codecov](https://about.codecov.io/apr-2021-post-mortem/) (CI script modified at same URL, undetected for 2 months) and [Polyfill.io](https://sansec.io/research/polyfill-supply-chain-attack) (domain acquired, content changed).

**Prior art:** [Go checksum database](https://go.dev/ref/mod#checksum-database), [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/), [Trustix](https://github.com/nix-community/trustix)/[Lila](https://github.com/nix-community/lila) (Nix ecosystem, M-of-N builder consensus with Merkle tree logs).

**Does NOT catch:** Malicious new versions (strong_password, event-stream) — these are different version numbers, not in-place mutations. Also does not help if no builder recorded the legitimate hash before the poisoning.

**Open design problems:** Nostr relay equivocation (no append-only guarantees), quorum policy (how many builders must agree before an anchor is trusted), interop with existing logs (SumDB, Rekor) vs. duplicating trust roots.

### Path 2: Source-to-archive verification

Builders verify that published package archives match the source code in the linked repository. Would have caught [XZ Utils](https://en.wikipedia.org/wiki/XZ_Utils_backdoor) (backdoor only in release tarball, not git), [SolarWinds](https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know) (malware injected at build, not in source), and [event-stream](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident) (published tarball contained code not in git).

**Prior art:** [Google OSS Rebuild](https://github.com/google/oss-rebuild) (launched July 2025, ~9,500+ attestations across npm/PyPI/crates.io using semantic reproducibility), [Reproducible Central](https://github.com/jvm-repo-rebuild/reproducible-central) (Maven), [cargo-goggles](https://github.com/M4SS-Code/cargo-goggles) (Rust).

**Reproducibility by ecosystem** ([ICSE 2025, 4,000 packages per ecosystem](https://ieeexplore.ieee.org/document/11029905/)):

| Ecosystem | Out-of-box reproducible | With infrastructure fixes |
|-----------|------------------------|--------------------------|
| Cargo (Rust) | ~100% | ~100% |
| npm (JavaScript) | ~100% | ~100% |
| Maven (Java) | ~2% | ~93% |
| PyPI (Python) | ~12% | Higher with tool patches |

**Does NOT catch:** Attacks where malicious code is genuinely in the source repository. Rebuild proves correspondence between source and artifact — it does not prove the source is safe.

**Open design problems:** Exact verification object per ecosystem (archive bytes vs. extracted tree vs. built artifact), coverage gaps (~20-30% of packages lack valid source links, varying heavily by ecosystem and popularity tier), privacy implications of publishing verification results.

## Status

Early stage. This project grew from a discussion about DNS-based supply chain attacks on nostr client dependencies ([context](https://github.com/zapstore/zapstore/issues/23)).

## License

MIT
