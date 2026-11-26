# wraith specification

The full, living specification (business rules R1–R7, architecture, connection flow,
CLI, config, testing, release, milestones, risks) is kept here:

https://claude.ai/artifact/UkCjGagwZaBHaMx2P3fVF8

Companion specs:

| Spec | Covers | Link |
| --- | --- | --- |
| GitHub Flow | Branches, commits, PRs, CI workflows, labels, releases, bootstrap | https://claude.ai/artifact/Hkjha8ZBnUtCgs2U5nd8ky |
| Security | Threat model, security rules S1–S6, checks, vulnerability reporting | https://claude.ai/artifact/CLYXoMfXK9MQ16pqhpy3GE |
| Test Strategy | Test levels, conventions, seams, rule traceability, simulator and manual tests | https://claude.ai/artifact/QbJCQVnEPMi7JmbkGTB2QV |

## Decisions

| Topic | Decision |
| --- | --- |
| Name | `wraith` |
| Interface | Terminal only: live TUI plus a plain log mode |
| Language | Go |
| Failed bypass | Fail closed: refuse the connection and show the error. (The bypass was removed in v2.0.0.) |
| Mac CA | Decrypt Mac apps only after `wraith ca trust --mac` |
| Distribution | Source-build formula in `esuEdu/homebrew-tap` |
| License | MIT |
| Release secret (M6) | None. The release workflow only publishes the GitHub release (tarball, checksums.txt, provenance attestation); esuEdu/homebrew-tap updates its own formula from the latest release, checking both, with its own token. Replaces the GitHub App token of S6.4. |
| Decryption default (M3) | On by default for the capture source; `--no-decrypt` turns it off. Mac apps are decrypted only when the Mac trusts the CA. |
| Bypass route (M0, #5) | Dial bypassed hosts over IPv6 bound to the physical interface first, then IPv4 bound; refuse if neither works. Bypass DNS: the interface's DHCP resolver, then `2606:4700:4700::1111`, both bound. `doctor` reports v4 and v6 separately. Reason: on the tested VPN, IPv4 sockets bound to en0 get `network is unreachable` while IPv6 is not tunnelled. |
| VPN bypass removed (v2.0.0) | Deprecated in v1.6, removed in v2.0.0: wraith only inspects. A bound dial cannot beat VPNs that enforce routes, and on the tested VPN it worked only because IPv6 is not tunnelled. Rules R3.1–R3.5 and S2.5 are gone; an old `bypass:` list is ignored with a warning; interface detection stays for `--device`; the live view's route column became `via` (a mock or a slow-network profile). |
| Physical devices (#55) | `wraith start --device` also listens on the Mac's private Wi-Fi address, never on every address. Rule S2.6: a peer off the Mac's network is refused before a byte is read; one on it may only open the setup page until it opens the link from the QR code, whose key is new each run (or is named with `--allow-device`). Allowed devices are remembered by IP address and network in `devices.json`, for 30 days unseen: macOS hides the network's hardware addresses from wraith. Without `--device`, S2.1 holds: loopback only. |
| Rejected certificates (#55) | A client's TLS alert during the handshake is a rejection (R2.4); a client that just closes is not. The host is passed through for that client for 30 s, then 5 min, then the session, so a device that trusts the CA a moment later is decrypted again. |
| Source lookup (M0, #5) | Match an app by its **outermost** `.app` bundle (Chrome's traffic comes from a nested helper bundle). WebKit traffic in a simulator comes from `com.apple.WebKit.Networking`, so per-app matching inside a simulator needs more than the process name. |

## Milestones

1. M0 Spikes: process lookup, interface-bound dial through the VPN
2. M1 Pass-through proxy with safe system-proxy set/restore
3. M2 Decryption and simulator CA
4. M3 Source filter
5. M4 VPN bypass and `doctor`
6. M5 TUI and export
7. M6 Release v1.0.0 via Homebrew
