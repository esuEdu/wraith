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
| Failed bypass | Fail closed: refuse the connection and show the error |
| Mac CA | Decrypt Mac apps only after `wraith ca trust --mac` |
| Distribution | Source-build formula in `esuEdu/homebrew-tap` |
| License | MIT |
| Bypass route (M0, #5) | Dial bypassed hosts over IPv6 bound to the physical interface first, then IPv4 bound; refuse if neither works. Bypass DNS: the interface's DHCP resolver, then `2606:4700:4700::1111`, both bound. `doctor` reports v4 and v6 separately. Reason: on the tested VPN, IPv4 sockets bound to en0 get `network is unreachable` while IPv6 is not tunnelled. |
| Source lookup (M0, #5) | Match an app by its **outermost** `.app` bundle (Chrome's traffic comes from a nested helper bundle). WebKit traffic in a simulator comes from `com.apple.WebKit.Networking`, so per-app matching inside a simulator needs more than the process name. |

## Milestones

1. M0 Spikes: process lookup, interface-bound dial through the VPN
2. M1 Pass-through proxy with safe system-proxy set/restore
3. M2 Decryption and simulator CA
4. M3 Source filter
5. M4 VPN bypass and `doctor`
6. M5 TUI and export
7. M6 Release v1.0.0 via Homebrew
