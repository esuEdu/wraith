# wraith

A terminal proxy for macOS that does two things:

- **Inspect** HTTP and HTTPS from a source you choose: the iOS Simulator, an iPhone or iPad on your Wi-Fi, one Mac app, one process, or everything. Everything else passes through untouched: never decrypted, stored or shown.
- **Route** chosen hosts around your VPN, out through Wi-Fi or Ethernet. If that fails, the connection fails; it is never sent through the VPN instead.

**Website and docs: https://esuedu.github.io/wraith/**

## Install

```sh
brew install esuEdu/tap/wraith
```

macOS 13 or later, Apple Silicon or Intel. Homebrew builds wraith from source on your Mac. To build it yourself: `make build && ./wraith version`.

## Use

```sh
xcrun simctl boot "iPhone 17" && open -a Simulator   # any simulator
wraith start                                          # sets the system proxy, opens the live view
```

wraith puts its CA into each booted simulator, decrypts the simulator's traffic and shows it as it happens. Press `q` (or Ctrl-C) to stop; your proxy settings are restored, even after a crash (`wraith stop` restores them at any time).

```sh
wraith start --source app:Safari         # one Mac app (decrypted only after `wraith ca trust --mac`)
wraith start --device                    # an iPhone or iPad on the same Wi-Fi: scan the QR code
wraith bypass add api.partner.example    # this host skips the VPN
wraith doctor                            # checks the proxy, CA, simulators and bypass
wraith export --har flows.har            # save flows from the running wraith, secrets redacted
```

Everything else, including the configuration file and every command, is in the [documentation](https://esuedu.github.io/wraith/docs/).

## Security

wraith holds a CA that can impersonate any site to the devices that trust it. It is created on your Mac, its key never leaves `~/.wraith/ca/`, and the Mac itself trusts it only if you ask. Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Development

```sh
make lint    # gofmt, go vet, golangci-lint, forbidden patterns, rules-check
make test    # all tests with the race detector
make build-universal   # arm64 + amd64 binary at dist/wraith
```

Every change goes through a pull request; see the GitHub Flow, Security and Test Strategy specs linked from [docs/SPEC.md](docs/SPEC.md). Rule IDs (R1.1, S2.3, ...) are listed in [docs/rules.txt](docs/rules.txt), and tests are named after them. Releases are tagged `vX.Y.Z` on `main`; the [release workflow](.github/workflows/release.yml) publishes them and [esuEdu/homebrew-tap](https://github.com/esuEdu/homebrew-tap) picks them up.

## License

MIT. See [LICENSE](LICENSE).
