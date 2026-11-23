# wraith

A terminal proxy for macOS that does two things:

- **Inspect** HTTP/HTTPS traffic from a source you choose (the iOS Simulator, one Mac app, one process, or everything). Everything else passes through untouched.
- **Route** chosen domains around your VPN, through the physical network interface.

> Status: pre-alpha. Milestone M0 (spikes) in progress. See [docs/SPEC.md](docs/SPEC.md).

## M0 spikes

Two throwaway programs that test the risky parts of the design on a real Mac.

### 1. Who opened this connection?

```sh
make spike-source            # proxy on 127.0.0.1:9090
```

In another terminal:

```sh
curl -x http://127.0.0.1:9090 https://example.com
```

The spike should print `[mac pid=… curl]`. Then point the Mac's proxy at `127.0.0.1:9090`
(System Settings > Network > Wi-Fi > Details > Proxies, HTTP and HTTPS), open Safari or
your app in a booted simulator, and check that its lines say `[SIMULATOR …]`.
Run with `SPIKE_VERBOSE=1` to see the path and the `launchd_sim` arguments.
Turn the Mac proxy off again when done.

### 2. Can we get around the VPN?

With the VPN connected:

```sh
make spike-bypass HOST=<a site you need outside the VPN> IFACE=en0
```

It connects twice, the normal way and bound to `en0`. The design holds if the bound
connection's local address is your Wi-Fi/Ethernet address and the TLS line says `ok`.

## Build

```sh
make build && ./wraith version
```

## Development

The `make` targets match the CI jobs, so a local run predicts CI:

```sh
make lint    # gofmt, go vet, golangci-lint, forbidden patterns, rules-check
make test    # all tests with the race detector
make build-universal   # arm64 + amd64 binary at dist/wraith
```

Every change goes through a pull request; see the GitHub Flow, Security and Test Strategy
specs linked from [docs/SPEC.md](docs/SPEC.md). Rule IDs (R1.1, S2.3, ...) are listed in
[docs/rules.txt](docs/rules.txt), and tests are named after them.

## License

MIT. See [LICENSE](LICENSE).
