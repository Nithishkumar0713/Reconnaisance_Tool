# Data source

`technologies/*.json` and `categories.json` in this folder are the
technology-fingerprint database from the Wappalyzer browser extension
(v6.12.2), used here to identify web technologies from HTTP responses.

This data is Wappalyzer's own commercial product — as of the version
pulled here it is not under an open-source license. Kept as a plain,
separate data directory (rather than folded into source) specifically so
its origin and status stay easy to find later.

## Local corrections

- `technologies/v.json` — Varnish's `headers.Via` rule captured the HTTP
  protocol-version prefix in the `Via` header (e.g. the "1.1" in
  `Via: 1.1 varnish`) and reported it as Varnish's own software version.
  That prefix is standard `Via` header syntax (protocol-version then
  proxy-name, RFC 7230) and never encodes the proxy's software version —
  verified directly against a real response. Simplified to a presence-only
  check (still detects Varnish, just doesn't claim a version).
