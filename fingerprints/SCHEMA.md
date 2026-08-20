# Fingerprint schema

One YAML file per vendor in `fingerprints/`. These are the source of truth.
`tools/build_fingerprints.py` compiles them to `edgeprint/data/fingerprints.json`,
which is what the engine loads — so the runtime keeps zero dependencies while
contributors get a format with comments. CI fails if the two drift apart.

```yaml
vendor: Imperva/Incapsula        # display name, must be unique
layers: [waf]                    # what a match proves: cdn | waf | bot | ddos
references:                      # public documentation for these signals
  - https://docs.imperva.com/...

signals:
  - type: header                 # header | cookie | body
    key: x-iinfo                 # header name; trailing * is a prefix match
    contains: ""                 # substring the value must hold; "" = presence only
    weight: 0.25
    layer: waf                   # optional: this signal proves more than the vendor default
    source: edgeprint            # edgeprint | wafw00f | identywaf | cdncheck | ...
    verified_against: tests/fixtures/positive/imperva_200.txt

  - type: cookie
    name_prefix: incap_ses       # matched against parsed cookie NAMES, never values
    weight: 0.20

  - type: body
    contains: powered by imperva # lowercase; matched against the body excerpt
    weight: 0.15
```

## Rules

**Weights.** Defaults are `header: 0.25`, `cookie: 0.20`, `body: 0.15`. These are
hand-assigned placeholders, not measurements — replacing them with likelihood
ratios derived from a labelled corpus is the point of the roadmap. Do not tune
them by intuition to make a case pass.

**Layers.** `layers` is what a match proves, not what the vendor sells. Cloudflare
is `[cdn]`: `cf-ray` shows the CDN served the response and says nothing about
whether filtering is enabled. Signals that prove more carry their own `layer` —
`cf-mitigated` is `waf` because it only appears when filtering acted.

**Generic phrases are not vendor signals.** `request blocked`, `access denied`,
`forbidden` and similar belong to `BLOCK_PATTERNS` in the analyzer, which only
score once a vendor is independently identified. Listing such a phrase as a
vendor `body` signal lets it corroborate itself into a false positive; this
happened and is regression-tested.

**Cookies match names.** `name_prefix` is compared against parsed cookie names.
Never write a needle short enough to appear inside an opaque session value.

**Every signal needs a fixture.** `verified_against` must point at a capture in
`tests/fixtures/`. A signal that has never matched a real response is how a dead
Akamai fingerprint shipped for months.

**`source` records provenance.** Imported entries must name the upstream project;
its license and attribution are recorded in `NOTICE`. WhatWaf (GPL) and JA4S
(FoxIO License 1.1) are excluded — see `NOTICE` for why.
