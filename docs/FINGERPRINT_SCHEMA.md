# Fingerprint schema

One JSON file per vendor in `edgeprint/data/fingerprints/`. These are read
directly at import — there is no build step and no compiled artifact, so what you
review is what ships. JSON rather than YAML keeps the runtime at zero
dependencies; use `notes` where you would have written a comment.

```jsonc
{
  "vendor": "Imperva/Incapsula",     // display name, must be unique
  "layers": ["waf"],                 // what a match proves: cdn | waf | bot | ddos
  "references": ["https://docs.imperva.com/..."],
  "signals": [
    {
      "type": "header",              // header | cookie | body
      "key": "x-iinfo",              // header name; trailing * is a prefix match
      "contains": "",                // substring the value must hold; "" = presence only
      "weight": 0.25,
      "layer": "waf",                // optional: proves more than the vendor default
      "source": "edgeprint",         // edgeprint | wafw00f | identywaf | cdncheck | ...
      "verified_against": "tests/fixtures/positive/imperva_200.txt",
      "notes": "why this signal is trustworthy"
    },
    {
      "type": "cookie",
      "name_prefix": "incap_ses",    // matched against parsed cookie NAMES, never values
      "weight": 0.20,
      "source": "edgeprint",
      "verified_against": "tests/fixtures/positive/imperva_200.txt"
    },
    {
      "type": "body",
      "contains": "powered by imperva",   // lowercase; matched against the body excerpt
      "weight": 0.15,
      "source": "edgeprint",
      "verified_against": "tests/fixtures/positive/imperva_200.txt"
    }
  ]
}
```

(The `//` comments above are illustration only — the files are strict JSON.)

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

**Every signal needs a fixture it actually matches.** `verified_against` names a
capture in `tests/fixtures/`, and the test suite replays the signal against it
through the same matchers the analyzer uses. Merely pointing at an existing file
is not enough — an earlier version of this rule checked only that the path
existed, and 31 of 60 signals cited a capture they did not match.

Block-page and challenge-page signals belong with a block-page capture; most
vendors therefore have both a normal-response fixture and a blocked one.

All of these rules are enforced by `tests/test_fingerprints.py`, so `pytest`
rejects a bad fingerprint without needing CI.

**`source` records provenance.** Imported entries must name the upstream project;
its license and attribution are recorded in `NOTICE`. WhatWaf (GPL) and JA4S
(FoxIO License 1.1) are excluded — see `NOTICE` for why.
