# Athena Public Vulnerability Disclosures

Public vulnerability disclosures from [Athena](https://www.chainguard.dev/athena), an industry coalition coordinating the discovery, remediation, and disclosure of AI-discovered vulnerabilities in open source software.

This repository contains the initial set of advisories being disclosed publicly. Each advisory in [`advisories/`](advisories/) is identified by a Chainguard identifier (CGP) and includes:

- **`CGP-<id>.json`**: the advisory in [OSV format](https://ossf.github.io/osv-schema/), with the vulnerability details.
- **`CGP-<id>-<purl>.patch`**: a `git format-patch` fix for an associated vulnerable version of the package, applicable to the upstream source at that version.

## Layout

```
advisories/
  CGP-3p49-8jjq-wc72/
    CGP-3p49-8jjq-wc72.json
    CGP-3p49-8jjq-wc72-pkg:maven_commons-validator_commons-validator@1.5.1.patch
  ...
```

## Learn more

See the [Athena page](https://www.chainguard.dev/athena) for how findings are discovered, triaged, and remediated ahead of disclosure.
