# OpenSSL VersionTree Variant Simulator

Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json`.

GT is used only for oracle probe verdicts and final metrics.

| variant | lines | mixed-origin lines | multi-series lines | avg probes | p95 | exact CVEs | FN CVEs | version FN | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| current | 24 | 0 | 9 | 79.86 | 96.00 | 48/50 | 1 | 1 | 0.999443 | 0.998331 |
| generic_major_minor_single_family | 12 | 2 | 12 | 57.18 | 66.00 | 48/50 | 1 | 1 | 0.999443 | 0.998331 |
| major_minor_family_partition | 14 | 0 | 12 | 62.46 | 70.00 | 48/50 | 1 | 1 | 0.999443 | 0.998331 |
| hybrid_patch_series_family_partition | 17 | 0 | 10 | 69.50 | 79.00 | 48/50 | 1 | 1 | 0.999443 | 0.998331 |
| current_plus_merge_mainline_09 | 17 | 0 | 10 | 69.50 | 79.00 | 48/50 | 1 | 1 | 0.999443 | 0.998331 |

Interpretation:

- Mixed-origin lines combine mainline/fips/engine tags and are semantically risky even if GT metrics do not drop.
- Multi-series lines combine multiple maintenance series such as 1.0.0/1.0.1/1.0.2 and require case review.
- A variant is eligible only if it reduces probes without introducing semantic mixing that affects CVE cases.
