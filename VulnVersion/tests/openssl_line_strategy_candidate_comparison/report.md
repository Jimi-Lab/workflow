# OpenSSL Candidate Line Strategy Pairwise Comparison

Compared variants:

- `major_minor_family_partition`
- `current_plus_merge_mainline_09`

GT is used only through prior simulator final metrics and affected-line impact artifacts.

## Metrics

| variant | lines | avg probes | p95 probes | exact CVEs | TP | FP | FN | precision | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| major_minor_family_partition | 14 | 62.46 | 70.00 | 48/50 | 1795 | 5 | 1 | 0.997222 | 0.999443 | 0.998331 |
| current_plus_merge_mainline_09 | 17 | 69.50 | 79.00 | 48/50 | 1795 | 5 | 1 | 0.997222 | 0.999443 | 0.998331 |

## Probe Difference

- `major_minor_family_partition` saves `7.04` probes/CVE over `current_plus_merge_mainline_09`.
- Relative saving: `10.13%`.
- CVEs where `major_minor_family_partition` uses fewer probes: `48/50`.
- CVEs where metrics differ: `0/50`.

## Risk Difference

- `major_minor_family_partition` review affected CVEs: `32`.
- `current_plus_merge_mainline_09` review affected CVEs: `0`.
- `major_minor_family_partition` unsafe affected CVEs: `0`.
- `current_plus_merge_mainline_09` unsafe affected CVEs: `0`.

## Recommendation

major_minor_family_partition is empirically better on probes and has identical simulator final metrics, but it merges affected 1.x patch-series lines in 32/50 OpenSSL CVEs. current_plus_merge_mainline_09 saves fewer probes but avoids affected patch-series merge risk. For a default paper system, keep current_plus_merge_mainline_09 as the safe first candidate. Use major_minor_family_partition only after manual or real-agent review of the 32 patch-series affected CVEs.
