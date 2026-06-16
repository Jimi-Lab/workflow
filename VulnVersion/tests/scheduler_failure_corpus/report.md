# Scheduler Failure Corpus

Dataset: `DataSet\BaseDataOrder.json`
Strategy: `transition_scout_s4_expand2_allfixfile_s4`

| metric | value |
| --- | ---: |
| CVEs | 1128 |
| avg probes | 45.05 |
| p50 probes | 39 |
| p95 probes | 92 |
| exact CVEs | 1115/1128 |
| FN CVEs | 9 |
| FP CVEs | 4 |
| avg active lines | 33.01 |
| avg irrelevant active lines | 15.80 |
| irrelevant active % | 47.88% |
| version FN | 10 |
| version FP | 12 |
| precision | 0.999797 |
| recall | 0.999831 |
| F1 | 0.999814 |

## FN Source Counts

{
  "active_line_missed_asbs_or_sparse": 9,
  "skipped_affected_line": 1
}

## Irrelevant Active Lines by Primary Reason

{
  "all_fix_file_scout": 3779,
  "fix_transition_neighbor": 179,
  "nohit_fallback": 1316,
  "positive_neighbor": 3087,
  "scout_stride": 9467
}
