# VulnGraph Judge Boundary v1

Boundary v1 validates raw candidate boundary events for deterministic conversion. It does not output BIC or affected versions.

- cases_total: 7
- parse_ok_count: 7
- contract_ok_count: 7
- repair_retry_count: 0
- selected_boundary_event_count: 7
- lifecycle: raw_boundary_event_accepted

| CVE | parse | contract | selected | uncertain |
|---|---|---:|---:|---:|
| CVE-2020-10251 | fenced_json | True | 0 | 1 |
| CVE-2020-8169 | json | True | 1 | 0 |
| CVE-2020-8177 | fenced_json | True | 2 | 0 |
| CVE-2022-0171 | fenced_json | True | 0 | 1 |
| CVE-2022-0433 | fenced_json | True | 0 | 1 |
| CVE-2020-11869 | fenced_json | True | 2 | 0 |
| CVE-2020-13164 | fenced_json | True | 2 | 0 |
