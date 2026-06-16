# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `30`

## Overall

- avg candidate tags/CVE: `51.5`
- median candidate tags/CVE: `51.0`
- max candidate tags/CVE: `60`
- avg GT coverage rate: `0.385`
- full GT coverage CVEs: `6/30`
- coverage miss CVEs: `24`
- frontier statuses: `{'unknown': 126, 'known': 12, 'probe_small': 36, 'pruned': 36}`

## Per Repo

### httpd
- CVEs: `30`
- avg/median/max candidates: `51.5` / `51.0` / `60`
- avg GT coverage: `0.385`
- full coverage CVEs: `6/30`
- frontier statuses: `{'unknown': 126, 'known': 12, 'probe_small': 36, 'pruned': 36}`
- most expensive CVEs:
  - `CVE-2022-30556`: candidates=`60`, gt=`47`, coverage=`1.000`
  - `CVE-2022-31813`: candidates=`60`, gt=`49`, coverage=`1.000`
  - `CVE-2021-33193`: candidates=`55`, gt=`32`, coverage=`1.000`
  - `CVE-2021-34798`: candidates=`55`, gt=`63`, coverage=`0.810`
  - `CVE-2021-39275`: candidates=`55`, gt=`182`, coverage=`0.302`
- worst coverage misses:
  - `CVE-2022-22719`: covered=`0/48`, candidates=`51`, unmapped=`['2.4.10', '2.4.20', '2.4.40', '2.4.51', '2.4.32']`
  - `CVE-2021-31618`: covered=`0/30`, candidates=`51`, unmapped=`['2.4.20', '2.4.40', '2.4.32', '2.4.34', '2.4.41']`
  - `CVE-2021-36160`: covered=`0/19`, candidates=`51`, unmapped=`['2.4.40', '2.4.32', '2.4.34', '2.4.41', '2.4.48']`
  - `CVE-2021-41773`: covered=`0/1`, candidates=`51`, unmapped=`['2.4.49']`
  - `CVE-2021-44790`: covered=`0/1`, candidates=`51`, unmapped=`['2.4.51']`

## Top Expensive CVEs

- `httpd/CVE-2022-30556`: candidates=`60`, gt=`47`, coverage=`1.000`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2022-31813`: candidates=`60`, gt=`49`, coverage=`1.000`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2021-33193`: candidates=`55`, gt=`32`, coverage=`1.000`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2021-34798`: candidates=`55`, gt=`63`, coverage=`0.810`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2021-39275`: candidates=`55`, gt=`182`, coverage=`0.302`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2021-40438`: candidates=`55`, gt=`41`, coverage=`1.000`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2020-35452`: candidates=`53`, gt=`180`, coverage=`0.294`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2021-30641`: candidates=`53`, gt=`161`, coverage=`0.329`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2020-13950`: candidates=`51`, gt=`135`, coverage=`0.237`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-1927`: candidates=`51`, gt=`102`, coverage=`0.235`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-1934`: candidates=`51`, gt=`153`, coverage=`0.209`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-9490`: candidates=`51`, gt=`23`, coverage=`1.000`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2021-26690`: candidates=`51`, gt=`64`, coverage=`0.125`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-26691`: candidates=`51`, gt=`64`, coverage=`0.125`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-31618`: candidates=`51`, gt=`30`, coverage=`0.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-36160`: candidates=`51`, gt=`19`, coverage=`0.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-41773`: candidates=`51`, gt=`1`, coverage=`0.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-44224`: candidates=`51`, gt=`185`, coverage=`0.205`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-44790`: candidates=`51`, gt=`1`, coverage=`0.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-22719`: candidates=`51`, gt=`48`, coverage=`0.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']

## Worst Coverage Misses

- `httpd/CVE-2022-22719`: covered=`0/48`, candidates=`51`, unmapped=`['2.4.10', '2.4.20', '2.4.40', '2.4.51', '2.4.32', '2.4.34', '2.4.41', '2.4.7']`
- `httpd/CVE-2021-31618`: covered=`0/30`, candidates=`51`, unmapped=`['2.4.20', '2.4.40', '2.4.32', '2.4.34', '2.4.41', '2.4.21', '2.4.43', '2.4.23']`
- `httpd/CVE-2021-36160`: covered=`0/19`, candidates=`51`, unmapped=`['2.4.40', '2.4.32', '2.4.34', '2.4.41', '2.4.48', '2.4.43', '2.4.44', '2.4.36']`
- `httpd/CVE-2021-41773`: covered=`0/1`, candidates=`51`, unmapped=`['2.4.49']`
- `httpd/CVE-2021-44790`: covered=`0/1`, candidates=`51`, unmapped=`['2.4.51']`
- `httpd/CVE-2022-28614`: covered=`4/58`, candidates=`51`, unmapped=`['2.4.40', '2.4.20', '2.4.10', '2.4.51', '2.4.4', '2.4.32', '2.4.41', '2.4.34']`
- `httpd/CVE-2022-30522`: covered=`8/71`, candidates=`51`, unmapped=`['2.4.40', '2.4.20', '2.4.10', '2.4.51', '2.4.4', '2.4.32', '2.4.41', '2.4.34']`
- `httpd/CVE-2022-23943`: covered=`8/70`, candidates=`51`, unmapped=`['2.4.10', '2.4.20', '2.4.40', '2.4.51', '2.4.4', '2.4.32', '2.4.34', '2.4.41']`
- `httpd/CVE-2021-26690`: covered=`8/64`, candidates=`51`, unmapped=`['2.4.40', '2.4.20', '2.4.10', '2.4.4', '2.4.32', '2.4.41', '2.4.34', '2.4.7']`
- `httpd/CVE-2021-26691`: covered=`8/64`, candidates=`51`, unmapped=`['2.4.40', '2.4.20', '2.4.10', '2.4.4', '2.4.32', '2.4.41', '2.4.34', '2.4.7']`
- `httpd/CVE-2022-28330`: covered=`16/102`, candidates=`51`, unmapped=`['2.2.17', '2.2.23', '2.4.41', '2.4.34', '2.4.49', '2.4.2', '2.4.23', '2.4.27']`
- `httpd/CVE-2022-28615`: covered=`33/182`, candidates=`51`, unmapped=`['2.2.17', '2.2.23', '2.4.41', '2.0.38', '2.4.34', '2.0.24', '2.4.49', '2.4.2']`
- `httpd/CVE-2022-22720`: covered=`32/167`, candidates=`51`, unmapped=`['2.2.17', '2.2.23', '2.4.34', '2.0.38', '2.4.41', '2.0.24', '2.4.49', '2.4.2']`
- `httpd/CVE-2022-22721`: covered=`38/186`, candidates=`51`, unmapped=`['2.2.17', '2.2.23', '2.4.34', '2.0.38', '2.4.41', '2.0.24', '2.4.49', '2.4.2']`
- `httpd/CVE-2021-44224`: covered=`38/185`, candidates=`51`, unmapped=`['2.2.17', '2.2.23', '2.4.41', '2.0.38', '2.4.34', '2.0.24', '2.4.49', '2.4.2']`
- `httpd/CVE-2020-1934`: covered=`32/153`, candidates=`51`, unmapped=`['2.2.17', '2.2.23', '2.4.41', '2.0.38', '2.4.34', '2.0.24', '2.4.2', '2.4.23']`
- `httpd/CVE-2020-1927`: covered=`24/102`, candidates=`51`, unmapped=`['2.2.17', '2.2.23', '2.4.41', '2.4.34', '2.4.2', '2.4.23', '2.2.1', '2.4.27']`
- `httpd/CVE-2020-13950`: covered=`32/135`, candidates=`51`, unmapped=`['2.2.17', '2.2.23', '2.4.41', '2.4.34', '2.4.2', '2.4.23', '2.1.2', '2.2.1']`
- `httpd/CVE-2020-35452`: covered=`53/180`, candidates=`53`, unmapped=`['2.2.17', '2.2.23', '2.2.31', '2.0.38', '2.0.62', '2.0.24', '2.3.9', '2.1.2']`
- `httpd/CVE-2021-39275`: covered=`55/182`, candidates=`55`, unmapped=`['2.2.17', '2.2.23', '2.2.31', '2.0.38', '2.0.62', '2.0.24', '2.3.9', '2.1.2']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
