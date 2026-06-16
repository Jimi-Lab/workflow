# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `30`

## Overall

- avg candidate tags/CVE: `198.1`
- median candidate tags/CVE: `212.0`
- max candidate tags/CVE: `212`
- avg GT coverage rate: `0.9993`
- full GT coverage CVEs: `28/30`
- coverage miss CVEs: `2`
- frontier statuses: `{'unknown': 174, 'known': 12, 'probe_small': 12, 'pruned': 12}`

## Per Repo

### httpd
- CVEs: `30`
- avg/median/max candidates: `198.1` / `212.0` / `212`
- avg GT coverage: `0.9993`
- full coverage CVEs: `28/30`
- frontier statuses: `{'unknown': 174, 'known': 12, 'probe_small': 12, 'pruned': 12}`
- most expensive CVEs:
  - `CVE-2020-13950`: candidates=`212`, gt=`135`, coverage=`1.000`
  - `CVE-2020-1927`: candidates=`212`, gt=`102`, coverage=`1.000`
  - `CVE-2020-1934`: candidates=`212`, gt=`153`, coverage=`1.000`
  - `CVE-2021-26690`: candidates=`212`, gt=`64`, coverage=`1.000`
  - `CVE-2021-26691`: candidates=`212`, gt=`64`, coverage=`1.000`
- worst coverage misses:
  - `CVE-2020-35452`: covered=`178/180`, candidates=`178`, unmapped=`['1.3.9', '1.3.10']`
  - `CVE-2021-39275`: covered=`180/182`, candidates=`180`, unmapped=`['1.3.9', '1.3.10']`

## Top Expensive CVEs

- `httpd/CVE-2020-13950`: candidates=`212`, gt=`135`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-1927`: candidates=`212`, gt=`102`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-1934`: candidates=`212`, gt=`153`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-26690`: candidates=`212`, gt=`64`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-26691`: candidates=`212`, gt=`64`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-31618`: candidates=`212`, gt=`30`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-36160`: candidates=`212`, gt=`19`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-41773`: candidates=`212`, gt=`1`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-44224`: candidates=`212`, gt=`185`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-44790`: candidates=`212`, gt=`1`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-22719`: candidates=`212`, gt=`48`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-22720`: candidates=`212`, gt=`167`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-22721`: candidates=`212`, gt=`186`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-23943`: candidates=`212`, gt=`70`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-28330`: candidates=`212`, gt=`102`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-28614`: candidates=`212`, gt=`58`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-28615`: candidates=`212`, gt=`182`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-30522`: candidates=`212`, gt=`71`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-30556`: candidates=`185`, gt=`47`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3']
- `httpd/CVE-2022-31813`: candidates=`185`, gt=`49`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3']

## Worst Coverage Misses

- `httpd/CVE-2020-35452`: covered=`178/180`, candidates=`178`, unmapped=`['1.3.9', '1.3.10']`
- `httpd/CVE-2021-39275`: covered=`180/182`, candidates=`180`, unmapped=`['1.3.9', '1.3.10']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
