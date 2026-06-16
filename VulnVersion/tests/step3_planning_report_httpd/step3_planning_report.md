# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `30`

## Overall

- avg candidate tags/CVE: `203.77`
- median candidate tags/CVE: `212.0`
- max candidate tags/CVE: `212`
- avg GT coverage rate: `0.9996`
- full GT coverage CVEs: `29/30`
- coverage miss CVEs: `1`
- frontier statuses: `{'unknown': 189, 'known': 7, 'probe_small': 7, 'pruned': 7}`

## Per Repo

### httpd
- CVEs: `30`
- avg/median/max candidates: `203.77` / `212.0` / `212`
- avg GT coverage: `0.9996`
- full coverage CVEs: `29/30`
- frontier statuses: `{'unknown': 189, 'known': 7, 'probe_small': 7, 'pruned': 7}`
- most expensive CVEs:
  - `CVE-2020-11984`: candidates=`212`, gt=`14`, coverage=`1.000`
  - `CVE-2020-11993`: candidates=`212`, gt=`28`, coverage=`1.000`
  - `CVE-2020-13950`: candidates=`212`, gt=`135`, coverage=`1.000`
  - `CVE-2020-1927`: candidates=`212`, gt=`102`, coverage=`1.000`
  - `CVE-2020-1934`: candidates=`212`, gt=`153`, coverage=`1.000`
- worst coverage misses:
  - `CVE-2020-35452`: covered=`178/180`, candidates=`178`, unmapped=`['1.3.9', '1.3.10']`

## Top Expensive CVEs

- `httpd/CVE-2020-11984`: candidates=`212`, gt=`14`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-11993`: candidates=`212`, gt=`28`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-13950`: candidates=`212`, gt=`135`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-1927`: candidates=`212`, gt=`102`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-1934`: candidates=`212`, gt=`153`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2020-9490`: candidates=`212`, gt=`23`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-26690`: candidates=`212`, gt=`64`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-26691`: candidates=`212`, gt=`64`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-31618`: candidates=`212`, gt=`30`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-36160`: candidates=`212`, gt=`19`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-39275`: candidates=`212`, gt=`182`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-41773`: candidates=`212`, gt=`1`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-44224`: candidates=`212`, gt=`185`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2021-44790`: candidates=`212`, gt=`1`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-22719`: candidates=`212`, gt=`48`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-22720`: candidates=`212`, gt=`167`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-22721`: candidates=`212`, gt=`186`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-23943`: candidates=`212`, gt=`70`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-28330`: candidates=`212`, gt=`102`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']
- `httpd/CVE-2022-28614`: candidates=`212`, gt=`58`, coverage=`1.000`, lines=['2.4', '2.2', '2.0', '2.3', '2.1', '1.3', '1.2']

## Worst Coverage Misses

- `httpd/CVE-2020-35452`: covered=`178/180`, candidates=`178`, unmapped=`['1.3.9', '1.3.10']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
