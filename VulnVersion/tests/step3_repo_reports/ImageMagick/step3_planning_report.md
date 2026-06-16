# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `72`

## Overall

- avg candidate tags/CVE: `160.9`
- median candidate tags/CVE: `174.0`
- max candidate tags/CVE: `278`
- avg GT coverage rate: `0.8116`
- full GT coverage CVEs: `56/72`
- coverage miss CVEs: `16`
- frontier statuses: `{'known': 72, 'probe_small': 19, 'pruned': 53}`

## Per Repo

### ImageMagick
- CVEs: `72`
- avg/median/max candidates: `160.9` / `174.0` / `278`
- avg GT coverage: `0.8116`
- full coverage CVEs: `56/72`
- frontier statuses: `{'known': 72, 'probe_small': 19, 'pruned': 53}`
- most expensive CVEs:
  - `CVE-2021-3610`: candidates=`278`, gt=`87`, coverage=`1.000`
  - `CVE-2021-3574`: candidates=`272`, gt=`272`, coverage=`1.000`
  - `CVE-2021-20309`: candidates=`266`, gt=`78`, coverage=`1.000`
  - `CVE-2021-20310`: candidates=`266`, gt=`76`, coverage=`1.000`
  - `CVE-2021-20311`: candidates=`266`, gt=`175`, coverage=`1.000`
- worst coverage misses:
  - `CVE-2021-39212`: covered=`9/170`, candidates=`9`, unmapped=`['7.0.10-10', '7.0.9-18', '7.0.10-33', '7.0.9-19', '7.0.8-12']`
  - `CVE-2022-0284`: covered=`22/299`, candidates=`22`, unmapped=`['7.0.10-10', '7.0.7-39', '7.0.9-18', '7.0.10-33', '7.0.1-2']`
  - `CVE-2022-32545`: covered=`30/307`, candidates=`30`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57']`
  - `CVE-2022-28463`: covered=`31/308`, candidates=`31`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57']`
  - `CVE-2022-32546`: covered=`31/308`, candidates=`31`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57']`

## Top Expensive CVEs

- `ImageMagick/CVE-2021-3610`: candidates=`278`, gt=`87`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-3574`: candidates=`272`, gt=`272`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20309`: candidates=`266`, gt=`78`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20310`: candidates=`266`, gt=`76`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20311`: candidates=`266`, gt=`175`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20312`: candidates=`266`, gt=`266`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20313`: candidates=`266`, gt=`175`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20241`: candidates=`263`, gt=`263`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20243`: candidates=`263`, gt=`263`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20244`: candidates=`263`, gt=`75`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20245`: candidates=`263`, gt=`90`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20246`: candidates=`263`, gt=`263`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20176`: candidates=`258`, gt=`258`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-20224`: candidates=`258`, gt=`258`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2020-27829`: candidates=`247`, gt=`56`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2020-27560`: candidates=`236`, gt=`236`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2021-3596`: candidates=`232`, gt=`232`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2020-19667`: candidates=`208`, gt=`208`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2020-10251`: candidates=`201`, gt=`51`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2023-3745`: candidates=`201`, gt=`10`, coverage=`1.000`, lines=['7.0']

## Worst Coverage Misses

- `ImageMagick/CVE-2021-39212`: covered=`9/170`, candidates=`9`, unmapped=`['7.0.10-10', '7.0.9-18', '7.0.10-33', '7.0.9-19', '7.0.8-12', '7.0.10-45', '7.0.10-18', '7.0.10-19']`
- `ImageMagick/CVE-2022-0284`: covered=`22/299`, candidates=`22`, unmapped=`['7.0.10-10', '7.0.7-39', '7.0.9-18', '7.0.10-33', '7.0.1-2', '7.0.9-19', '7.0.7-17', '7.0.8-12']`
- `ImageMagick/CVE-2022-32545`: covered=`30/307`, candidates=`30`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57', '7.0.10-32', '7.0.10-3', '7.0.8-43']`
- `ImageMagick/CVE-2022-28463`: covered=`31/308`, candidates=`31`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57', '7.0.10-32', '7.0.10-3', '7.0.8-43']`
- `ImageMagick/CVE-2022-32546`: covered=`31/308`, candidates=`31`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57', '7.0.10-32', '7.0.10-3', '7.0.8-43']`
- `ImageMagick/CVE-2022-2719`: covered=`32/309`, candidates=`32`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57', '7.0.10-32', '7.0.10-3', '7.0.8-43']`
- `ImageMagick/CVE-2022-32547`: covered=`32/309`, candidates=`32`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57', '7.0.10-32', '7.0.10-3', '7.0.8-43']`
- `ImageMagick/CVE-2023-3195`: covered=`13/100`, candidates=`13`, unmapped=`['7.0.10-10', '7.0.9-18', '7.0.10-33', '7.0.9-19', '7.0.10-45', '7.0.10-18', '7.0.10-19', '7.0.10-57']`
- `ImageMagick/CVE-2023-1289`: covered=`65/342`, candidates=`65`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57', '7.0.10-32', '7.0.10-3', '7.0.8-43']`
- `ImageMagick/CVE-2023-5341`: covered=`84/361`, candidates=`84`, unmapped=`['7.0.7-39', '7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57', '7.0.10-32', '7.0.10-3', '7.0.8-43']`
- `ImageMagick/CVE-2021-4219`: covered=`21/78`, candidates=`21`, unmapped=`['7.0.10-33', '7.0.10-45', '7.0.10-19', '7.0.10-57', '7.0.10-32', '7.0.10-30', '7.0.10-60', '7.0.10-59']`
- `ImageMagick/CVE-2022-3213`: covered=`49/135`, candidates=`49`, unmapped=`['7.0.10-10', '7.0.10-33', '7.0.9-18', '7.0.9-19', '7.0.10-45', '7.0.10-18', '7.0.10-19', '7.0.10-57']`
- `ImageMagick/CVE-2023-34474`: covered=`75/193`, candidates=`75`, unmapped=`['7.0.10-10', '7.0.9-18', '7.0.10-33', '7.0.9-19', '7.0.10-45', '7.0.10-18', '7.0.10-19', '7.0.10-57']`
- `ImageMagick/CVE-2023-34475`: covered=`75/193`, candidates=`75`, unmapped=`['7.0.10-10', '7.0.9-18', '7.0.10-33', '7.0.9-19', '7.0.10-45', '7.0.10-18', '7.0.10-19', '7.0.10-57']`
- `ImageMagick/CVE-2022-1114`: covered=`30/76`, candidates=`30`, unmapped=`['7.0.10-62', '7.0.10-54', '7.0.10-33', '7.0.10-46', '7.0.10-49', '7.0.10-45', '7.0.10-52', '7.0.11-4']`
- `ImageMagick/CVE-2023-1906`: covered=`70/156`, candidates=`71`, unmapped=`['7.0.10-10', '7.0.10-33', '7.0.9-18', '7.0.9-19', '7.0.10-45', '7.0.10-18', '7.0.10-19', '7.0.10-57']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
