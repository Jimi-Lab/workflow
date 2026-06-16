# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `72`

## Overall

- avg candidate tags/CVE: `234`
- median candidate tags/CVE: `220.0`
- max candidate tags/CVE: `378`
- avg GT coverage rate: `0.9861`
- full GT coverage CVEs: `72/72`
- coverage miss CVEs: `0`
- frontier statuses: `{'known': 72, 'unknown': 19, 'pruned': 53}`

## Per Repo

### ImageMagick
- CVEs: `72`
- avg/median/max candidates: `234` / `220.0` / `378`
- avg GT coverage: `0.9861`
- full coverage CVEs: `72/72`
- frontier statuses: `{'known': 72, 'unknown': 19, 'pruned': 53}`
- most expensive CVEs:
  - `CVE-2024-41817`: candidates=`378`, gt=`0`, coverage=`0.000`
  - `CVE-2023-5341`: candidates=`361`, gt=`361`, coverage=`1.000`
  - `CVE-2023-34474`: candidates=`352`, gt=`193`, coverage=`1.000`
  - `CVE-2023-34475`: candidates=`352`, gt=`193`, coverage=`1.000`
  - `CVE-2023-1906`: candidates=`348`, gt=`156`, coverage=`1.000`

## Top Expensive CVEs

- `ImageMagick/CVE-2024-41817`: candidates=`378`, gt=`0`, coverage=`0.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2023-5341`: candidates=`361`, gt=`361`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2023-34474`: candidates=`352`, gt=`193`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2023-34475`: candidates=`352`, gt=`193`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2023-1906`: candidates=`348`, gt=`156`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2023-1289`: candidates=`342`, gt=`342`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-3213`: candidates=`326`, gt=`135`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-2719`: candidates=`309`, gt=`309`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-32547`: candidates=`309`, gt=`309`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-1115`: candidates=`308`, gt=`24`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-28463`: candidates=`308`, gt=`308`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-32546`: candidates=`308`, gt=`308`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-1114`: candidates=`307`, gt=`76`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-32545`: candidates=`307`, gt=`307`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2022-0284`: candidates=`299`, gt=`299`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2021-4219`: candidates=`298`, gt=`78`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2021-3962`: candidates=`293`, gt=`3`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2023-3195`: candidates=`290`, gt=`100`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2021-39212`: candidates=`286`, gt=`170`, coverage=`1.000`, lines=['7.1', '7.0']
- `ImageMagick/CVE-2021-3610`: candidates=`278`, gt=`87`, coverage=`1.000`, lines=['7.0']

## Worst Coverage Misses


## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
