# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `71`

## Overall

- avg candidate tags/CVE: `88.93`
- median candidate tags/CVE: `51`
- max candidate tags/CVE: `201`
- avg GT coverage rate: `0.6975`
- full GT coverage CVEs: `33/71`
- coverage miss CVEs: `38`
- frontier statuses: `{'probe_small': 84, 'pruned': 1913, 'unknown': 394, 'known': 165}`

## Per Repo

### FFmpeg
- CVEs: `71`
- avg/median/max candidates: `88.93` / `51` / `201`
- avg GT coverage: `0.6975`
- full coverage CVEs: `33/71`
- frontier statuses: `{'probe_small': 84, 'pruned': 1913, 'unknown': 394, 'known': 165}`
- most expensive CVEs:
  - `CVE-2020-22016`: candidates=`201`, gt=`308`, coverage=`0.597`
  - `CVE-2020-22046`: candidates=`199`, gt=`292`, coverage=`0.651`
  - `CVE-2020-20448`: candidates=`198`, gt=`240`, coverage=`0.713`
  - `CVE-2020-21041`: candidates=`197`, gt=`119`, coverage=`1.000`
  - `CVE-2020-22025`: candidates=`196`, gt=`233`, coverage=`0.824`
- worst coverage misses:
  - `CVE-2020-20902`: covered=`12/240`, candidates=`39`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4']`
  - `CVE-2020-22049`: covered=`16/285`, candidates=`39`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4']`
  - `CVE-2022-3341`: covered=`23/350`, candidates=`27`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10']`
  - `CVE-2022-3109`: covered=`23/328`, candidates=`27`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10']`
  - `CVE-2020-22054`: covered=`16/196`, candidates=`39`, unmapped=`['n2.1.2', 'n3.4.4', 'n3.1.4', 'n2.1.8', 'n2.8.1']`

## Top Expensive CVEs

- `FFmpeg/CVE-2020-22016`: candidates=`201`, gt=`308`, coverage=`0.597`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22046`: candidates=`199`, gt=`292`, coverage=`0.651`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-20448`: candidates=`198`, gt=`240`, coverage=`0.713`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-21041`: candidates=`197`, gt=`119`, coverage=`1.000`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22025`: candidates=`196`, gt=`233`, coverage=`0.824`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-20451`: candidates=`194`, gt=`227`, coverage=`0.855`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22041`: candidates=`194`, gt=`97`, coverage=`1.000`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22044`: candidates=`194`, gt=`235`, coverage=`0.826`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22020`: candidates=`192`, gt=`192`, coverage=`1.000`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22022`: candidates=`192`, gt=`184`, coverage=`1.000`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22031`: candidates=`192`, gt=`184`, coverage=`1.000`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22032`: candidates=`192`, gt=`233`, coverage=`0.824`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-20446`: candidates=`187`, gt=`289`, coverage=`0.647`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22021`: candidates=`187`, gt=`187`, coverage=`1.000`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22037`: candidates=`187`, gt=`228`, coverage=`0.820`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2021-38114`: candidates=`187`, gt=`315`, coverage=`0.594`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2021-38171`: candidates=`187`, gt=`311`, coverage=`0.601`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-35965`: candidates=`185`, gt=`232`, coverage=`0.797`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-13904`: candidates=`178`, gt=`280`, coverage=`0.636`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22048`: candidates=`104`, gt=`75`, coverage=`1.000`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']

## Worst Coverage Misses

- `FFmpeg/CVE-2020-20902`: covered=`12/240`, candidates=`39`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n1.0.2']`
- `FFmpeg/CVE-2020-22049`: covered=`16/285`, candidates=`39`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n1.0.2']`
- `FFmpeg/CVE-2022-3341`: covered=`23/350`, candidates=`27`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2022-3109`: covered=`23/328`, candidates=`27`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-22054`: covered=`16/196`, candidates=`39`, unmapped=`['n2.1.2', 'n3.4.4', 'n3.1.4', 'n2.1.8', 'n2.8.1', 'n2.1', 'n2.8.3', 'n3.4.1']`
- `FFmpeg/CVE-2021-3566`: covered=`25/291`, candidates=`39`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n1.0.2']`
- `FFmpeg/CVE-2020-22043`: covered=`37/332`, candidates=`39`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-22039`: covered=`37/317`, candidates=`39`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-20450`: covered=`40/329`, candidates=`42`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-20892`: covered=`25/152`, candidates=`39`, unmapped=`['n3.4.4', 'n3.1.4', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n2.5.2', 'n2.4.8', 'n3.3.2']`
- `FFmpeg/CVE-2023-47342`: covered=`65/351`, candidates=`77`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n2.2.1', 'n3.2.1', 'n3.2.18']`
- `FFmpeg/CVE-2020-22042`: covered=`36/161`, candidates=`42`, unmapped=`['n3.4.4', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n2.5.2', 'n2.4.8', 'n3.3.2', 'n2.4.10']`
- `FFmpeg/CVE-2022-48434`: covered=`67/224`, candidates=`79`, unmapped=`['n3.4.4', 'n3.1.4', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n2.5.2', 'n2.4.8', 'n3.3.2']`
- `FFmpeg/CVE-2020-22040`: covered=`37/122`, candidates=`39`, unmapped=`['n3.4.4', 'n3.1.4', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n3.3.2', 'n3.1.11', 'n2.8']`
- `FFmpeg/CVE-2022-1475`: covered=`38/123`, candidates=`54`, unmapped=`['n3.4.4', 'n3.1.4', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n3.3.2', 'n3.1.11', 'n2.8']`
- `FFmpeg/CVE-2024-7055`: covered=`12/32`, candidates=`19`, unmapped=`['n4.3.7', 'n4.3.6', 'n5.0.2', 'n4.4', 'n4.3.1', 'n4.4.2', 'n5.0', 'n5.0.1']`
- `FFmpeg/CVE-2020-20891`: covered=`25/59`, candidates=`39`, unmapped=`['n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n3.2.7', 'n3.4.1', 'n3.2.3', 'n3.2.2']`
- `FFmpeg/CVE-2020-20898`: covered=`37/74`, candidates=`39`, unmapped=`['n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n3.2.7', 'n3.4.1', 'n3.2.3', 'n3.2.2']`
- `FFmpeg/CVE-2021-38092`: covered=`37/74`, candidates=`39`, unmapped=`['n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n3.2.7', 'n3.4.1', 'n3.2.3', 'n3.2.2']`
- `FFmpeg/CVE-2021-38114`: covered=`187/315`, candidates=`187`, unmapped=`['n1.0', 'n0.10.9', 'n4.4.2', 'n0.10.10', 'n0.11', 'n0.7.11', 'n1.1.2', 'v0.5.1']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
