# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `71`

## Overall

- avg candidate tags/CVE: `36.85`
- median candidate tags/CVE: `17`
- max candidate tags/CVE: `102`
- avg GT coverage rate: `0.3626`
- full GT coverage CVEs: `8/71`
- coverage miss CVEs: `63`
- frontier statuses: `{'probe_small': 71, 'pruned': 2202, 'known': 165, 'unknown': 118}`

## Per Repo

### FFmpeg
- CVEs: `71`
- avg/median/max candidates: `36.85` / `17` / `102`
- avg GT coverage: `0.3626`
- full coverage CVEs: `8/71`
- frontier statuses: `{'probe_small': 71, 'pruned': 2202, 'known': 165, 'unknown': 118}`
- most expensive CVEs:
  - `CVE-2020-21041`: candidates=`102`, gt=`119`, coverage=`0.857`
  - `CVE-2020-22046`: candidates=`100`, gt=`292`, coverage=`0.315`
  - `CVE-2020-20451`: candidates=`99`, gt=`227`, coverage=`0.436`
  - `CVE-2020-22041`: candidates=`99`, gt=`97`, coverage=`0.928`
  - `CVE-2020-22044`: candidates=`99`, gt=`235`, coverage=`0.421`
- worst coverage misses:
  - `CVE-2021-3566`: covered=`0/291`, candidates=`2`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4']`
  - `CVE-2020-22049`: covered=`0/285`, candidates=`2`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4']`
  - `CVE-2020-20902`: covered=`0/240`, candidates=`2`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4']`
  - `CVE-2020-22054`: covered=`0/196`, candidates=`2`, unmapped=`['n2.1.2', 'n3.4.4', 'n3.1.4', 'n2.1.8', 'n4.2.2']`
  - `CVE-2020-20892`: covered=`0/152`, candidates=`2`, unmapped=`['n3.4.4', 'n3.1.4', 'n4.2.2', 'n2.8.1', 'n3.4.7']`

## Top Expensive CVEs

- `FFmpeg/CVE-2020-21041`: candidates=`102`, gt=`119`, coverage=`0.857`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22046`: candidates=`100`, gt=`292`, coverage=`0.315`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-20451`: candidates=`99`, gt=`227`, coverage=`0.436`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22041`: candidates=`99`, gt=`97`, coverage=`0.928`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22044`: candidates=`99`, gt=`235`, coverage=`0.421`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22016`: candidates=`98`, gt=`308`, coverage=`0.269`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22020`: candidates=`97`, gt=`192`, coverage=`0.505`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22022`: candidates=`97`, gt=`184`, coverage=`0.527`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22025`: candidates=`97`, gt=`233`, coverage=`0.399`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22031`: candidates=`97`, gt=`184`, coverage=`0.527`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22032`: candidates=`97`, gt=`233`, coverage=`0.416`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-20446`: candidates=`92`, gt=`289`, coverage=`0.318`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22021`: candidates=`92`, gt=`187`, coverage=`0.492`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22037`: candidates=`92`, gt=`228`, coverage=`0.404`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2021-38114`: candidates=`92`, gt=`315`, coverage=`0.292`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2021-38171`: candidates=`92`, gt=`311`, coverage=`0.296`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-35965`: candidates=`90`, gt=`232`, coverage=`0.388`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-20448`: candidates=`88`, gt=`240`, coverage=`0.263`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-13904`: candidates=`83`, gt=`280`, coverage=`0.296`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `FFmpeg/CVE-2020-22048`: candidates=`63`, gt=`75`, coverage=`0.840`, lines=['4.2', '3.4', '4.1', '3.2', '4.0', '3.3', '3.1']

## Worst Coverage Misses

- `FFmpeg/CVE-2021-3566`: covered=`0/291`, candidates=`2`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n4.2.2']`
- `FFmpeg/CVE-2020-22049`: covered=`0/285`, candidates=`2`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n4.2.2']`
- `FFmpeg/CVE-2020-20902`: covered=`0/240`, candidates=`2`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n1.0.2']`
- `FFmpeg/CVE-2020-22054`: covered=`0/196`, candidates=`2`, unmapped=`['n2.1.2', 'n3.4.4', 'n3.1.4', 'n2.1.8', 'n4.2.2', 'n2.8.1', 'n2.1', 'n3.4.7']`
- `FFmpeg/CVE-2020-20892`: covered=`0/152`, candidates=`2`, unmapped=`['n3.4.4', 'n3.1.4', 'n4.2.2', 'n2.8.1', 'n3.4.7', 'n2.8.3', 'n3.4.1', 'n2.5.2']`
- `FFmpeg/CVE-2020-20891`: covered=`0/59`, candidates=`2`, unmapped=`['n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n4.2.2', 'n3.2.7', 'n3.4.7', 'n3.4.1']`
- `FFmpeg/CVE-2020-20896`: covered=`0/32`, candidates=`2`, unmapped=`['n3.4.3', 'n3.4.4', 'n4.2.2', 'n3.4.7', 'n3.4.1', 'n3.4.9', 'n4.1.5', 'n4.2.4']`
- `FFmpeg/CVE-2024-7055`: covered=`0/32`, candidates=`2`, unmapped=`['n4.3.7', 'n4.3.6', 'n5.1.5', 'n5.0.2', 'n4.4', 'n6.1', 'n5.1.3', 'n5.1.6']`
- `FFmpeg/CVE-2022-3964`: covered=`0/17`, candidates=`2`, unmapped=`['n5.1.5', 'n4.4.2', 'n4.4.4', 'n5.0.2', 'n4.4', 'n5.1.4', 'n5.1', 'n5.0']`
- `FFmpeg/CVE-2022-3965`: covered=`0/6`, candidates=`2`, unmapped=`['n5.1', 'n5.0.2', 'n5.0', 'n5.1.1', 'n5.0.1', 'n5.1.2']`
- `FFmpeg/CVE-2020-24020`: covered=`0/1`, candidates=`2`, unmapped=`['n4.3']`
- `FFmpeg/CVE-2022-3341`: covered=`1/350`, candidates=`2`, unmapped=`['n3.1.4', 'n4.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n4.4.2', 'n0.10.10', 'n3.3.2']`
- `FFmpeg/CVE-2020-22043`: covered=`1/332`, candidates=`2`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2022-3109`: covered=`1/328`, candidates=`2`, unmapped=`['n3.1.4', 'n4.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n4.4.2', 'n0.10.10', 'n3.3.2']`
- `FFmpeg/CVE-2020-22039`: covered=`1/317`, candidates=`2`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-22040`: covered=`1/122`, candidates=`2`, unmapped=`['n3.4.4', 'n3.1.4', 'n4.2.2', 'n2.8.1', 'n3.4.7', 'n2.8.3', 'n4.2.7', 'n4.2.8']`
- `FFmpeg/CVE-2020-20450`: covered=`4/329`, candidates=`5`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-20898`: covered=`1/74`, candidates=`2`, unmapped=`['n4.1.10', 'n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n4.2.2', 'n3.2.7', 'n4.1.11']`
- `FFmpeg/CVE-2021-38092`: covered=`1/74`, candidates=`2`, unmapped=`['n4.1.10', 'n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n4.2.2', 'n3.2.7', 'n4.1.11']`
- `FFmpeg/CVE-2020-22042`: covered=`3/161`, candidates=`5`, unmapped=`['n3.4.4', 'n4.2.2', 'n2.8.1', 'n3.4.7', 'n2.8.3', 'n4.2.7', 'n4.2.8', 'n3.4.1']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
