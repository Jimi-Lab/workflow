# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `71`

## Overall

- avg candidate tags/CVE: `74.08`
- median candidate tags/CVE: `46`
- max candidate tags/CVE: `163`
- avg GT coverage rate: `0.5774`
- full GT coverage CVEs: `8/71`
- coverage miss CVEs: `63`
- frontier statuses: `{'probe_small': 84, 'pruned': 1913, 'unknown': 394, 'known': 165}`

## Per Repo

### FFmpeg
- CVEs: `71`
- avg/median/max candidates: `74.08` / `46` / `163`
- avg GT coverage: `0.5774`
- full coverage CVEs: `8/71`
- frontier statuses: `{'probe_small': 84, 'pruned': 1913, 'unknown': 394, 'known': 165}`
- most expensive CVEs:
  - `CVE-2020-21041`: candidates=`163`, gt=`119`, coverage=`0.908`
  - `CVE-2020-22046`: candidates=`161`, gt=`292`, coverage=`0.524`
  - `CVE-2020-20451`: candidates=`160`, gt=`227`, coverage=`0.705`
  - `CVE-2020-22041`: candidates=`160`, gt=`97`, coverage=`0.928`
  - `CVE-2020-22044`: candidates=`160`, gt=`235`, coverage=`0.681`
- worst coverage misses:
  - `CVE-2020-24020`: covered=`0/1`, candidates=`31`, unmapped=`['n4.3']`
  - `CVE-2020-20902`: covered=`6/240`, candidates=`31`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4']`
  - `CVE-2020-22049`: covered=`9/285`, candidates=`31`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4']`
  - `CVE-2020-22054`: covered=`9/196`, candidates=`31`, unmapped=`['n2.1.2', 'n3.4.4', 'n3.1.4', 'n2.1.8', 'n4.2.2']`
  - `CVE-2021-3566`: covered=`17/291`, candidates=`31`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4']`

## Top Expensive CVEs

- `FFmpeg/CVE-2020-21041`: candidates=`163`, gt=`119`, coverage=`0.908`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22046`: candidates=`161`, gt=`292`, coverage=`0.524`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-20451`: candidates=`160`, gt=`227`, coverage=`0.705`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22041`: candidates=`160`, gt=`97`, coverage=`0.928`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22044`: candidates=`160`, gt=`235`, coverage=`0.681`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22016`: candidates=`159`, gt=`308`, coverage=`0.468`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22020`: candidates=`158`, gt=`192`, coverage=`0.823`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22022`: candidates=`158`, gt=`184`, coverage=`0.815`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22025`: candidates=`158`, gt=`233`, coverage=`0.661`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22031`: candidates=`158`, gt=`184`, coverage=`0.815`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22032`: candidates=`158`, gt=`233`, coverage=`0.678`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-20446`: candidates=`153`, gt=`289`, coverage=`0.529`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22021`: candidates=`153`, gt=`187`, coverage=`0.818`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22037`: candidates=`153`, gt=`228`, coverage=`0.671`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2021-38114`: candidates=`153`, gt=`315`, coverage=`0.486`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2021-38171`: candidates=`153`, gt=`311`, coverage=`0.492`, lines=['4.2', '4.4', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-35965`: candidates=`151`, gt=`232`, coverage=`0.651`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-20448`: candidates=`149`, gt=`240`, coverage=`0.517`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-13904`: candidates=`144`, gt=`280`, coverage=`0.514`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '2.4', '3.1', '2.6', '2.7', '2.5', '2.2', '2.0', '2.1', '2.3']
- `FFmpeg/CVE-2020-22048`: candidates=`93`, gt=`75`, coverage=`0.920`, lines=['4.2', '3.4', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']

## Worst Coverage Misses

- `FFmpeg/CVE-2020-24020`: covered=`0/1`, candidates=`31`, unmapped=`['n4.3']`
- `FFmpeg/CVE-2020-20902`: covered=`6/240`, candidates=`31`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n1.0.2']`
- `FFmpeg/CVE-2020-22049`: covered=`9/285`, candidates=`31`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n4.2.2']`
- `FFmpeg/CVE-2020-22054`: covered=`9/196`, candidates=`31`, unmapped=`['n2.1.2', 'n3.4.4', 'n3.1.4', 'n2.1.8', 'n4.2.2', 'n2.8.1', 'n2.1', 'n2.8.3']`
- `FFmpeg/CVE-2021-3566`: covered=`17/291`, candidates=`31`, unmapped=`['n1.1.4', 'n1.1.3', 'n3.4.4', 'n2.1.2', 'n3.1.4', 'n1.1.15', 'n2.1.8', 'n4.2.2']`
- `FFmpeg/CVE-2022-3341`: covered=`23/350`, candidates=`27`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2022-3109`: covered=`23/328`, candidates=`27`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-22043`: covered=`29/332`, candidates=`31`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-22039`: covered=`29/317`, candidates=`31`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-20450`: covered=`32/329`, candidates=`34`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n3.3.2', 'n2.2.1', 'n3.2.1']`
- `FFmpeg/CVE-2020-20892`: covered=`17/152`, candidates=`31`, unmapped=`['n3.4.4', 'n3.1.4', 'n4.2.2', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n2.5.2', 'n2.4.8']`
- `FFmpeg/CVE-2023-47342`: covered=`58/351`, candidates=`70`, unmapped=`['n3.1.4', 'n2.8.3', 'n1.0', 'n0.10.9', 'n0.10.10', 'n2.2.1', 'n3.2.1', 'n3.2.18']`
- `FFmpeg/CVE-2020-22042`: covered=`28/161`, candidates=`34`, unmapped=`['n3.4.4', 'n4.2.2', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n2.5.2', 'n2.4.8', 'n3.3.2']`
- `FFmpeg/CVE-2020-22040`: covered=`29/122`, candidates=`31`, unmapped=`['n3.4.4', 'n3.1.4', 'n4.2.2', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n3.3.2', 'n3.1.11']`
- `FFmpeg/CVE-2022-1475`: covered=`30/123`, candidates=`46`, unmapped=`['n3.4.4', 'n3.1.4', 'n4.2.2', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n3.3.2', 'n3.1.11']`
- `FFmpeg/CVE-2022-48434`: covered=`58/224`, candidates=`70`, unmapped=`['n3.4.4', 'n3.1.4', 'n4.2.2', 'n2.8.1', 'n2.8.3', 'n3.4.1', 'n2.5.2', 'n2.4.8']`
- `FFmpeg/CVE-2020-20891`: covered=`17/59`, candidates=`31`, unmapped=`['n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n4.2.2', 'n3.2.7', 'n3.4.1', 'n3.2.3']`
- `FFmpeg/CVE-2024-7055`: covered=`12/32`, candidates=`19`, unmapped=`['n4.3.7', 'n4.3.6', 'n5.0.2', 'n4.4', 'n4.3.1', 'n4.4.2', 'n5.0', 'n5.0.1']`
- `FFmpeg/CVE-2020-20898`: covered=`29/74`, candidates=`31`, unmapped=`['n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n4.2.2', 'n3.2.7', 'n3.4.1', 'n3.2.3']`
- `FFmpeg/CVE-2021-38092`: covered=`29/74`, candidates=`31`, unmapped=`['n3.4.3', 'n3.4.4', 'n3.2.12', 'n3.2.13', 'n4.2.2', 'n3.2.7', 'n3.4.1', 'n3.2.3']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
