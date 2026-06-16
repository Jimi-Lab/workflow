# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `13`

## Overall

- avg candidate tags/CVE: `3`
- median candidate tags/CVE: `3`
- max candidate tags/CVE: `3`
- avg GT coverage rate: `0.3462`
- full GT coverage CVEs: `2/13`
- coverage miss CVEs: `11`
- frontier statuses: `{'pruned': 130, 'probe_small': 26}`

## Per Repo

### openjpeg
- CVEs: `13`
- avg/median/max candidates: `3` / `3` / `3`
- avg GT coverage: `0.3462`
- full coverage CVEs: `2/13`
- frontier statuses: `{'pruned': 130, 'probe_small': 26}`
- most expensive CVEs:
  - `CVE-2020-15389`: candidates=`3`, gt=`8`, coverage=`0.375`
  - `CVE-2020-27814`: candidates=`3`, gt=`5`, coverage=`0.600`
  - `CVE-2020-27823`: candidates=`3`, gt=`5`, coverage=`0.600`
  - `CVE-2020-27824`: candidates=`3`, gt=`16`, coverage=`0.188`
  - `CVE-2020-27841`: candidates=`3`, gt=`8`, coverage=`0.375`
- worst coverage misses:
  - `CVE-2020-27824`: covered=`3/16`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4']`
  - `CVE-2020-27845`: covered=`3/16`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4']`
  - `CVE-2020-27842`: covered=`3/15`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4']`
  - `CVE-2020-27843`: covered=`3/15`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4']`
  - `CVE-2021-29338`: covered=`3/15`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4']`

## Top Expensive CVEs

- `openjpeg/CVE-2020-15389`: candidates=`3`, gt=`8`, coverage=`0.375`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-27814`: candidates=`3`, gt=`5`, coverage=`0.600`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-27823`: candidates=`3`, gt=`5`, coverage=`0.600`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-27824`: candidates=`3`, gt=`16`, coverage=`0.188`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-27841`: candidates=`3`, gt=`8`, coverage=`0.375`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-27842`: candidates=`3`, gt=`15`, coverage=`0.200`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-27843`: candidates=`3`, gt=`15`, coverage=`0.200`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-27844`: candidates=`3`, gt=`0`, coverage=`0.000`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-27845`: candidates=`3`, gt=`16`, coverage=`0.188`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-6851`: candidates=`3`, gt=`2`, coverage=`1.000`, lines=['2.3', '2.2']
- `openjpeg/CVE-2020-8112`: candidates=`3`, gt=`8`, coverage=`0.375`, lines=['2.3', '2.2']
- `openjpeg/CVE-2021-29338`: candidates=`3`, gt=`15`, coverage=`0.200`, lines=['2.4', '2.3']
- `openjpeg/CVE-2022-1122`: candidates=`3`, gt=`15`, coverage=`0.200`, lines=['2.4', '2.3']

## Worst Coverage Misses

- `openjpeg/CVE-2020-27824`: covered=`3/16`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4', 'version.1.5', 'version.2.0.1', 'version.1.1']`
- `openjpeg/CVE-2020-27845`: covered=`3/16`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4', 'version.1.5', 'version.2.0.1', 'version.1.1']`
- `openjpeg/CVE-2020-27842`: covered=`3/15`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4', 'version.1.5', 'version.2.0.1', 'version.1.1']`
- `openjpeg/CVE-2020-27843`: covered=`3/15`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4', 'version.1.5', 'version.2.0.1', 'version.1.1']`
- `openjpeg/CVE-2021-29338`: covered=`3/15`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4', 'version.1.5', 'version.2.0.1', 'version.1.5.1']`
- `openjpeg/CVE-2022-1122`: covered=`3/15`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.1.2', 'version.2.1', 'version.1.4', 'version.1.5', 'version.2.0.1', 'version.1.5.1']`
- `openjpeg/CVE-2020-15389`: covered=`3/8`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.2.1', 'version.2.0.1', 'v2.1.1']`
- `openjpeg/CVE-2020-27841`: covered=`3/8`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.2.1', 'version.2.0.1', 'v2.1.1']`
- `openjpeg/CVE-2020-8112`: covered=`3/8`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.2.1', 'version.2.0.1', 'v2.1.1']`
- `openjpeg/CVE-2020-27814`: covered=`3/5`, candidates=`3`, unmapped=`['v2.1.2', 'v2.1.1']`
- `openjpeg/CVE-2020-27823`: covered=`3/5`, candidates=`3`, unmapped=`['v2.1.2', 'v2.1.1']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
