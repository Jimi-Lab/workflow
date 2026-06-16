# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `13`

## Overall

- avg candidate tags/CVE: `16.15`
- median candidate tags/CVE: `16`
- max candidate tags/CVE: `17`
- avg GT coverage rate: `0.9231`
- full GT coverage CVEs: `13/13`
- coverage miss CVEs: `0`
- frontier statuses: `{'pruned': 24, 'unknown': 54, 'probe_small': 78}`

## Per Repo

### openjpeg
- CVEs: `13`
- avg/median/max candidates: `16.15` / `16` / `17`
- avg GT coverage: `0.9231`
- full coverage CVEs: `13/13`
- frontier statuses: `{'pruned': 24, 'unknown': 54, 'probe_small': 78}`
- most expensive CVEs:
  - `CVE-2021-29338`: candidates=`17`, gt=`15`, coverage=`1.000`
  - `CVE-2022-1122`: candidates=`17`, gt=`15`, coverage=`1.000`
  - `CVE-2020-15389`: candidates=`16`, gt=`8`, coverage=`1.000`
  - `CVE-2020-27814`: candidates=`16`, gt=`5`, coverage=`1.000`
  - `CVE-2020-27823`: candidates=`16`, gt=`5`, coverage=`1.000`

## Top Expensive CVEs

- `openjpeg/CVE-2021-29338`: candidates=`17`, gt=`15`, coverage=`1.000`, lines=['2.4', '2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2022-1122`: candidates=`17`, gt=`15`, coverage=`1.000`, lines=['2.4', '2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-15389`: candidates=`16`, gt=`8`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-27814`: candidates=`16`, gt=`5`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-27823`: candidates=`16`, gt=`5`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-27824`: candidates=`16`, gt=`16`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-27841`: candidates=`16`, gt=`8`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-27842`: candidates=`16`, gt=`15`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-27843`: candidates=`16`, gt=`15`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-27844`: candidates=`16`, gt=`0`, coverage=`0.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-27845`: candidates=`16`, gt=`16`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-6851`: candidates=`16`, gt=`2`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']
- `openjpeg/CVE-2020-8112`: candidates=`16`, gt=`8`, coverage=`1.000`, lines=['2.3', '2.2', '2.1', '2.0', '1.5', '1.3', '1.4', '1.2', '1.1', '1.0']

## Worst Coverage Misses


## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
