# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `57`

## Overall

- avg candidate tags/CVE: `10.16`
- median candidate tags/CVE: `10`
- max candidate tags/CVE: `15`
- avg GT coverage rate: `0.4747`
- full GT coverage CVEs: `23/57`
- coverage miss CVEs: `34`
- frontier statuses: `{'pruned': 3019, 'probe_small': 342, 'unknown': 1, 'known': 1}`

## Per Repo

### qemu
- CVEs: `57`
- avg/median/max candidates: `10.16` / `10` / `15`
- avg GT coverage: `0.4747`
- full coverage CVEs: `23/57`
- frontier statuses: `{'pruned': 3019, 'probe_small': 342, 'unknown': 1, 'known': 1}`
- most expensive CVEs:
  - `CVE-2020-13765`: candidates=`15`, gt=`76`, coverage=`0.184`
  - `CVE-2020-10702`: candidates=`12`, gt=`5`, coverage=`1.000`
  - `CVE-2020-11869`: candidates=`12`, gt=`3`, coverage=`1.000`
  - `CVE-2020-11947`: candidates=`12`, gt=`64`, coverage=`0.188`
  - `CVE-2020-12829`: candidates=`12`, gt=`76`, coverage=`0.158`
- worst coverage misses:
  - `CVE-2021-3507`: covered=`8/107`, candidates=`8`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1']`
  - `CVE-2020-25625`: covered=`11/115`, candidates=`11`, unmapped=`['v1.4.1', 'v0.4.4', 'v2.9.0', 'v1.2.2', 'v1.7.0']`
  - `CVE-2022-0216`: covered=`8/76`, candidates=`8`, unmapped=`['v1.4.1', 'v2.5.0', 'v0.15.1', 'v2.10.0', 'v2.9.0']`
  - `CVE-2021-20221`: covered=`10/94`, candidates=`10`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1']`
  - `CVE-2020-13361`: covered=`10/93`, candidates=`12`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1']`

## Top Expensive CVEs

- `qemu/CVE-2020-13765`: candidates=`15`, gt=`76`, coverage=`0.184`, lines=['4.1', '4.0', '3.1', '3.0', '2.12', '2.11', '2.10', '2.9']
- `qemu/CVE-2020-10702`: candidates=`12`, gt=`5`, coverage=`1.000`, lines=['4.2', '4.1', '4.0', '3.1', '3.0', '2.12']
- `qemu/CVE-2020-11869`: candidates=`12`, gt=`3`, coverage=`1.000`, lines=['4.2', '4.1', '4.0', '3.1', '3.0', '2.12']
- `qemu/CVE-2020-11947`: candidates=`12`, gt=`64`, coverage=`0.188`, lines=['4.2', '4.1', '4.0', '3.1', '3.0', '2.12']
- `qemu/CVE-2020-12829`: candidates=`12`, gt=`76`, coverage=`0.158`, lines=['5.0', '4.2', '4.1', '4.0', '3.1', '3.0']
- `qemu/CVE-2020-13361`: candidates=`12`, gt=`93`, coverage=`0.108`, lines=['5.0', '4.2', '4.1', '4.0', '3.1', '3.0']
- `qemu/CVE-2020-13800`: candidates=`12`, gt=`6`, coverage=`1.000`, lines=['5.0', '4.2', '4.1', '4.0', '3.1', '3.0']
- `qemu/CVE-2020-14394`: candidates=`12`, gt=`43`, coverage=`0.279`, lines=['2.7', '2.6', '2.5', '2.4', '2.3', '2.2']
- `qemu/CVE-2020-14415`: candidates=`12`, gt=`1`, coverage=`1.000`, lines=['4.2', '4.1', '4.0', '3.1', '3.0', '2.12']
- `qemu/CVE-2020-15863`: candidates=`12`, gt=`69`, coverage=`0.174`, lines=['5.0', '4.2', '4.1', '4.0', '3.1', '3.0']
- `qemu/CVE-2020-1711`: candidates=`12`, gt=`12`, coverage=`0.917`, lines=['4.2', '4.1', '4.0', '3.1', '3.0', '2.12']
- `qemu/CVE-2020-25084`: candidates=`11`, gt=`64`, coverage=`0.172`, lines=['5.0', '5.1', '4.2', '4.1', '4.0', '3.1']
- `qemu/CVE-2020-25085`: candidates=`11`, gt=`59`, coverage=`0.186`, lines=['5.0', '5.1', '4.2', '4.1', '4.0', '3.1']
- `qemu/CVE-2020-25624`: candidates=`11`, gt=`93`, coverage=`0.118`, lines=['5.0', '5.1', '4.2', '4.1', '4.0', '3.1']
- `qemu/CVE-2020-25625`: candidates=`11`, gt=`115`, coverage=`0.096`, lines=['5.0', '5.1', '4.2', '4.1', '4.0', '3.1']
- `qemu/CVE-2020-25723`: candidates=`11`, gt=`72`, coverage=`0.153`, lines=['5.0', '5.1', '4.2', '4.1', '4.0', '3.1']
- `qemu/CVE-2020-27661`: candidates=`11`, gt=`1`, coverage=`1.000`, lines=['5.0', '5.1', '4.2', '4.1', '4.0', '3.1']
- `qemu/CVE-2020-35517`: candidates=`11`, gt=`1`, coverage=`1.000`, lines=['5.0', '5.1', '4.2', '4.1', '4.0', '3.1']
- `qemu/CVE-2021-3409`: candidates=`11`, gt=`60`, coverage=`0.183`, lines=['5.0', '5.1', '4.2', '4.1', '4.0', '3.1']
- `qemu/CVE-2021-20181`: candidates=`10`, gt=`73`, coverage=`0.137`, lines=['5.2', '5.0', '5.1', '4.2', '4.1', '4.0']

## Worst Coverage Misses

- `qemu/CVE-2021-3507`: covered=`8/107`, candidates=`8`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1', 'v3.0.0', 'v1.3.1', 'v2.3.0']`
- `qemu/CVE-2020-25625`: covered=`11/115`, candidates=`11`, unmapped=`['v1.4.1', 'v0.4.4', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1', 'v0.1.1', 'v3.0.0']`
- `qemu/CVE-2022-0216`: covered=`8/76`, candidates=`8`, unmapped=`['v1.4.1', 'v2.5.0', 'v0.15.1', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v2.4.1']`
- `qemu/CVE-2021-20221`: covered=`10/94`, candidates=`10`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1', 'v3.0.0', 'v1.3.1', 'v2.3.0']`
- `qemu/CVE-2020-13361`: covered=`10/93`, candidates=`12`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1', 'v1.3.1', 'v2.3.0', 'v2.11.1']`
- `qemu/CVE-2021-20257`: covered=`10/93`, candidates=`10`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1', 'v3.0.0', 'v1.3.1', 'v2.3.0']`
- `qemu/CVE-2021-4206`: covered=`9/83`, candidates=`9`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1', 'v3.0.0', 'v1.3.1', 'v2.3.0']`
- `qemu/CVE-2020-25624`: covered=`11/93`, candidates=`11`, unmapped=`['v1.4.1', 'v2.9.0', 'v1.2.2', 'v1.7.0', 'v0.14.1', 'v3.0.0', 'v1.3.1', 'v2.3.0']`
- `qemu/CVE-2021-3930`: covered=`9/76`, candidates=`10`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v1.7.0', 'v2.4.1']`
- `qemu/CVE-2021-3748`: covered=`8/67`, candidates=`10`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.6.0', 'v1.7.0', 'v2.4.1', 'v2.2.0']`
- `qemu/CVE-2021-3527`: covered=`9/74`, candidates=`10`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v1.7.0', 'v2.4.1']`
- `qemu/CVE-2021-20181`: covered=`10/73`, candidates=`10`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v1.7.0', 'v2.4.1']`
- `qemu/CVE-2021-3682`: covered=`10/73`, candidates=`10`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v1.7.0', 'v2.4.1']`
- `qemu/CVE-2021-3416`: covered=`10/71`, candidates=`10`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v1.7.0', 'v2.4.1']`
- `qemu/CVE-2021-3713`: covered=`9/63`, candidates=`10`, unmapped=`['v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.6.0', 'v1.7.0', 'v2.4.1', 'v1.6.2', 'v2.0.0']`
- `qemu/CVE-2021-4207`: covered=`9/61`, candidates=`9`, unmapped=`['v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.6.0', 'v1.7.0', 'v2.4.1', 'v1.6.2', 'v2.0.0']`
- `qemu/CVE-2020-25723`: covered=`11/72`, candidates=`11`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v1.7.0', 'v2.4.1']`
- `qemu/CVE-2021-20203`: covered=`10/64`, candidates=`10`, unmapped=`['v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.6.0', 'v1.7.0', 'v2.4.1', 'v1.6.2', 'v2.0.0']`
- `qemu/CVE-2020-12829`: covered=`12/76`, candidates=`12`, unmapped=`['v1.4.1', 'v2.5.0', 'v0.15.1', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v1.7.0']`
- `qemu/CVE-2020-25084`: covered=`11/64`, candidates=`11`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.6.0', 'v1.7.0', 'v2.4.1', 'v1.6.2']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
