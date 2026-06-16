# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `68`

## Overall

- avg candidate tags/CVE: `169.13`
- median candidate tags/CVE: `168.5`
- max candidate tags/CVE: `191`
- avg GT coverage rate: `0.9918`
- full GT coverage CVEs: `64/68`
- coverage miss CVEs: `4`
- frontier statuses: `{'known': 68}`

## Per Repo

### curl
- CVEs: `68`
- avg/median/max candidates: `169.13` / `168.5` / `191`
- avg GT coverage: `0.9918`
- full coverage CVEs: `64/68`
- frontier statuses: `{'known': 68}`
- most expensive CVEs:
  - `CVE-2024-9681`: candidates=`191`, gt=`37`, coverage=`1.000`
  - `CVE-2024-8096`: candidates=`189`, gt=`86`, coverage=`1.000`
  - `CVE-2024-7264`: candidates=`188`, gt=`95`, coverage=`1.000`
  - `CVE-2024-6197`: candidates=`187`, gt=`4`, coverage=`1.000`
  - `CVE-2024-6874`: candidates=`187`, gt=`1`, coverage=`1.000`
- worst coverage misses:
  - `CVE-2020-8284`: covered=`154/191`, candidates=`154`, unmapped=`['curl-4_4', 'curl-5_4', 'curl-5_2_1', 'curl-4_7', 'curl-4_0']`
  - `CVE-2022-27774`: covered=`165/188`, candidates=`165`, unmapped=`['curl-5_4', 'curl-5_2_1', 'curl-7_1', 'curl-5_2', 'curl-6_3']`
  - `CVE-2022-27776`: covered=`165/188`, candidates=`165`, unmapped=`['curl-5_4', 'curl-5_2_1', 'curl-7_1', 'curl-5_2', 'curl-6_3']`
  - `CVE-2022-35252`: covered=`168/191`, candidates=`168`, unmapped=`['curl-5_4', 'curl-5_2_1', 'curl-7_1', 'curl-5_2', 'curl-6_3']`

## Top Expensive CVEs

- `curl/CVE-2024-9681`: candidates=`191`, gt=`37`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-8096`: candidates=`189`, gt=`86`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-7264`: candidates=`188`, gt=`95`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-6197`: candidates=`187`, gt=`4`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-6874`: candidates=`187`, gt=`1`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-2004`: candidates=`184`, gt=`16`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-2379`: candidates=`184`, gt=`1`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-2398`: candidates=`184`, gt=`77`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-2466`: candidates=`184`, gt=`2`, coverage=`1.000`, lines=['main']
- `curl/CVE-2024-0853`: candidates=`183`, gt=`1`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-46218`: candidates=`182`, gt=`73`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-46219`: candidates=`182`, gt=`15`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-38545`: candidates=`181`, gt=`34`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-38546`: candidates=`181`, gt=`163`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-38039`: candidates=`180`, gt=`13`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-28319`: candidates=`175`, gt=`12`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-28320`: candidates=`175`, gt=`150`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-28321`: candidates=`175`, gt=`137`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-28322`: candidates=`175`, gt=`164`, coverage=`1.000`, lines=['main']
- `curl/CVE-2023-27533`: candidates=`173`, gt=`162`, coverage=`1.000`, lines=['main']

## Worst Coverage Misses

- `curl/CVE-2020-8284`: covered=`154/191`, candidates=`154`, unmapped=`['curl-4_4', 'curl-5_4', 'curl-5_2_1', 'curl-4_7', 'curl-4_0', 'curl-4_8', 'curl-7_1', 'curl-5_2']`
- `curl/CVE-2022-27774`: covered=`165/188`, candidates=`165`, unmapped=`['curl-5_4', 'curl-5_2_1', 'curl-7_1', 'curl-5_2', 'curl-6_3', 'curl-5_3', 'curl-4_10', 'curl-6_3_1']`
- `curl/CVE-2022-27776`: covered=`165/188`, candidates=`165`, unmapped=`['curl-5_4', 'curl-5_2_1', 'curl-7_1', 'curl-5_2', 'curl-6_3', 'curl-5_3', 'curl-4_10', 'curl-6_3_1']`
- `curl/CVE-2022-35252`: covered=`168/191`, candidates=`168`, unmapped=`['curl-5_4', 'curl-5_2_1', 'curl-7_1', 'curl-5_2', 'curl-6_3', 'curl-5_3', 'curl-4_10', 'curl-6_3_1']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
