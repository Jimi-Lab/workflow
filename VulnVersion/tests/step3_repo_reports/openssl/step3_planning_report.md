# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `50`

## Overall

- avg candidate tags/CVE: `109.58`
- median candidate tags/CVE: `122.0`
- max candidate tags/CVE: `141`
- avg GT coverage rate: `0.5166`
- full GT coverage CVEs: `14/50`
- coverage miss CVEs: `36`
- frontier statuses: `{'probe_small': 54, 'unknown': 938, 'known': 49, 'pruned': 159}`

## Per Repo

### openssl
- CVEs: `50`
- avg/median/max candidates: `109.58` / `122.0` / `141`
- avg GT coverage: `0.5166`
- full coverage CVEs: `14/50`
- frontier statuses: `{'probe_small': 54, 'unknown': 938, 'known': 49, 'pruned': 159}`
- most expensive CVEs:
  - `CVE-2024-4603`: candidates=`141`, gt=`23`, coverage=`0.957`
  - `CVE-2023-5678`: candidates=`140`, gt=`64`, coverage=`0.516`
  - `CVE-2023-6237`: candidates=`140`, gt=`19`, coverage=`0.947`
  - `CVE-2022-3996`: candidates=`135`, gt=`8`, coverage=`1.000`
  - `CVE-2022-4203`: candidates=`135`, gt=`8`, coverage=`1.000`
- worst coverage misses:
  - `CVE-2022-2274`: covered=`0/1`, candidates=`96`, unmapped=`['openssl-3.0.4']`
  - `CVE-2023-6129`: covered=`1/19`, candidates=`117`, unmapped=`['openssl-3.0.1', 'openssl-3.0.8', 'openssl-3.1.1', 'openssl-3.0.5', 'openssl-3.0.12']`
  - `CVE-2024-6119`: covered=`2/27`, candidates=`113`, unmapped=`['openssl-3.0.1', 'openssl-3.0.8', 'openssl-3.1.1', 'openssl-3.0.14', 'openssl-3.0.5']`
  - `CVE-2023-1255`: covered=`1/10`, candidates=`122`, unmapped=`['openssl-3.0.7', 'openssl-3.0.1', 'openssl-3.0.0', 'openssl-3.0.8', 'openssl-3.0.4']`
  - `CVE-2023-2975`: covered=`2/12`, candidates=`123`, unmapped=`['openssl-3.0.7', 'openssl-3.0.1', 'openssl-3.0.9', 'openssl-3.0.0', 'openssl-3.0.8']`

## Top Expensive CVEs

- `openssl/CVE-2024-4603`: candidates=`141`, gt=`23`, coverage=`0.957`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-5678`: candidates=`140`, gt=`64`, coverage=`0.516`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-6237`: candidates=`140`, gt=`19`, coverage=`0.947`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-3996`: candidates=`135`, gt=`8`, coverage=`1.000`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-4203`: candidates=`135`, gt=`8`, coverage=`1.000`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-4304`: candidates=`135`, gt=`58`, coverage=`0.483`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-4450`: candidates=`135`, gt=`28`, coverage=`0.429`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-0215`: candidates=`135`, gt=`58`, coverage=`0.431`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-0216`: candidates=`135`, gt=`8`, coverage=`1.000`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-0217`: candidates=`135`, gt=`8`, coverage=`1.000`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-0286`: candidates=`135`, gt=`50`, coverage=`0.400`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-0401`: candidates=`135`, gt=`8`, coverage=`1.000`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-3602`: candidates=`134`, gt=`7`, coverage=`1.000`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-3786`: candidates=`134`, gt=`7`, coverage=`1.000`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-3358`: candidates=`125`, gt=`6`, coverage=`1.000`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-5363`: candidates=`125`, gt=`16`, coverage=`0.250`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-2097`: candidates=`124`, gt=`22`, coverage=`0.273`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-4807`: candidates=`124`, gt=`37`, coverage=`0.270`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2022-2068`: candidates=`123`, gt=`42`, coverage=`0.286`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']
- `openssl/CVE-2023-2975`: candidates=`123`, gt=`12`, coverage=`0.167`, lines=['3.0', '3.3', '3.4', '3.5', '3.6', '3.2', '3.1', '1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', '0.9.8', '1.0.0', 'fips-1.2', '0.9.7', 'fips-1.0', 'engine-0.9.6', '0.9.6', '0.9.5', '0.9.4', '0.9.3', '0.9.2', '0.9.1']

## Worst Coverage Misses

- `openssl/CVE-2022-2274`: covered=`0/1`, candidates=`96`, unmapped=`['openssl-3.0.4']`
- `openssl/CVE-2023-6129`: covered=`1/19`, candidates=`117`, unmapped=`['openssl-3.0.1', 'openssl-3.0.8', 'openssl-3.1.1', 'openssl-3.0.5', 'openssl-3.0.12', 'openssl-3.0.9', 'openssl-3.0.0', 'openssl-3.0.4']`
- `openssl/CVE-2024-6119`: covered=`2/27`, candidates=`113`, unmapped=`['openssl-3.0.1', 'openssl-3.0.8', 'openssl-3.1.1', 'openssl-3.0.14', 'openssl-3.0.5', 'openssl-3.0.12', 'openssl-3.1.6', 'openssl-3.0.9']`
- `openssl/CVE-2023-1255`: covered=`1/10`, candidates=`122`, unmapped=`['openssl-3.0.7', 'openssl-3.0.1', 'openssl-3.0.0', 'openssl-3.0.8', 'openssl-3.0.4', 'openssl-3.0.2', 'openssl-3.0.5', 'openssl-3.0.3']`
- `openssl/CVE-2023-2975`: covered=`2/12`, candidates=`123`, unmapped=`['openssl-3.0.7', 'openssl-3.0.1', 'openssl-3.0.9', 'openssl-3.0.0', 'openssl-3.0.8', 'openssl-3.0.2', 'openssl-3.0.4', 'openssl-3.0.5']`
- `openssl/CVE-2024-4741`: covered=`9/47`, candidates=`112`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'openssl-3.0.1', 'openssl-3.0.8', 'openssl-3.1.1', 'openssl-3.0.5', 'OpenSSL_1_1_1n', 'openssl-3.0.12']`
- `openssl/CVE-2024-2511`: covered=`10/46`, candidates=`118`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'openssl-3.0.1', 'openssl-3.0.8', 'openssl-3.1.1', 'openssl-3.0.5', 'OpenSSL_1_1_1n', 'openssl-3.0.12']`
- `openssl/CVE-2020-1971`: covered=`23/105`, candidates=`27`, unmapped=`['OpenSSL_1_0_1r', 'OpenSSL-fips-2_0_12', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2p', 'OpenSSL-fips-2_0_13', 'OpenSSL_1_0_2m', 'OpenSSL-fips-2_0_8', 'OpenSSL_1_0_1b']`
- `openssl/CVE-2021-4160`: covered=`9/36`, candidates=`120`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'OpenSSL_1_0_2f', 'OpenSSL_1_1_1b', 'OpenSSL_1_1_1c', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2i', 'OpenSSL_1_1_1a']`
- `openssl/CVE-2023-5363`: covered=`4/16`, candidates=`125`, unmapped=`['openssl-3.0.11', 'openssl-3.0.7', 'openssl-3.0.1', 'openssl-3.0.9', 'openssl-3.0.0', 'openssl-3.0.8', 'openssl-3.0.4', 'openssl-3.0.2']`
- `openssl/CVE-2024-0727`: covered=`17/65`, candidates=`117`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'openssl-3.0.1', 'OpenSSL_1_0_2f', 'openssl-3.0.8', 'openssl-3.1.1', 'openssl-3.0.5', 'OpenSSL_1_1_1n']`
- `openssl/CVE-2022-0778`: covered=`10/38`, candidates=`121`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'OpenSSL_1_0_2f', 'OpenSSL_1_1_1c', 'OpenSSL_1_1_1b', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2i', 'OpenSSL_1_1_1a']`
- `openssl/CVE-2023-0466`: covered=`14/53`, candidates=`122`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'openssl-3.0.1', 'OpenSSL_1_0_2f', 'openssl-3.0.8', 'openssl-3.0.5', 'OpenSSL_1_1_1n', 'OpenSSL_1_1_1c']`
- `openssl/CVE-2023-4807`: covered=`10/37`, candidates=`124`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'openssl-3.0.1', 'openssl-3.0.8', 'openssl-3.0.5', 'OpenSSL_1_1_1n', 'OpenSSL_1_1_1c', 'OpenSSL_1_1_1b']`
- `openssl/CVE-2022-2097`: covered=`6/22`, candidates=`124`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'OpenSSL_1_1_1n', 'OpenSSL_1_1_1c', 'OpenSSL_1_1_1b', 'OpenSSL_1_1_1a', 'OpenSSL_1_1_1o', 'OpenSSL_1_1_1e']`
- `openssl/CVE-2022-1292`: covered=`11/40`, candidates=`122`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'OpenSSL_1_0_2f', 'OpenSSL_1_1_1n', 'OpenSSL_1_1_1c', 'OpenSSL_1_1_1b', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2i']`
- `openssl/CVE-2023-3446`: covered=`16/56`, candidates=`123`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'openssl-3.0.1', 'OpenSSL_1_0_2f', 'openssl-3.0.8', 'openssl-3.0.5', 'OpenSSL_1_1_1n', 'OpenSSL_1_1_1c']`
- `openssl/CVE-2022-2068`: covered=`12/42`, candidates=`123`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'OpenSSL_1_0_2f', 'OpenSSL_1_1_1n', 'OpenSSL_1_1_1c', 'OpenSSL_1_1_1b', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2i']`
- `openssl/CVE-2021-23841`: covered=`14/45`, candidates=`28`, unmapped=`['OpenSSL_1_0_2f', 'OpenSSL_1_0_2n', 'OpenSSL_1_1_0g', 'OpenSSL_1_0_2e', 'OpenSSL_1_1_0b', 'OpenSSL_1_1_0', 'OpenSSL_1_0_2i', 'OpenSSL_1_0_2p']`
- `openssl/CVE-2023-2650`: covered=`21/65`, candidates=`122`, unmapped=`['OpenSSL_1_1_1f', 'OpenSSL_1_1_1g', 'openssl-3.0.1', 'OpenSSL_1_0_2f', 'openssl-3.0.8', 'openssl-3.0.5', 'OpenSSL_1_1_1n', 'OpenSSL_1_1_1b']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
