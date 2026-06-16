# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `50`

## Overall

- avg candidate tags/CVE: `236.5`
- median candidate tags/CVE: `227.0`
- max candidate tags/CVE: `470`
- avg GT coverage rate: `0.6674`
- full GT coverage CVEs: `23/50`
- coverage miss CVEs: `27`
- frontier statuses: `{'known': 159, 'pruned': 339, 'unknown': 383, 'probe_small': 719}`

## Per Repo

### wireshark
- CVEs: `50`
- avg/median/max candidates: `236.5` / `227.0` / `470`
- avg GT coverage: `0.6674`
- full coverage CVEs: `23/50`
- frontier statuses: `{'known': 159, 'pruned': 339, 'unknown': 383, 'probe_small': 719}`
- most expensive CVEs:
  - `CVE-2020-25863`: candidates=`470`, gt=`158`, coverage=`1.000`
  - `CVE-2020-13164`: candidates=`464`, gt=`369`, coverage=`0.642`
  - `CVE-2020-11647`: candidates=`462`, gt=`330`, coverage=`0.676`
  - `CVE-2020-9428`: candidates=`460`, gt=`92`, coverage=`1.000`
  - `CVE-2020-9430`: candidates=`460`, gt=`186`, coverage=`0.925`
- worst coverage misses:
  - `CVE-2022-3190`: covered=`24/124`, candidates=`125`, unmapped=`['wireshark-3.4.11', 'v3.0.2', 'v3.0.0', 'v3.6.3', 'wireshark-3.4.12']`
  - `CVE-2024-24476`: covered=`118/485`, candidates=`120`, unmapped=`['wireshark-3.4.11', 'v1.10.8', 'wireshark-1.10.10', 'v3.6.20', 'v3.6.12']`
  - `CVE-2024-24478`: covered=`118/477`, candidates=`120`, unmapped=`['wireshark-3.4.11', 'v1.10.8', 'wireshark-1.10.10', 'v3.6.20', 'v3.6.12']`
  - `CVE-2022-0581`: covered=`59/190`, candidates=`107`, unmapped=`['wireshark-1.10.4', 'v1.10.8', 'wireshark-1.4.2', 'wireshark-1.10.10', 'v1.8.0']`
  - `CVE-2020-7045`: covered=`72/206`, candidates=`312`, unmapped=`['wireshark-2.0.2', 'v2.0.8', 'wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9']`

## Top Expensive CVEs

- `wireshark/CVE-2020-25863`: candidates=`470`, gt=`158`, coverage=`1.000`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-13164`: candidates=`464`, gt=`369`, coverage=`0.642`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-11647`: candidates=`462`, gt=`330`, coverage=`0.676`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-9428`: candidates=`460`, gt=`92`, coverage=`1.000`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-9430`: candidates=`460`, gt=`186`, coverage=`0.925`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-9431`: candidates=`460`, gt=`232`, coverage=`0.802`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-17498`: candidates=`324`, gt=`13`, coverage=`1.000`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-15466`: candidates=`322`, gt=`244`, coverage=`0.352`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-7044`: candidates=`314`, gt=`4`, coverage=`1.000`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2020-7045`: candidates=`312`, gt=`206`, coverage=`0.350`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6', '1.4', '1.2', '1.0', '0.99', 'main']
- `wireshark/CVE-2021-39920`: candidates=`227`, gt=`21`, coverage=`1.000`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-39921`: candidates=`227`, gt=`61`, coverage=`1.000`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-39922`: candidates=`227`, gt=`371`, coverage=`0.426`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-39923`: candidates=`227`, gt=`393`, coverage=`0.402`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-39924`: candidates=`227`, gt=`387`, coverage=`0.450`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-39925`: candidates=`227`, gt=`344`, coverage=`0.448`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-39926`: candidates=`227`, gt=`21`, coverage=`1.000`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-39928`: candidates=`227`, gt=`171`, coverage=`0.626`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-39929`: candidates=`227`, gt=`171`, coverage=`0.626`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']
- `wireshark/CVE-2021-4181`: candidates=`227`, gt=`51`, coverage=`1.000`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.8', '1.10', '1.11', '1.6']

## Worst Coverage Misses

- `wireshark/CVE-2022-3190`: covered=`24/124`, candidates=`125`, unmapped=`['wireshark-3.4.11', 'v3.0.2', 'v3.0.0', 'v3.6.3', 'wireshark-3.4.12', 'wireshark-3.6.3', 'v3.2.7', 'v3.4.11']`
- `wireshark/CVE-2024-24476`: covered=`118/485`, candidates=`120`, unmapped=`['wireshark-3.4.11', 'v1.10.8', 'wireshark-1.10.10', 'v3.6.20', 'v3.6.12', 'wireshark-1.8.11', 'wireshark-3.6.11', 'v3.6.15']`
- `wireshark/CVE-2024-24478`: covered=`118/477`, candidates=`120`, unmapped=`['wireshark-3.4.11', 'v1.10.8', 'wireshark-1.10.10', 'v3.6.20', 'v3.6.12', 'wireshark-1.8.11', 'wireshark-3.6.11', 'v3.6.15']`
- `wireshark/CVE-2022-0581`: covered=`59/190`, candidates=`107`, unmapped=`['wireshark-1.10.4', 'v1.10.8', 'wireshark-1.4.2', 'wireshark-1.10.10', 'v1.8.0', 'wireshark-1.8.11', 'wireshark-1.10.1', 'wireshark-1.6.2']`
- `wireshark/CVE-2020-7045`: covered=`72/206`, candidates=`312`, unmapped=`['wireshark-2.0.2', 'v2.0.8', 'wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'wireshark-1.12.10', 'v2.2.11']`
- `wireshark/CVE-2020-15466`: covered=`86/244`, candidates=`322`, unmapped=`['wireshark-2.0.2', 'v2.0.8', 'wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'wireshark-1.12.7', 'wireshark-1.12.10']`
- `wireshark/CVE-2020-26421`: covered=`133/376`, candidates=`189`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2', 'wireshark-1.2.0', 'wireshark-1.6.6']`
- `wireshark/CVE-2021-4185`: covered=`167/455`, candidates=`227`, unmapped=`['v1.10.8', 'v4.4.0', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-4.0.11', 'wireshark-1.10.1', 'wireshark-2.2.11', 'wireshark-1.6.2']`
- `wireshark/CVE-2021-22191`: covered=`148/401`, candidates=`189`, unmapped=`['v4.4.0', 'v3.6.20', 'v3.6.15', 'wireshark-4.0.11', 'wireshark-2.2.11', 'wireshark-3.6.11', 'v3.6.12', 'v4.0.11']`
- `wireshark/CVE-2022-0583`: covered=`168/446`, candidates=`227`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2', 'wireshark-1.0.0', 'wireshark-1.2.0']`
- `wireshark/CVE-2021-39923`: covered=`158/393`, candidates=`227`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2', 'wireshark-1.6.6', 'wireshark-2.2.7']`
- `wireshark/CVE-2020-25862`: covered=`64/158`, candidates=`167`, unmapped=`['wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'v2.2.11', 'wireshark-2.6.5', 'wireshark-2.2.7', 'v2.2.8']`
- `wireshark/CVE-2021-39922`: covered=`158/371`, candidates=`227`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.6', 'wireshark-2.2.7', 'wireshark-2.4.8']`
- `wireshark/CVE-2022-0586`: covered=`168/388`, candidates=`227`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2', 'wireshark-1.6.6', 'wireshark-2.2.7']`
- `wireshark/CVE-2021-39925`: covered=`154/344`, candidates=`227`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-2.2.7', 'wireshark-2.4.8', 'v2.0.7']`
- `wireshark/CVE-2022-0582`: covered=`178/397`, candidates=`227`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2', 'wireshark-1.6.6', 'wireshark-2.2.7']`
- `wireshark/CVE-2021-39924`: covered=`174/387`, candidates=`227`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.6', 'wireshark-2.2.7', 'wireshark-2.4.8']`
- `wireshark/CVE-2020-28030`: covered=`104/226`, candidates=`162`, unmapped=`['wireshark-2.0.2', 'v2.0.8', 'wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'v2.2.11', 'wireshark-2.6.5']`
- `wireshark/CVE-2020-26420`: covered=`82/176`, candidates=`189`, unmapped=`['wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'v2.2.11', 'wireshark-2.6.5', 'wireshark-2.2.7', 'v2.2.8']`
- `wireshark/CVE-2021-22207`: covered=`102/218`, candidates=`189`, unmapped=`['v2.0.8', 'wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'v2.2.11', 'wireshark-2.6.5', 'wireshark-2.0.4']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
