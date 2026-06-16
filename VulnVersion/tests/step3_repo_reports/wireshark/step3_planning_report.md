# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- repos tested: `1`
- CVEs tested: `50`

## Overall

- avg candidate tags/CVE: `28.7`
- median candidate tags/CVE: `12.0`
- max candidate tags/CVE: `121`
- avg GT coverage rate: `0.117`
- full GT coverage CVEs: `4/50`
- coverage miss CVEs: `46`
- frontier statuses: `{'known': 159, 'pruned': 1105, 'probe_small': 200, 'unknown': 136}`

## Per Repo

### wireshark
- CVEs: `50`
- avg/median/max candidates: `28.7` / `12.0` / `121`
- avg GT coverage: `0.117`
- full coverage CVEs: `4/50`
- frontier statuses: `{'known': 159, 'pruned': 1105, 'probe_small': 200, 'unknown': 136}`
- most expensive CVEs:
  - `CVE-2020-25863`: candidates=`121`, gt=`158`, coverage=`0.348`
  - `CVE-2020-13164`: candidates=`115`, gt=`369`, coverage=`0.122`
  - `CVE-2020-11647`: candidates=`113`, gt=`330`, coverage=`0.142`
  - `CVE-2020-9428`: candidates=`111`, gt=`92`, coverage=`0.402`
  - `CVE-2020-9430`: candidates=`111`, gt=`186`, coverage=`0.220`
- worst coverage misses:
  - `CVE-2021-22235`: covered=`0/4`, candidates=`12`, unmapped=`['v3.2.14', 'wireshark-3.2.14', 'v3.4.6', 'wireshark-3.4.6']`
  - `CVE-2020-26419`: covered=`0/2`, candidates=`12`, unmapped=`['v3.4.0', 'wireshark-3.4.0']`
  - `CVE-2021-4184`: covered=`0/2`, candidates=`10`, unmapped=`['wireshark-3.6.0', 'v3.6.0']`
  - `CVE-2022-0583`: covered=`3/446`, candidates=`10`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11']`
  - `CVE-2021-39923`: covered=`3/393`, candidates=`10`, unmapped=`['wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11']`

## Top Expensive CVEs

- `wireshark/CVE-2020-25863`: candidates=`121`, gt=`158`, coverage=`0.348`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.1']
- `wireshark/CVE-2020-13164`: candidates=`115`, gt=`369`, coverage=`0.122`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.1']
- `wireshark/CVE-2020-11647`: candidates=`113`, gt=`330`, coverage=`0.142`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.1']
- `wireshark/CVE-2020-9428`: candidates=`111`, gt=`92`, coverage=`0.402`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.1']
- `wireshark/CVE-2020-9430`: candidates=`111`, gt=`186`, coverage=`0.220`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.1']
- `wireshark/CVE-2020-9431`: candidates=`111`, gt=`232`, coverage=`0.177`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.1']
- `wireshark/CVE-2020-17498`: candidates=`73`, gt=`13`, coverage=`1.000`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.9']
- `wireshark/CVE-2020-15466`: candidates=`71`, gt=`244`, coverage=`0.070`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.9']
- `wireshark/CVE-2020-7044`: candidates=`63`, gt=`4`, coverage=`1.000`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.9']
- `wireshark/CVE-2020-7045`: candidates=`61`, gt=`206`, coverage=`0.034`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.9']
- `wireshark/CVE-2020-25862`: candidates=`51`, gt=`158`, coverage=`0.222`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '2.6', '3.0', '3.1', '2.4', '2.9', '2.5']
- `wireshark/CVE-2022-0581`: candidates=`20`, gt=`190`, coverage=`0.032`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '2.6', '3.0', '2.4', '2.2', '2.5', '2.0', '1.12', '2.1', '1.99', '1.11']
- `wireshark/CVE-2020-9429`: candidates=`17`, gt=`37`, coverage=`0.243`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '2.6', '3.0', '3.1', '2.9']
- `wireshark/CVE-2020-25866`: candidates=`13`, gt=`46`, coverage=`0.087`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.3', '3.0', '3.1', '2.9']
- `wireshark/CVE-2020-26575`: candidates=`13`, gt=`130`, coverage=`0.046`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.3', '3.0', '3.1']
- `wireshark/CVE-2020-28030`: candidates=`13`, gt=`226`, coverage=`0.035`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.3', '3.0', '3.1']
- `wireshark/CVE-2020-26418`: candidates=`12`, gt=`23`, coverage=`0.130`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.3', '3.1']
- `wireshark/CVE-2020-26419`: candidates=`12`, gt=`2`, coverage=`0.000`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.3', '3.1']
- `wireshark/CVE-2020-26420`: candidates=`12`, gt=`176`, coverage=`0.023`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.3', '3.1']
- `wireshark/CVE-2020-26421`: candidates=`12`, gt=`376`, coverage=`0.011`, lines=['4.4', '4.2', '4.0', '3.6', '3.4', '3.2', '3.3', '3.1']

## Worst Coverage Misses

- `wireshark/CVE-2021-22235`: covered=`0/4`, candidates=`12`, unmapped=`['v3.2.14', 'wireshark-3.2.14', 'v3.4.6', 'wireshark-3.4.6']`
- `wireshark/CVE-2020-26419`: covered=`0/2`, candidates=`12`, unmapped=`['v3.4.0', 'wireshark-3.4.0']`
- `wireshark/CVE-2021-4184`: covered=`0/2`, candidates=`10`, unmapped=`['wireshark-3.6.0', 'v3.6.0']`
- `wireshark/CVE-2022-0583`: covered=`3/446`, candidates=`10`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2']`
- `wireshark/CVE-2021-39923`: covered=`3/393`, candidates=`10`, unmapped=`['wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2', 'wireshark-1.6.6']`
- `wireshark/CVE-2022-0586`: covered=`3/388`, candidates=`10`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2']`
- `wireshark/CVE-2021-39922`: covered=`3/371`, candidates=`10`, unmapped=`['wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.6', 'wireshark-2.2.7']`
- `wireshark/CVE-2021-39925`: covered=`3/344`, candidates=`10`, unmapped=`['wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-2.2.7', 'wireshark-2.4.8']`
- `wireshark/CVE-2020-26421`: covered=`4/376`, candidates=`12`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2', 'wireshark-1.2.0', 'wireshark-1.6.6']`
- `wireshark/CVE-2022-0582`: covered=`5/397`, candidates=`10`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.2']`
- `wireshark/CVE-2021-39924`: covered=`5/387`, candidates=`10`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-2.2.11', 'wireshark-1.10.1', 'wireshark-1.6.6']`
- `wireshark/CVE-2021-4185`: covered=`6/455`, candidates=`10`, unmapped=`['wireshark-3.2.16', 'v1.10.8', 'v4.4.0', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-4.0.11', 'wireshark-1.10.1', 'wireshark-2.2.11']`
- `wireshark/CVE-2024-24476`: covered=`7/485`, candidates=`9`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'v3.6.20', 'v3.6.12', 'wireshark-1.8.11', 'wireshark-4.0.11']`
- `wireshark/CVE-2024-24478`: covered=`7/477`, candidates=`9`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v1.10.8', 'wireshark-1.10.10', 'v3.6.20', 'v3.6.12', 'wireshark-1.8.11', 'wireshark-4.0.11']`
- `wireshark/CVE-2021-39928`: covered=`3/171`, candidates=`10`, unmapped=`['wireshark-3.2.16', 'v3.0.2', 'v2.9.0', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'v3.0.0', 'v3.0.13']`
- `wireshark/CVE-2021-39929`: covered=`3/171`, candidates=`10`, unmapped=`['wireshark-3.2.16', 'v3.0.2', 'v2.9.0', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'v3.0.0', 'v3.0.13']`
- `wireshark/CVE-2021-22207`: covered=`4/218`, candidates=`12`, unmapped=`['v3.0.2', 'v2.9.0', 'v2.0.8', 'wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'v3.0.0']`
- `wireshark/CVE-2020-26420`: covered=`4/176`, candidates=`12`, unmapped=`['v3.0.2', 'v2.9.0', 'wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3', 'v3.0.0', 'v3.0.13']`
- `wireshark/CVE-2022-3190`: covered=`3/124`, candidates=`9`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v3.0.2', 'v3.0.0', 'v3.6.3', 'v3.0.13', 'wireshark-3.4.12', 'v3.4.15']`
- `wireshark/CVE-2021-22191`: covered=`12/401`, candidates=`12`, unmapped=`['wireshark-3.4.11', 'wireshark-3.2.16', 'v4.4.0', 'v3.6.20', 'v3.6.15', 'wireshark-4.0.11', 'wireshark-2.2.11', 'wireshark-3.6.11']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
