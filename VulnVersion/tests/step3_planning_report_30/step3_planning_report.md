# Step3 Planning Evaluation

- dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json`
- repos tested: `9`
- CVEs tested: `30`

## Overall

- avg candidate tags/CVE: `57`
- median candidate tags/CVE: `26.0`
- max candidate tags/CVE: `208`
- avg GT coverage rate: `0.6782`
- full GT coverage CVEs: `14/30`
- coverage miss CVEs: `16`
- frontier statuses: `{'pruned': 855, 'known': 25, 'probe_small': 81, 'unknown': 50}`

## Per Repo

### FFmpeg
- CVEs: `3`
- avg/median/max candidates: `32.33` / `11` / `83`
- avg GT coverage: `0.7655`
- full coverage CVEs: `2/3`
- frontier statuses: `{'pruned': 92, 'known': 10, 'probe_small': 3, 'unknown': 3}`
- most expensive CVEs:
  - `CVE-2020-13904`: candidates=`83`, gt=`280`, coverage=`0.296`
  - `CVE-2020-12284`: candidates=`11`, gt=`9`, coverage=`1.000`
  - `CVE-2020-14212`: candidates=`3`, gt=`1`, coverage=`1.000`
- worst coverage misses:
  - `CVE-2020-13904`: covered=`83/280`, candidates=`83`, unmapped=`['n2.1.2', 'n1.1.3', 'n1.1.15', 'n1.1.4', 'n2.1.8']`

### ImageMagick
- CVEs: `3`
- avg/median/max candidates: `194.33` / `201` / `208`
- avg GT coverage: `1.0`
- full coverage CVEs: `3/3`
- frontier statuses: `{'pruned': 3, 'known': 3}`
- most expensive CVEs:
  - `CVE-2020-19667`: candidates=`208`, gt=`208`, coverage=`1.000`
  - `CVE-2020-10251`: candidates=`201`, gt=`51`, coverage=`1.000`
  - `CVE-2020-25663`: candidates=`174`, gt=`12`, coverage=`1.000`

### curl
- CVEs: `3`
- avg/median/max candidates: `150.67` / `150` / `152`
- avg GT coverage: `1.0`
- full coverage CVEs: `3/3`
- frontier statuses: `{'known': 3}`
- most expensive CVEs:
  - `CVE-2020-8231`: candidates=`152`, gt=`62`, coverage=`1.000`
  - `CVE-2020-8169`: candidates=`150`, gt=`14`, coverage=`1.000`
  - `CVE-2020-8177`: candidates=`150`, gt=`68`, coverage=`1.000`

### httpd
- CVEs: `3`
- avg/median/max candidates: `43.33` / `50` / `50`
- avg GT coverage: `0.8828`
- full coverage CVEs: `1/3`
- frontier statuses: `{'known': 3, 'probe_small': 9, 'pruned': 9}`
- most expensive CVEs:
  - `CVE-2020-11984`: candidates=`50`, gt=`14`, coverage=`1.000`
  - `CVE-2020-11993`: candidates=`50`, gt=`28`, coverage=`0.964`
  - `CVE-2020-11985`: candidates=`30`, gt=`38`, coverage=`0.684`
- worst coverage misses:
  - `CVE-2020-11985`: covered=`26/38`, candidates=`30`, unmapped=`['2.3.14', '2.3.7', '2.3.5', '2.3.9', '2.3.11']`
  - `CVE-2020-11993`: covered=`27/28`, candidates=`50`, unmapped=`['2.2.25']`

### linux
- CVEs: `6`
- avg/median/max candidates: `4` / `4.0` / `4`
- avg GT coverage: `0.6183`
- full coverage CVEs: `2/6`
- frontier statuses: `{'pruned': 468, 'probe_small': 24}`
- most expensive CVEs:
  - `CVE-2022-0171`: candidates=`4`, gt=`8`, coverage=`0.500`
  - `CVE-2022-0185`: candidates=`4`, gt=`16`, coverage=`0.250`
  - `CVE-2022-0264`: candidates=`4`, gt=`4`, coverage=`1.000`
  - `CVE-2022-0286`: candidates=`4`, gt=`5`, coverage=`0.800`
  - `CVE-2022-0322`: candidates=`4`, gt=`25`, coverage=`0.160`
- worst coverage misses:
  - `CVE-2022-0322`: covered=`4/25`, candidates=`4`, unmapped=`['v5.0', 'v5.10', 'v4.20', 'v4.15', 'v5.6']`
  - `CVE-2022-0185`: covered=`4/16`, candidates=`4`, unmapped=`['v5.10', 'v5.7', 'v5.8', 'v5.5', 'v5.6']`
  - `CVE-2022-0171`: covered=`4/8`, candidates=`4`, unmapped=`['v5.10', 'v5.12', 'v5.13', 'v5.11']`
  - `CVE-2022-0286`: covered=`4/5`, candidates=`4`, unmapped=`['v5.9']`

### openjpeg
- CVEs: `3`
- avg/median/max candidates: `3` / `3` / `3`
- avg GT coverage: `0.525`
- full coverage CVEs: `0/3`
- frontier statuses: `{'pruned': 30, 'probe_small': 6}`
- most expensive CVEs:
  - `CVE-2020-15389`: candidates=`3`, gt=`8`, coverage=`0.375`
  - `CVE-2020-27814`: candidates=`3`, gt=`5`, coverage=`0.600`
  - `CVE-2020-27823`: candidates=`3`, gt=`5`, coverage=`0.600`
- worst coverage misses:
  - `CVE-2020-15389`: covered=`3/8`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.2.1', 'version.2.0.1', 'v2.1.1']`
  - `CVE-2020-27814`: covered=`3/5`, candidates=`3`, unmapped=`['v2.1.2', 'v2.1.1']`
  - `CVE-2020-27823`: covered=`3/5`, candidates=`3`, unmapped=`['v2.1.2', 'v2.1.1']`

### openssl
- CVEs: `3`
- avg/median/max candidates: `26.67` / `27` / `28`
- avg GT coverage: `0.5313`
- full coverage CVEs: `1/3`
- frontier statuses: `{'pruned': 54, 'known': 3, 'probe_small': 9, 'unknown': 6}`
- most expensive CVEs:
  - `CVE-2021-23840`: candidates=`28`, gt=`32`, coverage=`0.375`
  - `CVE-2020-1971`: candidates=`27`, gt=`105`, coverage=`0.219`
  - `CVE-2020-1967`: candidates=`25`, gt=`3`, coverage=`1.000`
- worst coverage misses:
  - `CVE-2020-1971`: covered=`23/105`, candidates=`27`, unmapped=`['OpenSSL_1_0_1r', 'OpenSSL-fips-2_0_12', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2p', 'OpenSSL-fips-2_0_13']`
  - `CVE-2021-23840`: covered=`12/32`, candidates=`28`, unmapped=`['OpenSSL_1_0_2f', 'OpenSSL_1_0_2n', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2i', 'OpenSSL_1_0_2p']`

### qemu
- CVEs: `3`
- avg/median/max candidates: `12` / `12` / `12`
- avg GT coverage: `0.7292`
- full coverage CVEs: `2/3`
- frontier statuses: `{'pruned': 159, 'probe_small': 18}`
- most expensive CVEs:
  - `CVE-2020-10702`: candidates=`12`, gt=`5`, coverage=`1.000`
  - `CVE-2020-11869`: candidates=`12`, gt=`3`, coverage=`1.000`
  - `CVE-2020-11947`: candidates=`12`, gt=`64`, coverage=`0.188`
- worst coverage misses:
  - `CVE-2020-11947`: covered=`12/64`, candidates=`12`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.2.2']`

### wireshark
- CVEs: `3`
- avg/median/max candidates: `99.67` / `113` / `115`
- avg GT coverage: `0.1113`
- full coverage CVEs: `0/3`
- frontier statuses: `{'unknown': 41, 'known': 3, 'probe_small': 12, 'pruned': 40}`
- most expensive CVEs:
  - `CVE-2020-13164`: candidates=`115`, gt=`369`, coverage=`0.122`
  - `CVE-2020-11647`: candidates=`113`, gt=`330`, coverage=`0.142`
  - `CVE-2020-15466`: candidates=`71`, gt=`244`, coverage=`0.070`
- worst coverage misses:
  - `CVE-2020-15466`: covered=`17/244`, candidates=`71`, unmapped=`['wireshark-1.99.9', 'wireshark-2.0.2', 'v3.0.2', 'v2.0.8', 'wireshark-2.2.11']`
  - `CVE-2020-13164`: covered=`45/369`, candidates=`115`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-1.10.1', 'wireshark-2.2.11']`
  - `CVE-2020-11647`: covered=`47/330`, candidates=`113`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-1.10.1', 'wireshark-2.2.11']`

## Top Expensive CVEs

- `ImageMagick/CVE-2020-19667`: candidates=`208`, gt=`208`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2020-10251`: candidates=`201`, gt=`51`, coverage=`1.000`, lines=['7.0']
- `ImageMagick/CVE-2020-25663`: candidates=`174`, gt=`12`, coverage=`1.000`, lines=['7.0']
- `curl/CVE-2020-8231`: candidates=`152`, gt=`62`, coverage=`1.000`, lines=['main']
- `curl/CVE-2020-8169`: candidates=`150`, gt=`14`, coverage=`1.000`, lines=['main']
- `curl/CVE-2020-8177`: candidates=`150`, gt=`68`, coverage=`1.000`, lines=['main']
- `wireshark/CVE-2020-13164`: candidates=`115`, gt=`369`, coverage=`0.122`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.1']
- `wireshark/CVE-2020-11647`: candidates=`113`, gt=`330`, coverage=`0.142`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.4', '2.9', '2.2', '2.5', '2.1']
- `FFmpeg/CVE-2020-13904`: candidates=`83`, gt=`280`, coverage=`0.296`, lines=['4.2', '3.4', '4.3', '2.8', '4.1', '3.2', '4.0', '3.3', '3.0', '3.1', '2.7']
- `wireshark/CVE-2020-15466`: candidates=`71`, gt=`244`, coverage=`0.070`, lines=['4.4', '4.6', '4.2', '4.0', '4.3', '3.6', '4.1', '3.4', '3.7', '3.2', '3.5', '3.3', '2.6', '3.0', '3.1', '2.9']
- `httpd/CVE-2020-11984`: candidates=`50`, gt=`14`, coverage=`1.000`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2020-11993`: candidates=`50`, gt=`28`, coverage=`0.964`, lines=['2.4', '2.2', '2.3', '2.1']
- `httpd/CVE-2020-11985`: candidates=`30`, gt=`38`, coverage=`0.684`, lines=['2.4', '2.2', '2.3', '2.1']
- `openssl/CVE-2021-23840`: candidates=`28`, gt=`32`, coverage=`0.375`, lines=['1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', 'fips-1.2']
- `openssl/CVE-2020-1971`: candidates=`27`, gt=`105`, coverage=`0.219`, lines=['1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', 'fips-1.2']
- `openssl/CVE-2020-1967`: candidates=`25`, gt=`3`, coverage=`1.000`, lines=['1.1.1', '1.0.2', '1.1.0', 'fips-2.0', '1.0.1', 'fips-1.2']
- `qemu/CVE-2020-10702`: candidates=`12`, gt=`5`, coverage=`1.000`, lines=['4.2', '4.1', '4.0', '3.1', '3.0', '2.12']
- `qemu/CVE-2020-11869`: candidates=`12`, gt=`3`, coverage=`1.000`, lines=['4.2', '4.1', '4.0', '3.1', '3.0', '2.12']
- `qemu/CVE-2020-11947`: candidates=`12`, gt=`64`, coverage=`0.188`, lines=['4.2', '4.1', '4.0', '3.1', '3.0', '2.12']
- `FFmpeg/CVE-2020-12284`: candidates=`11`, gt=`9`, coverage=`1.000`, lines=['4.2', '4.1', '4.0']

## Worst Coverage Misses

- `wireshark/CVE-2020-15466`: covered=`17/244`, candidates=`71`, unmapped=`['wireshark-1.99.9', 'wireshark-2.0.2', 'v3.0.2', 'v2.0.8', 'wireshark-2.2.11', 'wireshark-2.4.7', 'v2.6.9', 'wireshark-2.6.3']`
- `wireshark/CVE-2020-13164`: covered=`45/369`, candidates=`115`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-1.10.1', 'wireshark-2.2.11', 'wireshark-1.6.2', 'wireshark-1.0.0', 'wireshark-1.2.0']`
- `wireshark/CVE-2020-11647`: covered=`47/330`, candidates=`113`, unmapped=`['v1.10.8', 'wireshark-1.10.10', 'wireshark-1.8.11', 'wireshark-1.10.1', 'wireshark-2.2.11', 'wireshark-1.6.2', 'wireshark-1.6.6', 'wireshark-2.2.7']`
- `linux/CVE-2022-0322`: covered=`4/25`, candidates=`4`, unmapped=`['v5.0', 'v5.10', 'v4.20', 'v4.15', 'v5.6', 'v4.13', 'v4.14', 'v5.5']`
- `qemu/CVE-2020-11947`: covered=`12/64`, candidates=`12`, unmapped=`['v1.4.1', 'v2.5.0', 'v2.10.0', 'v2.9.0', 'v1.2.2', 'v1.6.0', 'v1.7.0', 'v2.4.1']`
- `openssl/CVE-2020-1971`: covered=`23/105`, candidates=`27`, unmapped=`['OpenSSL_1_0_1r', 'OpenSSL-fips-2_0_12', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2p', 'OpenSSL-fips-2_0_13', 'OpenSSL_1_0_2m', 'OpenSSL-fips-2_0_8', 'OpenSSL_1_0_1b']`
- `linux/CVE-2022-0185`: covered=`4/16`, candidates=`4`, unmapped=`['v5.10', 'v5.7', 'v5.8', 'v5.5', 'v5.6', 'v5.9', 'v5.12', 'v5.3']`
- `FFmpeg/CVE-2020-13904`: covered=`83/280`, candidates=`83`, unmapped=`['n2.1.2', 'n1.1.3', 'n1.1.15', 'n1.1.4', 'n2.1.8', 'n1.0.2', 'n2.1', 'n0.10.13']`
- `openssl/CVE-2021-23840`: covered=`12/32`, candidates=`28`, unmapped=`['OpenSSL_1_0_2f', 'OpenSSL_1_0_2n', 'OpenSSL_1_0_2e', 'OpenSSL_1_0_2i', 'OpenSSL_1_0_2p', 'OpenSSL_1_0_2b', 'OpenSSL_1_0_2m', 'OpenSSL_1_0_2g']`
- `openjpeg/CVE-2020-15389`: covered=`3/8`, candidates=`3`, unmapped=`['version.2.0', 'v2.1.2', 'version.2.1', 'version.2.0.1', 'v2.1.1']`
- `linux/CVE-2022-0171`: covered=`4/8`, candidates=`4`, unmapped=`['v5.10', 'v5.12', 'v5.13', 'v5.11']`
- `openjpeg/CVE-2020-27814`: covered=`3/5`, candidates=`3`, unmapped=`['v2.1.2', 'v2.1.1']`
- `openjpeg/CVE-2020-27823`: covered=`3/5`, candidates=`3`, unmapped=`['v2.1.2', 'v2.1.1']`
- `httpd/CVE-2020-11985`: covered=`26/38`, candidates=`30`, unmapped=`['2.3.14', '2.3.7', '2.3.5', '2.3.9', '2.3.11', '2.3.6', '2.3.8', '2.3.12']`
- `linux/CVE-2022-0286`: covered=`4/5`, candidates=`4`, unmapped=`['v5.9']`
- `httpd/CVE-2020-11993`: covered=`27/28`, candidates=`50`, unmapped=`['2.2.25']`

## Notes

- This evaluates Step3 planning only; it does not call the backend model.
- Source code under `vulnversion/` is not modified by this script.
- Candidate count is based on `tag_plan.verification_order`.
- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.
