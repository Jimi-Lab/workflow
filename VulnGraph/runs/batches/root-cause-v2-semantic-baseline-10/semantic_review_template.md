# Root Cause Semantic Review Template

For each CVE, inspect packet, evidence trace, parsed output, contract lint, structural validation, and ingestion result before filling `evaluation.csv`.

## CVE-2020-14212

- Repo: `FFmpeg`
- CWE: `['CWE-787']`
- Fix commits: `[['0b3bd001ac1745d9d008a2d195817df57d7d1d14', 'dd273d359e45ab69398ac0dc41206d5f1a9371bf']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2020-14212`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-19667

- Repo: `ImageMagick`
- CWE: `['CWE-787']`
- Fix commits: `[['5462fd4725018567764c8f66bed98b7ee3e23006']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2020-19667`
- Status: `rejected`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-8231

- Repo: `curl`
- CWE: `['CWE-416']`
- Fix commits: `[['3c9e021f86872baae412a427e807fbfa2f3e8a22']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2020-8231`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-11984

- Repo: `httpd`
- CWE: `['CWE-120']`
- Fix commits: `[['0c543e3f5b3881d515d6235f152aacaaaf3aba72', 'fb08e475bf322f081665fa6f9d9e346136df9337']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2020-11984`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2022-0171

- Repo: `linux`
- CWE: `['CWE-212', 'CWE-459']`
- Fix commits: `[['683412ccf61294d727ead4a73d97397396e69a6b']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2022-0171`
- Status: `parse_error`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2022-0286

- Repo: `linux`
- CWE: `['CWE-476']`
- Fix commits: `[['105cd17a866017b45f3c45901b394c711c97bf40']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2022-0286`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-15389

- Repo: `openjpeg`
- CWE: `['CWE-416']`
- Fix commits: `[['e8e258ab049240c2dd1f1051b4e773b21e2d3dc0']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2020-15389`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-1967

- Repo: `openssl`
- CWE: `['CWE-476']`
- Fix commits: `[['eb563247aef3e83dda7679c43f9649270462e5b1']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2020-1967`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-11869

- Repo: `qemu`
- CWE: `['CWE-190']`
- Fix commits: `[['ac2071c3791b67fc7af78b8ceb320c01ca1b5df7']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2020-11869`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-13164

- Repo: `wireshark`
- CWE: `['CWE-674', 'CWE-400']`
- Fix commits: `[['e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a']]`
- Run dir: `runs\batches\root-cause-v2-semantic-baseline-10\CVE-2020-13164`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。
