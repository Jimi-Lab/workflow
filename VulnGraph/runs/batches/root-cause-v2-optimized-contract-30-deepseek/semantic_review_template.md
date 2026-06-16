# Root Cause Semantic Review Template

For each CVE, inspect packet, evidence trace, parsed output, contract lint, structural validation, and ingestion result before filling `evaluation.csv`.

## CVE-2020-12284

- Repo: `FFmpeg`
- CWE: `['CWE-787', 'CWE-20']`
- Fix commits: `[['1812352d767ccf5431aa440123e2e260a4db2726', '838105153a579ff0cea0794afc0275c19c51d3a7', 'a3a3730b5456ca00587455004d40c047f7b20a99']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-12284`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-13904

- Repo: `FFmpeg`
- CWE: `['CWE-416']`
- Fix commits: `[['8a2ef6d25dc79d472ea7b184c3b95b4658c99838', 'd7abedc90443d6bbd7e956fd53d91b343cba50a8', '6959358683c7533f586c07a766acc5fe9544d8b2', '7dc5dfad31d1bc6cec5f4eb1f9033ce3b715425d', '21ce988f98f2399b8919a8a425d467da682a29a7', '0f6fa27b241676624bab91fc6ecdf8ac01121d29', 'b5e39880fb7269b1b3577cee288e06aa3dc1dfa2', '9dfb19baeb86a8bb02c53a441682c6e9a6e104cc', 'a3fdeb0c3a4ecabab2c2351b86fc92004526e9cc', '57970c41f59319f54879993fc26c55147854c52f', 'f80106e256e051082e507496cdaed564adbd4da9', '2a5219d359933b4d6a4ccf13e241253543fc390e', 'c00e881a450fc465e60f41bd47ea6396a87f3eef', 'bd09c9d46c70ef94d34c91f502326853d3f741ab', 'c229e5e80f1b67b2120f317e815fec29ca1390a5']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-13904`
- Status: `rejected`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-14212

- Repo: `FFmpeg`
- CWE: `['CWE-787']`
- Fix commits: `[['0b3bd001ac1745d9d008a2d195817df57d7d1d14', 'dd273d359e45ab69398ac0dc41206d5f1a9371bf']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-14212`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-10251

- Repo: `ImageMagick`
- CWE: `['CWE-125']`
- Fix commits: `[['868aad754ee599eb7153b84d610f2ecdf7b339f6']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-10251`
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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-19667`
- Status: `parse_error`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-25663

- Repo: `ImageMagick`
- CWE: `['CWE-416']`
- Fix commits: `[['a47e7a994766b92b10d4a87df8c1c890c8b170f3']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-25663`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-8169

- Repo: `curl`
- CWE: `['CWE-200']`
- Fix commits: `[['600a8cded447cd7118ed50142c576567c0cf5158']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-8169`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-8177

- Repo: `curl`
- CWE: `['CWE-74', 'CWE-99']`
- Fix commits: `[['8236aba58542c5f89f1d41ca09d84579efb05e22']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-8177`
- Status: `ingested_raw`

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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-8231`
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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-11984`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-11985

- Repo: `httpd`
- CWE: `['CWE-345']`
- Fix commits: `[['d0c4af10ab713734de906b5634cfc15cd370fdf4']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-11985`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-11993

- Repo: `httpd`
- CWE: `['CWE-444']`
- Fix commits: `[['63a0a87efa0925514d15c211b508f6594669888c', '971fc8f5b5d664ddeb5d22f8adef2137c7980fc7']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-11993`
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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2022-0171`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2022-0185

- Repo: `linux`
- CWE: `['CWE-191', 'CWE-190']`
- Fix commits: `[['722d94847de29310e8aa03fcbdb41fc92c521756']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2022-0185`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2022-0264

- Repo: `linux`
- CWE: `['CWE-755', 'CWE-200']`
- Fix commits: `[['7d3baf0afa3aa9102d6a521a8e4c41888bb79882']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2022-0264`
- Status: `ingested_raw`

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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2022-0286`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2022-0322

- Repo: `linux`
- CWE: `['CWE-704', 'CWE-681']`
- Fix commits: `[['a2d859e3fc97e79d907761550dbc03ff1b36479c']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2022-0322`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2022-0433

- Repo: `linux`
- CWE: `['CWE-476', 'CWE-908']`
- Fix commits: `[['3ccdcee28415c4226de05438b4d89eb5514edf73']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2022-0433`
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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-15389`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-27814

- Repo: `openjpeg`
- CWE: `['CWE-122']`
- Fix commits: `[['43dd9ee17894a22fa3df88b1e561274632d9ab43']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-27814`
- Status: `rejected`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-27823

- Repo: `openjpeg`
- CWE: `['CWE-787', 'CWE-120', 'CWE-20']`
- Fix commits: `[['b2072402b7e14d22bba6fb8cde2a1e9996e9a919']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-27823`
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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-1967`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-1971

- Repo: `openssl`
- CWE: `['CWE-476']`
- Fix commits: `[['f960d81215ebf3f65e03d4d5d857fb9b666d6920']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-1971`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2021-23840

- Repo: `openssl`
- CWE: `['CWE-190']`
- Fix commits: `[['6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2021-23840`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-10702

- Repo: `qemu`
- CWE: `['CWE-325']`
- Fix commits: `[['de0b1bae6461f67243282555475f88b2384a1eb9']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-10702`
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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-11869`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-11947

- Repo: `qemu`
- CWE: `['CWE-125']`
- Fix commits: `[['ff0507c239a246fd7215b31c5658fc6a3ee1e4c5']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-11947`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-11647

- Repo: `wireshark`
- CWE: `['CWE-674', 'CWE-74']`
- Fix commits: `[['6f56fc9496db158218243ea87e3660c874a0bab0']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-11647`
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
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-13164`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。

## CVE-2020-15466

- Repo: `wireshark`
- CWE: `['CWE-835']`
- Fix commits: `[['11f40896b696e4e8c7f8b2ad96028404a83a51a4']]`
- Run dir: `runs\batches\root-cause-v2-optimized-contract-30-deepseek\CVE-2020-15466`
- Status: `ingested_raw`

1. 机制是否解释了真实漏洞原因，而不是只复述补丁。
2. VulnerablePredicate 是否表达漏洞成立条件。
3. FixPredicate 是否表达补丁阻断条件。
4. CodeAnchor 是否指向正确文件、函数、PatchHunk。
5. SUPPORTS 边是否由对应 GitObservation 真实支撑。
6. 是否有 patch/evidence 外的无证据推断。
7. multi-fix 是否覆盖完整 fix_set。
8. 是否把无关重构或上下文误认为 root cause。
