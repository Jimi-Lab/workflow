@echo off
cd /d E:\AI\Agent\workflow\VulnVersion
"D:\CodeTools\Language\Python\python.exe" tests\run_vet_case_review_81.py --dataset tests\vet_taxonomy_corpus\BaseDataOrder_vet_case_study_81.json --selected-cases tests\vet_taxonomy_corpus\selected_cases.json --vet-seeds tests\vet_taxonomy_corpus\vet_archetype_seed.jsonl --stage expanded_27_v2 --out tests\vet_taxonomy_case_review\expanded_27_v2 --enable-readonly-git-tools --resume --retry-agent-failed --timeout-s 1200 > "
E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_case_review\expanded_27_v2\real_opencode_20260519_123338.stdout.log
" 2> "
E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_case_review\expanded_27_v2\real_opencode_20260519_123338.stderr.log
"
echo EXIT=%ERRORLEVEL% > "
E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_case_review\expanded_27_v2\real_opencode_20260519_123338.exit.txt
"
