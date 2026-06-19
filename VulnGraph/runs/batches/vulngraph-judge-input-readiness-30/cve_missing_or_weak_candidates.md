# Missing Or Weak Judge Candidates

## No Candidate Cases

- CVE-2020-27814: no_blameable_old_side; impossible_reason=current packet materializes only the merge fix commit and no PatchHunk old-side line; a semantic fallback may require importing the second-parent equivalent fix commit, but this run cannot fabricate one

## Fallback Or Weak Cases

- CVE-2020-12284: risks=add_only_semantic_anchor;broad_candidate_range;fallback_candidate;no_model_anchor;non_release_tag_noise; suitable_for_judge=True
- CVE-2020-13904: risks=add_only_semantic_anchor;broad_candidate_range;fallback_candidate;no_model_anchor;non_release_tag_noise; suitable_for_judge=True
- CVE-2020-14212: risks=fallback_candidate;no_model_anchor;non_release_tag_noise; suitable_for_judge=True
- CVE-2020-19667: risks=add_only_semantic_anchor;fallback_candidate;no_model_anchor; suitable_for_judge=True
- CVE-2020-8169: risks=add_only_semantic_anchor;broad_candidate_range;fallback_candidate;no_model_anchor; suitable_for_judge=True
- CVE-2022-0433: risks=add_only_semantic_anchor;broad_candidate_range;fallback_candidate;no_model_anchor;non_release_tag_noise; suitable_for_judge=True
- CVE-2020-1971: risks=add_only_semantic_anchor;fallback_candidate;no_model_anchor;non_release_tag_noise; suitable_for_judge=True
- CVE-2020-15466: risks=fallback_candidate;no_model_anchor;non_release_tag_noise; suitable_for_judge=True

## CVE-2020-27814 Deterministic Analysis

```json
{
  "cve_id": "CVE-2020-27814",
  "no_candidate_reason": "no_blameable_old_side",
  "inventory_candidate_count": 0,
  "fix_patch_classification": "merge_commit_without_materialized_patch_hunks_with_stat_only_code_change",
  "parent_commit_exists": true,
  "old_side_blameable_statement_available": false,
  "semantic_fallback_possible": false,
  "impossible_reason": "current packet materializes only the merge fix commit and no PatchHunk old-side line; a semantic fallback may require importing the second-parent equivalent fix commit, but this run cannot fabricate one",
  "fix_patch_add_only": null,
  "fix_patch_new_file": false,
  "fix_patch_generated_file": false,
  "fix_patch_metadata_only": false,
  "merge_parent_count": 2,
  "second_parent_equivalent_fix_commit": "4ce7d285a55d29b79880d0566d4b010fe1907aa9",
  "packet_patch_hunk_count": 0,
  "old_side_verdict": "not_available_from_current_materialized_merge_commit_packet",
  "semantic_fallback_blocked_by": "missing_materialized_patch_hunk_for_equivalent_fix_commit",
  "deterministic_git_notes": {
    "repo": "E:\\AI\\Agent\\workflow\\VulnVersion\\repo\\openjpeg",
    "fix_commit_sha": "43dd9ee17894a22fa3df88b1e561274632d9ab43",
    "stat_excerpt": "43dd9ee1 Merge pull request #1303 from zodf0055980/fix#1283\n\n src/lib/openjp2/tcd.c | 3 ++-\n 1 file changed, 2 insertions(+), 1 deletion(-)\n",
    "second_parent_stat_excerpt": "4ce7d285 Encoder: grow again buffer size in opj_tcd_code_block_enc_allocate_data() (fixes #1283)\n src/lib/openjp2/tcd.c | 3 ++-\n 1 file changed, 2 insertions(+), 1 deletion(-)\n"
  }
}
```
