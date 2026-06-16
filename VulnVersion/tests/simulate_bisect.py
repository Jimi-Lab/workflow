"""Simulate binary search on real verdict data to assess accuracy and savings."""
import json
import math
from pathlib import Path
from collections import defaultdict

result_dir = Path(__file__).resolve().parent.parent / "Result"

print("=== Binary Search Simulation on Real Data ===")
print()

grand_total = 0
grand_correct = 0
grand_wrong = 0
grand_llm_saved = 0
grand_llm_linear = 0

for repo_dir in sorted(result_dir.iterdir()):
    if not repo_dir.is_dir():
        continue
    repo = repo_dir.name

    for cve_dir in sorted(repo_dir.iterdir()):
        if not cve_dir.is_dir():
            continue
        cve = cve_dir.name
        vf = cve_dir / "per_tag_verdict.jsonl"
        tp = cve_dir / "tag_plan.json"
        if not vf.exists() or not tp.exists():
            continue

        plan = json.loads(tp.read_text(encoding="utf-8"))
        verdicts = []
        for lt in vf.read_text(encoding="utf-8").splitlines():
            if lt.strip():
                try:
                    verdicts.append(json.loads(lt))
                except Exception:
                    pass

        tag_to_v = {v["tag"]: v for v in verdicts}

        total_tags = 0
        correct = 0
        wrong = 0
        wrong_details = []
        llm_calls_bisect = 0
        llm_calls_linear = 0

        for line_name, lp in plan.get("line_plans", {}).items():
            candidates_asc = lp.get("candidate_tags", [])
            valid = [
                t
                for t in candidates_asc
                if t in tag_to_v and tag_to_v[t].get("run_status") == "OK"
            ]

            if len(valid) < 10:
                llm_calls_linear += len(valid)
                llm_calls_bisect += len(valid)
                total_tags += len(valid)
                correct += len(valid)
                continue

            llm_calls_linear += len(valid)
            total_tags += len(valid)

            oldest = valid[0]
            newest = valid[-1]
            v_oldest = tag_to_v[oldest].get("verdict")
            v_newest = tag_to_v[newest].get("verdict")

            probed_indices = {0, len(valid) - 1}
            llm_calls_bisect += 2

            if v_oldest == v_newest:
                inferred_verdict = v_oldest
                for i, t in enumerate(valid):
                    actual = tag_to_v[t].get("verdict")
                    if actual == inferred_verdict:
                        correct += 1
                    else:
                        wrong += 1
                        wrong_details.append(
                            f"  {line_name}/{t}: inferred={inferred_verdict} actual={actual} (same-endpoints)"
                        )
                continue

            if v_newest != "AFFECTED" or v_oldest != "NOT_AFFECTED":
                llm_calls_bisect += len(valid) - 2
                correct += len(valid)
                continue

            lo, hi = 0, len(valid) - 1
            violation = False
            while hi - lo > 1:
                mid = (lo + hi) // 2
                v_mid = tag_to_v[valid[mid]].get("verdict")
                probed_indices.add(mid)
                llm_calls_bisect += 1

                if v_mid == "AFFECTED":
                    hi = mid
                elif v_mid == "NOT_AFFECTED":
                    lo = mid
                else:
                    break

                v_lo = tag_to_v[valid[lo]].get("verdict")
                v_hi = tag_to_v[valid[hi]].get("verdict")
                if v_lo == "AFFECTED" or v_hi == "NOT_AFFECTED":
                    violation = True
                    break

            if violation:
                llm_calls_bisect += len(valid) - len(probed_indices)
                correct += len(valid)
                continue

            # Boundary pad
            for offset in [-1, 1]:
                for base in [lo, hi]:
                    idx = base + offset
                    if 0 <= idx < len(valid) and idx not in probed_indices:
                        probed_indices.add(idx)
                        llm_calls_bisect += 1

            # Post-refinement violation check
            probed_list = sorted(probed_indices)
            probed_verdicts = [tag_to_v[valid[i]].get("verdict") for i in probed_list]
            pv_clean = [v for v in probed_verdicts if v in ("AFFECTED", "NOT_AFFECTED")]
            has_violation = False
            for i in range(len(pv_clean) - 2):
                if (
                    pv_clean[i] == "AFFECTED"
                    and pv_clean[i + 1] == "NOT_AFFECTED"
                    and pv_clean[i + 2] == "AFFECTED"
                ):
                    has_violation = True
                    break
                if (
                    pv_clean[i] == "NOT_AFFECTED"
                    and pv_clean[i + 1] == "AFFECTED"
                    and pv_clean[i + 2] == "NOT_AFFECTED"
                ):
                    has_violation = True
                    break

            if has_violation:
                llm_calls_bisect += len(valid) - len(probed_indices)
                correct += len(valid)
                continue

            # Find boundary
            boundary_na = lo
            boundary_aff = hi
            for i in sorted(probed_indices):
                v = tag_to_v[valid[i]].get("verdict")
                if v == "NOT_AFFECTED" and i > boundary_na:
                    boundary_na = i
                if v == "AFFECTED" and i < boundary_aff:
                    boundary_aff = i

            for i, t in enumerate(valid):
                actual = tag_to_v[t].get("verdict")
                if i in probed_indices:
                    correct += 1
                elif i <= boundary_na:
                    inferred = "NOT_AFFECTED"
                    if actual == inferred:
                        correct += 1
                    else:
                        wrong += 1
                        wrong_details.append(
                            f"  {line_name}/{t}: inferred={inferred} actual={actual} (below boundary)"
                        )
                elif i >= boundary_aff:
                    inferred = "AFFECTED"
                    if actual == inferred:
                        correct += 1
                    else:
                        wrong += 1
                        wrong_details.append(
                            f"  {line_name}/{t}: inferred={inferred} actual={actual} (above boundary)"
                        )
                else:
                    correct += 1
                    llm_calls_bisect += 1

        if total_tags > 0:
            accuracy = 100 * correct / total_tags
            saved = llm_calls_linear - llm_calls_bisect
            saved_pct = 100 * saved / max(llm_calls_linear, 1)
            print(
                f"{repo}/{cve}: tags={total_tags} correct={correct} wrong={wrong} "
                f"accuracy={accuracy:.1f}% "
                f"linear={llm_calls_linear} bisect={llm_calls_bisect} "
                f"saved={saved}({saved_pct:.0f}%)"
            )
            if wrong_details:
                for d in wrong_details[:5]:
                    print(d)
                if len(wrong_details) > 5:
                    print(f"  ... and {len(wrong_details) - 5} more")

            grand_total += total_tags
            grand_correct += correct
            grand_wrong += wrong
            grand_llm_linear += llm_calls_linear
            grand_llm_saved += saved

print()
print("=== GRAND TOTAL ===")
overall_acc = 100 * grand_correct / max(grand_total, 1)
overall_saved_pct = 100 * grand_llm_saved / max(grand_llm_linear, 1)
print(f"Tags: {grand_total}, Correct: {grand_correct}, Wrong: {grand_wrong}")
print(f"Accuracy: {overall_acc:.1f}%")
print(f"LLM calls: linear={grand_llm_linear}, bisect={grand_llm_linear - grand_llm_saved}")
print(f"Saved: {grand_llm_saved} ({overall_saved_pct:.0f}%)")
if grand_wrong > 0:
    print(
        f"WARNING: {grand_wrong} incorrect inferences "
        f"({100 * grand_wrong / grand_total:.1f}% of tags)"
    )
    print(
        "NOTE: These are inferences that disagree with the LLM's own linear verdicts."
    )
    print(
        "Since the LLM itself has errors (monotonicity violations are mostly LLM errors),"
    )
    print(
        "the 'wrong' inferences may actually be MORE correct than the LLM's verdicts."
    )
