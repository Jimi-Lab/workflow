import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # add repo root to path for standalone runs
import json
from collections import defaultdict
from eval.evaluation import eval_question_answering, exact_match_score, f1_score, f1
import argparse
from pathlib import Path
from typing import List, Dict

def parse_args():

    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=str, required=True)
    parser.add_argument('--sample', type=str, required=False)
    parser.add_argument('--basedir', type=str, required=False)
    parser.add_argument('--allfile', action="store_true", required=False)
    args = parser.parse_args()
    return args

def load_results_as_list(dataset: str, base_dir: str = "result", pattern: str = "*_result_claude.jsonl", recursive: bool = False) -> List[Dict]:
    """
    Read every JSON line from all *_result_claude.jsonl under result/{dataset} into a single list.
    Also extract the sample name from the filename into each record's 'sample' field.
    """
    root = Path(base_dir) / dataset
    print("== path check ==")
    print("root:", root.resolve())
    print("exists:", root.exists(), "is_dir:", root.is_dir())

    # 1) match files
    globber = root.rglob if recursive else root.glob
    files = sorted(globber(pattern))
    print(f"match rule: {'**/' if recursive else ''}{pattern}")
    print("matched files:", len(files))

    root = Path(base_dir) / dataset
    all_items = []
    for fp in sorted(root.glob("*_result_claude.jsonl")):
        sample = fp.name.replace("_result_claude.jsonl", "")
        with fp.open("r", encoding="utf-8") as f:
            for ln, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as e:
                    # include file and line number on error for debugging
                    raise ValueError(f"JSON parse failed: {fp} line {ln}: {e}") from e
                # add source info
                if "sample" not in obj:
                    obj["sample"] = sample
                all_items.append(obj)
    return all_items


args = parse_args()
dataset = args.dataset
sample = args.sample
allfile = args.allfile
basedir = "result"#args.basedir
# load data

if allfile:
    data = load_results_as_list(dataset, basedir)
else:
    with open(f"result/{dataset}/{sample}_result_claude_claude_sort_all.jsonl", "r", encoding="utf-8") as f:
        data = [json.loads(line) for line in f]

eval_key = 'prediction'

# field init to avoid errors
for line in data:
    if eval_key not in line:
        line[eval_key] = ''
    if eval_key + '_context' not in line or not isinstance(line[eval_key + '_context'], list):
        line[eval_key + '_context'] = []
    if 'evidence' not in line or not isinstance(line['evidence'], list):
        line['evidence'] = []
    if 'category' not in line:
        line['category'] = 2  # default to 2

# call the eval function (ems = per-sample metric, recall_list = per-sample recall)
ems, _, recall_list = eval_question_answering(data, eval_key=eval_key, metric='f1')

# print the per-sample metrics header

print(f"| {'Idx':<4} | {'Category':<8} | {'Question':<50} | {'Prediction':<50} | {'Answer':<30} | {'F1':<6} | {'Recall':<6} |")
print("-" * 190)


# for per-category aggregation
stats = defaultdict(lambda: {
    "count": 0,
    "em_sum": 0.0,
    "f1_sum": 0.0,
    "recall_sum": 0.0,
    "len_sum": 0,
    "ems": [],
    "f1s": [],
    "recalls": []
})

# iterate over samples and print
for i, line in enumerate(data):
    prediction = line[eval_key]
    answer = str(line['answer'])
    if prediction is None:
        prediction = ""
    em_bool = exact_match_score(prediction, answer)
    em = 1 if em_bool else 0
    if line['category'] in [2, 3, 4]:
        f1_val = f1_score(prediction, answer)
    elif line['category'] in [1]:
        f1_val = f1(prediction, answer)
    elif line['category'] in [5]:
        if 'no information available' in prediction.lower() or 'not mentioned' in prediction.lower():
            f1_val = 1
        else:
            f1_val = 0

    else:
        f1_val = f1_score(prediction, answer)

    recall = recall_list[i] if i < len(recall_list) else 0
    output_len = len(prediction.split())

    cat = line.get('category', 'NA')

    # update category stats
    s = stats[cat]
    s["count"] += 1
    s["em_sum"] += em
    s["f1_sum"] += f1_val
    s["recall_sum"] += (recall if isinstance(recall, (int, float)) else 0)
    s["len_sum"] += output_len
    s["recalls"].append(recall)

    # print this sample (truncate long fields for readability)
    #     f"{i+1:<4} | {str(cat):<8} | {line.get('question','')[:50]:<50} | {prediction[:50]:<50} | {answer[:30]:<30} | "
    #     f"{em:<4} | {f1_val:<6.3f} | {recall!s:<6} | {output_len:<3}"
    # )

    print(
        f"| {i + 1:<4} | {str(cat):<8} | {line.get('question', '')[:50]:<50} | {prediction[:50]:<50} | {answer[:30]:<30} | "
        f"{f1_val:<6.3f} | {recall!s:<6} |"
    )


# compute and print per-category and overall averages
print("\nPer-category summary:")
overall = {"count": 0, "em_sum": 0.0, "f1_sum": 0.0, "recall_sum": 0.0, "len_sum": 0}
CATEGORY_MAP = {
    1: "multi-hop",
    2: "temporal",
    3: "open domain",
    4: "single-hop",
    5: "adversarial",
}
summary = {}
for cat, v in sorted(stats.items(), key=lambda x: str(x[0])):
    cnt = v["count"]
    avg_em = v["em_sum"] / cnt if cnt else 0.0
    avg_f1 = v["f1_sum"] / cnt if cnt else 0.0
    avg_recall = v["recall_sum"] / cnt if cnt else 0.0
    avg_len = v["len_sum"] / cnt if cnt else 0.0

    if dataset == "locomo":
        print(f" Category {CATEGORY_MAP[cat]}: count={cnt}, avg_EM={avg_em:.3f}, avg_F1={avg_f1:.3f}, avg_recall={avg_recall:.3f}, avg_len={avg_len:.2f}")
    else:
        print(f" Category {cat}: count={cnt}, avg_EM={avg_em:.3f}, avg_F1={avg_f1:.3f}, avg_recall={avg_recall:.3f}, avg_len={avg_len:.2f}")


    summary[cat] = {
        "count": cnt,
        "avg_em": round(avg_em, 4),
        "avg_f1": round(avg_f1, 4),
        "avg_recall": round(avg_recall, 4),
        "avg_len": round(avg_len, 4)
    }

    overall["count"] += cnt
    overall["em_sum"] += v["em_sum"]
    overall["f1_sum"] += v["f1_sum"]
    overall["recall_sum"] += v["recall_sum"]
    overall["len_sum"] += v["len_sum"]

# overall averages
if overall["count"] > 0:
    overall_avg_em = overall["em_sum"] / overall["count"]
    overall_avg_f1 = overall["f1_sum"] / overall["count"]
    overall_avg_recall = overall["recall_sum"] / overall["count"]
    overall_avg_len = overall["len_sum"] / overall["count"]
else:
    overall_avg_em = overall_avg_f1 = overall_avg_recall = overall_avg_len = 0.0

print("\nOverall summary:")
print(f" Total samples={overall['count']}, avg_EM={overall_avg_em:.3f}, avg_F1={overall_avg_f1:.3f}, avg_recall={overall_avg_recall:.3f}, avg_len={overall_avg_len:.2f}")

# save eval results to file (per-sample and per-category summary)
eval_results = {
    "per_sample": [
        {
            "idx": i + 1,
            "category": line.get('category', None),
            "question": line.get('question', None),
            "prediction": line.get(eval_key, None),
            "answer": str(line.get('answer', '')),
            "em": int(exact_match_score(line.get(eval_key, ''), str(line.get('answer', '')))),
            "f1": f1_score(line.get(eval_key, ''), str(line.get('answer', ''))),
            "recall": recall_list[i] if i < len(recall_list) else None,
            "len": len(line.get(eval_key, '').split())
        }
        for i, line in enumerate(data)
    ],
    "per_category": summary,
    "overall": {
        "total": overall["count"],
        "avg_em": round(overall_avg_em, 4),
        "avg_f1": round(overall_avg_f1, 4),
        "avg_recall": round(overall_avg_recall, 4),
        "avg_len": round(overall_avg_len, 4)
    }
}

with open("eval_results.json", "w", encoding="utf-8") as f:
    json.dump(eval_results, f, ensure_ascii=False, indent=2)

print("\nEvaluation results saved to eval_results.json")
