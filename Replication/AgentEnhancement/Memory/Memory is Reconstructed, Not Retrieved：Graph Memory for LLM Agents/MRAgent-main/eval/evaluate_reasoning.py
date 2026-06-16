import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # add repo root to path for standalone runs
import json
import argparse
from pathlib import Path
from typing import List, Dict
from eval.evaluation import f1_score
from eval.judge import evaluate_llm_judge




# load data

import argparse
parser = argparse.ArgumentParser(description="Configure dataset and model parameters.")
parser.add_argument("--data", type=str, default="AR", help="Dataset name, e.g., AR / LM / locomo")
parser.add_argument("--model", type=str, default="AR", help="Dataset name, e.g., AR / LM / locomo")
parser.add_argument("--file", type=str, default="AR", help="Dataset name, e.g., AR / LM / locomo")
parser.add_argument('--allfile', action="store_true", required=False)
args = parser.parse_args()


from pathlib import Path
import json

if args.allfile:
# ===== configure here =====
    ROOT = Path(f"result/{args.data}")   # change to your directory
    PATTERN = f"conv-*_result_{args.model}_{args.file}.jsonl"
    # ===================

    data = []  # final list: each JSON line as one element (dict)

    # to include subdirs, change .glob to .rglob
    for fp in sorted(ROOT.glob(PATTERN)):
        with fp.open("r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                data.append(json.loads(s))

    print(len(data))

#
# with open(f"result", "r", encoding="utf-8") as f:
# result_list = data["individual_results"]
F1_dict = {1:[],2:[],3:[],4:[],5:[]}
i=0
for result in data:
    import numbers
    sample = result["sample"]
    question = result["question"]
    prediction = result["prediction"]
    reference = result["answer"]
    category = result['category']#.get("category")
    i += 1
    if category != 5:
        if isinstance(prediction, numbers.Number):
            prediction = str(prediction)
        if isinstance(reference, numbers.Number):
            reference = str(reference)
        F1_dict[category].append(f1_score(prediction, reference))

    else:
        if "Not mentioned" in prediction:
            F1_dict[category].append(1)
        else:
            F1_dict[category].append(0)

for c in range(1,6):
    print(f"{c} {len(F1_dict[c])} {sum(F1_dict[c])/len(F1_dict[c])}")
print(i)
llm_dict = {1:[],2:[],3:[],4:[],5:[]}
with open(f"result_judge_{args.data}_{args.model}_{args.file}.jsonl", "a", encoding="utf-8") as of:
    for result in data:
        sample = result["sample"]
        question = result["question"]
        prediction = result["prediction"]
        reference = result["answer"]
        category = result['category']
        if category != 5:
            #F1_dict[category].append(f1_score(prediction, reference))
            llm_score = evaluate_llm_judge(question, reference, prediction)
            out = {"llm_score": llm_score, "question": question, "prediction":prediction,
                    "reference":reference, "category": category, "sample":sample}
            of.write(json.dumps(out, ensure_ascii=False, default=list) + "\n")
            llm_dict[category].append(llm_score)

for c in range(1,5):
    print(f"{c} {len(llm_dict[c])} {sum(llm_dict[c])/len(llm_dict[c])}")

