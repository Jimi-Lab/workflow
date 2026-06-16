import regex
import json
import string
import unicodedata
from typing import List
import numpy as np
from collections import Counter
import os
from bert_score import score
from nltk.stem import PorterStemmer
ps = PorterStemmer()

LENGTH_THRESHOLD = 5

class SimpleTokenizer(object):
    ALPHA_NUM = r'[\p{L}\p{N}\p{M}]+'
    NON_WS = r'[^\p{Z}\p{C}]'

    def __init__(self):
        """
        Args:
            annotators: None or empty set (only tokenizes).
        """
        self._regexp = regex.compile(
            '(%s)|(%s)' % (self.ALPHA_NUM, self.NON_WS),
            flags=regex.IGNORECASE + regex.UNICODE + regex.MULTILINE
        )

    def tokenize(self, text, uncased=False):
        matches = [m for m in self._regexp.finditer(text)]
        if uncased:
            tokens = [m.group().lower() for m in matches]
        else:
            tokens = [m.group() for m in matches]
        return tokens








def normalize_answer(s):

    s = s.replace(',', "")
    def remove_articles(text):
        return regex.sub(r'\b(a|an|the|and)\b', ' ', text)

    def white_space_fix(text):
        return ' '.join(text.split())

    def remove_punc(text):
        exclude = set(string.punctuation)
        return ''.join(ch for ch in text if ch not in exclude)

    def lower(text):
        return text.lower()

    return white_space_fix(remove_articles(remove_punc(lower(s))))


def exact_match_score(prediction, ground_truth):

    prediction = normalize_answer(prediction)
    ground_truth = normalize_answer(ground_truth)
    return set(prediction.split()) == set(ground_truth.split())
    
# def bert_score(prediction, ground_truths):
#     values = []
#         P, R, F1 = score([prediction], [ground_truth], lang='en', verbose=False, rescale_with_baseline=True)
#         values.append(R[0].item())






def f1_score(prediction, ground_truth):
    prediction_tokens = [ps.stem(w) for w in normalize_answer(prediction).split()]
    ground_truth_tokens = [ps.stem(w) for w in normalize_answer(ground_truth).split()]
    common = Counter(prediction_tokens) & Counter(ground_truth_tokens)
    num_same = sum(common.values())
    if num_same == 0:
        return 0
    precision = 1.0 * num_same / len(prediction_tokens)
    recall = 1.0 * num_same / len(ground_truth_tokens)
    f1 = (2 * precision * recall) / (precision + recall)
    return f1


def f1(prediction, ground_truth):
    predictions = [p.strip() for p in prediction.split(',')]
    ground_truths = [g.strip() for g in ground_truth.split(',')]
    # print('# F1 [multi-answer]#', predictions, ' | ', ground_truths, ' #', np.mean([max([f1_score(prediction, gt) for prediction in predictions]) for gt in ground_truths]))
    return np.mean([max([f1_score(prediction, gt) for prediction in predictions]) for gt in ground_truths])






## file-level evaluation ... ### 


def eval_question_answering(qas, eval_key='prediction', metric='f1'):


    all_ems = []
    all_recall = []
    exact_match_count = 0
    f1_count = 0
    answer_lengths = []
    for i, line in enumerate(qas):
        if type(line[eval_key]) == list:
            answer = line['answer']
        else:
            answer = str(line['answer'])
        if line['category'] == 3:
            answer = answer.split(';')[0].strip()
        
        output = line[eval_key]
        if output is None:
            output=""
        
        # single-hop, temporal, open-domain eval without splitting for sub-answers 
        if line['category'] in [2, 3, 4]:
            all_ems.append(f1_score(output, answer))
        
        # multi-hop eval by splitting entire phrase into sub-answers and computing partial F1 for each
        elif line['category'] in [1]:
            all_ems.append(f1(output, answer))

        # adversarial eval --> check for selection of correct option
        elif line['category'] in [5]:
            if 'no information available' in output.lower() or 'not mentioned' in output.lower():
                all_ems.append(1)
            else:
                all_ems.append(0)
        else:
            all_ems.append(f1_score(output, answer))

        
        assert i+1 == len(all_ems), all_ems

        if eval_key + '_context' in line and len(line['evidence']) > 0 and line.get(eval_key + '_context', []):
            # recall_acc for dialog
            if line[eval_key + '_context'][0].startswith('S'):
                sessions = [e[1:] for e in line[eval_key + '_context']]
                recall_acc = float(sum([ev.split(':')[0][1:] in sessions for ev in line["evidence"]]))/len(line['evidence'])
            else:
                recall_acc = float(sum([ev in line[eval_key + '_context'] for ev in line["evidence"]]))/len(line['evidence'])
            all_recall.append(recall_acc)
        else:
            all_recall.append(0)

    print("{} QA samples evaluated; {} accuracy values".format(len(qas), len(all_ems)))
    lens = 0.0
    return all_ems, lens, all_recall





