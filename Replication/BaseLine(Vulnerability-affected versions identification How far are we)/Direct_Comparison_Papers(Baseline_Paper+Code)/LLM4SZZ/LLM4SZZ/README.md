# Replication package

This repository contains datasets and source code of our paper "Enhancing Bug-Inducing Commit Identification: A Fine-Grained Semantic Analysis Approach
", which is submitted to IEEE Transactions on Software Engineering. 

## Directories

This repository contains four sub-directories:

1. **dataset**: This directory includes the dataset mentioned in the paper. The names of the three files correspond to `DATASET-A`, `DATASET-FA`, and `DATASET-D`, respectively.
2. **result**: This directory contains the experimental results for each test case. To calculate the metrics directly, use the cal_metrics.py file.
3. **DelBaselines**: This directory contains the baselines for `DATASET-D`.
4. **NoDelBaselines**: This directory contains the baselines for `DATASET-A` and `DATASET-FA`.

## Files
**_CFG.py_** : This file aims to build a control flow graph from the AST parsed by [tree-sitter](https://github.com/tree-sitter/tree-sitter). We borrow the core idea from [tree_climber](https://github.com/bstee615/tree-climber).

**_constant.py_** : This file defines some constants that needs to set, such as the project directory.

**_diss.py_** : This file includes the code used in the Discussion section of the paper.

**_gen_baseline_results_for_dels.py_** : This file contains the code generating the baselines' results for `DATASET-D`.

**_gen_baseline_results_for_no_dels.py_** : This file contains the code generating the baselines' results for `DATASET-A` and `DATASET-FA`.

**_gen_results_for_dels.py_** : This file contains the code used to get *SEMA-SZZ* reults for `DATASET-D`

**_gen_results_for_no_dels.py_** : This file contains the code used to get *SEMA-SZZ* results for `DATASET-A` and `DATASET-FA`.

**_parse_patch.py_** : This file parses a bug-fixing commit, extracting added lines, deleted lines, and their line numbers.

**_util.py_** : This file includes utility functions and classes used in _gen_results_for_dels.py_ and _gen_results_for_no_dels.py_. It includes the classes representing the data flow of a variable and  path contraints. It also includes the functions that do program slicing, collect states of the program and locate bug-inducing commits.

## Environment

Install all packages listed in requirements.txt for the Python environment.

Install Joern from the [official site](https://joern.io/)


## Pre-calculated results

### RQ 1
To replicate our results for RQ 1:

```
python gen_baseline_results_for_no_deletes.py

python gen_results_for_no_dels.py
```

### RQ 2

To replicate our results for RQ 2:

```
python gen_baseline_results_for_dels.py

python gen_results_for_dels.py
```

### RQ 3

To replicate our results for RQ 2:

```
python ablation.py
```
### discussion
To replicate our results for discussion:

```
python diss.py
```