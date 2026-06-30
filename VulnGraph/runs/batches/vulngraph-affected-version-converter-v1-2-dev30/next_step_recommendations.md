# Next Step Recommendations

1. Do not run 100-CVE validation. The dev30 gate failed.
2. Audit the seven unresolved cases first; these are Judge abstention, not converter success.
3. Inspect false-negative-heavy selected cases for line-survival overconstraint and alternative-event selection.
4. Inspect false-positive-heavy cases for branch context breadth and missing branch-local equivalent fix detection.
5. Preserve v1.2 branch grouping and event materialization; optimize selection/calibration without using GT in the blind path.
