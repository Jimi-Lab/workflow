# v1.1 vs v1.2 vs Raw Top1

| System | Exact | Micro P | Micro R | Micro F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| Judge v1.1 | 0.266667 | 0.713217 | 0.283589 | 0.405818 | 572 | 230 | 1445 |
| Judge v1.2 | 0.333333 | 0.746281 | 0.447695 | 0.559653 | 903 | 307 | 1114 |
| Raw top1 artifact recompute | 0.500000 | 0.610344 | 0.854239 | 0.711983 | 1723 | 1100 | 294 |

The user-stated advancement baseline is Exact 15/30 and micro F1 0.704872. The current raw-top1 artifact recomputes to a slightly different F1; both provenance values are retained rather than silently conflated. v1.2 does not pass either threshold.
