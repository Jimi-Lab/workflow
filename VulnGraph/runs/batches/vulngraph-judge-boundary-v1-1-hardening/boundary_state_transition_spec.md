# Boundary State Transition Specification v1.1

## Scope

This specification governs Judge Boundary v1.1 and deterministic converter v1.1 on the development 30-CVE set. It does not validate BICs and does not use affected-version labels in model input.

## Single source of truth

The model outputs only `candidate_judgments`. Every wrapper-owned input candidate appears exactly once. The wrapper derives selected, rejected, and uncertain views deterministically.

- `introduction`: introduces a vulnerability-enabling code fact.
- `activation`: enables a previously present vulnerability state.
- `prerequisite`: required precondition; it cannot activate a vulnerability alone.
- `fix_series_noise`, `refactor_noise`, `equivalent_fix_noise`: non-boundary roles.
- `uncertain` is a decision, not a boundary role.

## Decision and role contract

| Decision | Allowed roles | Converter effect |
|---|---|---|
| selected | introduction, activation, prerequisite | May enter wrapper-derived boundary events |
| rejected | fix-series/refactor/equivalent-fix noise | Never enters conversion |
| uncertain | any non-uncertain role | Preserved for diagnostics; never enters conversion |

## Wrapper-owned groups

Each candidate receives wrapper-owned `boundary_group_ids`, `fix_set_id`, and `patch_family_id`. The model cannot output or modify these IDs.

A boundary group is active for a tag only when at least one selected introduction/activation event is reachable and all selected prerequisite events are reachable. A prerequisite-only group is inactive and records `prerequisite_without_activation`.

## Fix completion

A patch family is complete when any equivalent/member fix commit is reachable. A fix group is complete only when all required patch families are complete. A tag is predicted affected only when at least one boundary group is active and its related fix group is definitely incomplete.

Unknown reachability is recorded as uncertainty and is not silently converted to affected.

## Fail-closed behavior

- Judge contract rejection produces `prediction_status=blocked`.
- Blocked predictions contain an empty `affected_versions` list and remain in all-case metric denominators.
- Converter re-lints parsed output before deriving views.
- No model-owned selected-event list is consumed.
