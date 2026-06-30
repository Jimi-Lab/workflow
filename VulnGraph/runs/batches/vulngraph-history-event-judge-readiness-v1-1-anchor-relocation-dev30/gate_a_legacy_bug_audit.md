# Gate A Legacy Anchor Bug Audit

- Context resolutions: 122
- Found contexts: 83
- Same-line but wrong-text: 71
- Comment/blank accepted anchors: 10
- Stored hash/text mismatches: 71
- Context found but anchor unverified: 71

## CVE-2020-8231 failures

- parent candidate=pre-fix-line:96e2823d262eba5fab1e424346eba3b286e2e1397a371c9d9f8e0cbfdd8a56b8 hint=680 expected=`      data->state.lastconnect = conn;` actual=`    /* When this handle gets removed, other handles may be able to get the`
- candidate candidate=pre-fix-line:96e2823d262eba5fab1e424346eba3b286e2e1397a371c9d9f8e0cbfdd8a56b8 hint=680 expected=`      data->state.lastconnect = conn;` actual=``
