"""Red acceptance tests for the quarterly access-review exercise.

The ten numbered tests map one-to-one to the ten defects stated in README.
The remaining five tests cover the required integration cases: an unchanged
snapshot, an added high-risk permission, a departed principal in the full
review, the inclusive expiry boundary, and independent batch review.
"""

from review.audit import (
    approval_valid,
    diff_snapshots,
    high_risk,
    load_snapshot,
    orphan_grants,
    review,
    review_batch,
    validate_policy,
)


def _grant(principal, resource, action, source="direct"):
    return {
        "principal": principal,
        "resource": resource,
        "action": action,
        "source": source,
    }


def _canonical(principal, resource, action, *sources):
    return {
        "principal": principal,
        "resource": resource,
        "action": action,
        "sources": sorted(set(sources)),
    }


def _snapshot(*grants):
    by_principal = {}
    by_resource = {}
    for grant in grants:
        by_principal.setdefault(grant["principal"], []).append(grant)
        by_resource.setdefault(grant["resource"], []).append(grant)
    return {
        "grants": list(grants),
        "by_principal": by_principal,
        "by_resource": by_resource,
    }


# Defect 1: a resource-keyed index loses the other resources of a principal.
def test_load_snapshot_indexes_each_principal_resource_pair():
    records = [
        _grant("alice", "billing", "delete", "direct"),
        _grant("alice", "orders", "read", "sso"),
        _grant("bob", "billing", "read", "group:eng"),
        _grant("alice", "billing", "delete", "direct"),
    ]

    snapshot = load_snapshot(records)

    assert set(snapshot) == {"grants", "by_principal", "by_resource"}
    assert snapshot["by_principal"]["alice"] == [
        _grant("alice", "billing", "delete", "direct"),
        _grant("alice", "orders", "read", "sso"),
    ]
    assert snapshot["by_principal"]["bob"] == [
        _grant("bob", "billing", "read", "group:eng"),
    ]
    assert snapshot["by_resource"]["billing"] == [
        _grant("alice", "billing", "delete", "direct"),
        _grant("bob", "billing", "read", "group:eng"),
    ]
    assert snapshot["by_resource"]["orders"] == [
        _grant("alice", "orders", "read", "sso"),
    ]
    assert snapshot["grants"] == [
        _grant("alice", "billing", "delete", "direct"),
        _grant("alice", "orders", "read", "sso"),
        _grant("bob", "billing", "read", "group:eng"),
    ]


# Defect 2: reporting only additions hides removals and source changes.
def test_diff_snapshots_reports_removed_and_changed_permissions():
    old = _snapshot(
        _grant("alice", "orders", "read", "direct"),
        _grant("bob", "users", "write", "direct"),
        _grant("carol", "billing", "read", "direct"),
    )
    new = _snapshot(
        _grant("alice", "orders", "read", "direct"),
        _grant("alice", "orders", "read", "group:eng"),
        _grant("bob", "users", "write", "direct"),
        _grant("dave", "billing", "delete", "direct"),
    )

    delta = diff_snapshots(old, new)

    assert delta["added"] == [
        _canonical("dave", "billing", "delete", "direct"),
    ]
    assert delta["removed"] == [
        _canonical("carol", "billing", "read", "direct"),
    ]
    assert delta["changed"] == [
        {
            "before": _canonical("alice", "orders", "read", "direct"),
            "after": _canonical(
                "alice", "orders", "read", "direct", "group:eng"
            ),
        },
    ]


# Defect 3: checking only for an empty principal misses departed staff.
def test_orphan_grants_reports_departed_principal():
    snapshot = _snapshot(
        _grant("alice", "orders", "read", "direct"),
        _grant("bob", "billing", "delete", "direct"),
        _grant("carol", "users", "write", "direct"),
    )
    directory = {
        "alice": {"status": "active"},
        "bob": {"status": "departed"},
    }

    assert orphan_grants(snapshot, directory) == [
        _canonical("bob", "billing", "delete", "direct"),
        _canonical("carol", "users", "write", "direct"),
    ]


# Defect 4: prefix comparison flags a lower-risk neighbouring resource.
def test_high_risk_requires_exact_resource_match():
    rules = [
        {"id": "billing-delete", "resource": "billing", "action": "delete"},
        {"id": "billing-delete-alias", "resource": "billing", "action": "delete"},
    ]
    grants = [
        _grant("alice", "billing", "delete", "direct"),
        _grant("bob", "billing-export", "delete", "direct"),
        _grant("carol", "billing", "delete", "direct"),
        _grant("carol", "billing", "delete", "group:eng"),
    ]

    assert high_risk(grants, rules) == [
        _canonical("alice", "billing", "delete", "direct"),
        _canonical("carol", "billing", "delete", "direct", "group:eng"),
    ]


# Defect 5: comparing only the resource marks read-only grants as high risk.
def test_high_risk_requires_matching_action():
    rules = [
        {"id": "billing-delete", "resource": "billing", "action": "delete"},
    ]
    grants = [
        _grant("alice", "billing", "read", "direct"),
        _grant("bob", "billing", "delete", "direct"),
        _grant("carol", "billing", "admin", "direct"),
    ]

    assert high_risk(grants, rules) == [
        _canonical("bob", "billing", "delete", "direct"),
    ]


# Defect 6: checking only that an approval was issued, not that it is fresh.
def test_approval_valid_rejects_approval_older_than_ttl():
    grant = _grant("alice", "billing", "delete", "direct")
    fresh = [
        {
            "principal": "alice",
            "resource": "billing",
            "action": "delete",
            "issued_at": 9900,
        }
    ]
    stale = [
        {
            "principal": "alice",
            "resource": "billing",
            "action": "delete",
            "issued_at": 9000,
        }
    ]

    assert approval_valid(grant, fresh, 10000, 600) is True
    assert approval_valid(grant, stale, 10000, 600) is False


# Defect 7: ignoring the approval scope accepts approvals for other grants.
def test_approval_valid_requires_matching_scope():
    grant = _grant("alice", "billing", "delete", "direct")
    exact = [
        {
            "principal": "alice",
            "resource": "billing",
            "action": "delete",
            "issued_at": 9900,
        }
    ]
    wrong_scope = [
        {
            "principal": "alice",
            "resource": "billing",
            "action": "read",
            "issued_at": 9900,
        },
        {
            "principal": "alice",
            "resource": "billing-export",
            "action": "delete",
            "issued_at": 9900,
        },
        {
            "principal": "bob",
            "resource": "billing",
            "action": "delete",
            "issued_at": 9900,
        },
    ]

    assert approval_valid(grant, exact, 10000, 600) is True
    assert approval_valid(grant, wrong_scope, 10000, 600) is False


# Defect 8: the same permission from several sources is counted more than once.
def test_review_counts_same_permission_once_across_sources():
    snapshot = _snapshot(
        _grant("alice", "billing", "delete", "direct"),
        _grant("alice", "billing", "delete", "group:eng"),
    )
    directory = {"alice": {"status": "active"}}
    policy = {
        "high_risk_rules": [
            {"id": "billing-delete", "resource": "billing", "action": "delete"},
        ],
        "approval_ttl": 600,
        "check_orphans": True,
        "approvals": [
            {
                "principal": "alice",
                "resource": "billing",
                "action": "delete",
                "issued_at": 9900,
            }
        ],
    }

    result = review(snapshot, directory, policy, 10000)

    assert result["orphans"] == []
    assert result["high_risk"] == [
        _canonical("alice", "billing", "delete", "direct", "group:eng"),
    ]
    assert len(result["high_risk"]) == 1
    assert result["unapproved"] == []
    assert result["counts"] == {
        "grants": 1,
        "orphans": 0,
        "high_risk": 1,
        "unapproved": 0,
    }


# Defect 9: policy validation never checks that high-risk rules are configured.
def test_validate_policy_reports_missing_high_risk_rules():
    rule = {"id": "billing-delete", "resource": "billing", "action": "delete"}
    unsafe = {
        "high_risk_rules": [],
        "check_orphans": False,
    }
    safe = {
        "high_risk_rules": [rule],
        "approval_ttl": 600,
        "check_orphans": True,
    }

    assert validate_policy(unsafe) == [
        "missing high risk rules",
        "missing approval ttl",
        "orphan check disabled",
    ]
    assert validate_policy(safe) == []


# Defect 10: the second batch inherits the first batch's principal set.
def test_review_batch_does_not_reuse_first_batch_principals():
    batches = [
        {
            "id": "q1",
            "records": [_grant("alice", "billing", "delete", "direct")],
            "directory": {"alice": {"status": "active"}},
        },
        {
            "id": "q2",
            "records": [_grant("bob", "orders", "read", "direct")],
            "directory": {"bob": {"status": "active"}},
        },
    ]
    policy = {
        "high_risk_rules": [
            {"id": "billing-delete", "resource": "billing", "action": "delete"},
        ],
        "approval_ttl": 600,
        "check_orphans": True,
        "approvals": [
            {
                "principal": "alice",
                "resource": "billing",
                "action": "delete",
                "issued_at": 9900,
            }
        ],
    }

    result = review_batch(batches, policy, 10000)

    assert result["batches"]["q1"]["counts"] == {
        "grants": 1,
        "orphans": 0,
        "high_risk": 1,
        "unapproved": 0,
    }
    assert result["batches"]["q2"]["orphans"] == []
    assert result["batches"]["q2"]["high_risk"] == []
    assert result["batches"]["q2"]["counts"] == {
        "grants": 1,
        "orphans": 0,
        "high_risk": 0,
        "unapproved": 1,
    }
    assert result["counts"] == {
        "batches": 2,
        "grants": 2,
        "orphans": 0,
        "high_risk": 1,
        "unapproved": 1,
    }


# Extra case: identical snapshots produce no differences at all.
def test_diff_snapshots_returns_empty_categories_when_unchanged():
    old = _snapshot(
        _grant("alice", "orders", "read", "direct"),
        _grant("bob", "billing", "delete", "group:eng"),
    )
    new = _snapshot(
        _grant("alice", "orders", "read", "direct"),
        _grant("bob", "billing", "delete", "group:eng"),
    )

    assert diff_snapshots(old, new) == {
        "added": [],
        "removed": [],
        "changed": [],
    }


# Extra case: a high-risk grant added between snapshots must be reported.
def test_new_high_risk_grant_is_reported_from_snapshot_diff():
    old = _snapshot(_grant("alice", "orders", "read", "direct"))
    new = _snapshot(
        _grant("alice", "orders", "read", "direct"),
        _grant("alice", "billing", "delete", "direct"),
    )
    rules = [
        {"id": "billing-delete", "resource": "billing", "action": "delete"},
    ]

    delta = diff_snapshots(old, new)

    assert delta["added"] == [
        _canonical("alice", "billing", "delete", "direct"),
    ]
    assert high_risk(delta["added"], rules) == [
        _canonical("alice", "billing", "delete", "direct"),
    ]


# Extra case: a departed principal is reported as an orphan by full review.
def test_review_reports_departed_principal_as_orphan():
    snapshot = _snapshot(
        _grant("alice", "orders", "read", "direct"),
        _grant("bob", "billing", "delete", "direct"),
        _grant("carol", "users", "write", "direct"),
    )
    directory = {
        "alice": {"status": "active"},
        "bob": {"status": "departed"},
    }
    policy = {
        "high_risk_rules": [
            {"id": "billing-delete", "resource": "billing", "action": "delete"},
        ],
        "approval_ttl": 600,
        "check_orphans": True,
        "approvals": [
            {
                "principal": "alice",
                "resource": "orders",
                "action": "read",
                "issued_at": 9900,
            }
        ],
    }

    result = review(snapshot, directory, policy, 10000)

    assert result["orphans"] == [
        _canonical("bob", "billing", "delete", "direct"),
        _canonical("carol", "users", "write", "direct"),
    ]
    assert result["high_risk"] == [
        _canonical("bob", "billing", "delete", "direct"),
    ]
    assert result["unapproved"] == [
        _canonical("bob", "billing", "delete", "direct"),
        _canonical("carol", "users", "write", "direct"),
    ]
    assert result["counts"] == {
        "grants": 3,
        "orphans": 2,
        "high_risk": 1,
        "unapproved": 2,
    }


# Extra case: expiry boundary is inclusive, but an expired approval is rejected.
def test_expired_approval_is_not_valid_and_boundary_is_inclusive():
    grant = _grant("alice", "billing", "delete", "direct")
    boundary = [
        {
            "principal": "alice",
            "resource": "billing",
            "action": "delete",
            "issued_at": 9400,
        }
    ]
    expired = [
        {
            "principal": "alice",
            "resource": "billing",
            "action": "delete",
            "issued_at": 9399,
        }
    ]
    future = [
        {
            "principal": "alice",
            "resource": "billing",
            "action": "delete",
            "issued_at": 10001,
        }
    ]

    assert approval_valid(grant, boundary, 10000, 600) is True
    assert approval_valid(grant, expired, 10000, 600) is False
    assert approval_valid(grant, future, 10000, 600) is False


# Extra case: every batch result equals the same review performed on its own.
def test_review_batch_matches_independent_reviews():
    batches = [
        {
            "id": "a",
            "records": [_grant("alice", "orders", "read", "direct")],
            "directory": {"alice": {"status": "active"}},
        },
        {
            "id": "b",
            "records": [_grant("bob", "users", "write", "direct")],
            "directory": {"bob": {"status": "departed"}},
        },
    ]
    policy = {
        "high_risk_rules": [
            {"id": "users-write", "resource": "users", "action": "write"},
        ],
        "approval_ttl": 600,
        "check_orphans": True,
        "approvals": [
            {
                "principal": "alice",
                "resource": "orders",
                "action": "read",
                "issued_at": 9900,
            }
        ],
    }

    combined = review_batch(batches, policy, 10000)

    assert combined["batches"]["a"] == review(
        _snapshot(_grant("alice", "orders", "read", "direct")),
        {"alice": {"status": "active"}},
        policy,
        10000,
    )
    assert combined["batches"]["b"] == review(
        _snapshot(_grant("bob", "users", "write", "direct")),
        {"bob": {"status": "departed"}},
        policy,
        10000,
    )
    assert combined["counts"] == {
        "batches": 2,
        "grants": 2,
        "orphans": 1,
        "high_risk": 1,
        "unapproved": 1,
    }