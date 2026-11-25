"""Access-review contracts for a quarterly permission recertification.

Data model
----------
A permission record is a mapping with four string fields: ``principal``,
``resource``, ``action`` and ``source``.  A logical permission is identified by
the triple ``(principal, resource, action)``.  ``source`` is provenance only:
two rows that differ only in source describe the same permission and must
never be reported twice.

A snapshot is the mapping returned by :func:`load_snapshot`.  It has three
keys: ``grants``, ``by_principal`` and ``by_resource``.  ``grants`` contains
every distinct permission row.  ``by_principal`` maps each principal to that
principal's rows and ``by_resource`` maps each resource to that resource's
rows.  Both indexes must retain every row: a resource key must never shadow a
different resource belonging to the same principal.

A high-risk rule is a mapping with ``resource`` and ``action``.  Both are
exact, case-sensitive strings; prefixes and action wildcards never match.  An
optional ``id`` is ignored by matching.

An approval is a mapping with ``principal``, ``resource``, ``action`` and
``issued_at``.  It covers a grant only when all three scope dimensions match
exactly.  It is fresh only when its age at ``now`` does not exceed ``ttl``.
The age boundary is inclusive.

A policy is a mapping with ``high_risk_rules``, ``approval_ttl``,
``check_orphans`` and an optional ``approvals`` sequence.  A review finding is
a canonical grant mapping with ``principal``, ``resource``, ``action`` and
``sources``; ``sources`` is a sorted list of unique source values for the one
logical permission.
"""


def _row_sources(row):
    """Return the provenance values carried by a record or canonical grant."""
    if "sources" in row:
        return list(row["sources"])
    return [row["source"]]


def _canonical_grants(rows):
    """Merge rows into canonical grants, one per logical permission.

    Rows may be permission records (``source``) or canonical grants
    (``sources``).  Sources are merged per ``(principal, resource, action)``
    identity, deduplicated and sorted.  The result is sorted by logical
    identity.
    """
    merged = {}
    for row in rows:
        key = (row["principal"], row["resource"], row["action"])
        merged.setdefault(key, set()).update(_row_sources(row))
    result = []
    for principal, resource, action in sorted(merged):
        result.append(
            {
                "principal": principal,
                "resource": resource,
                "action": action,
                "sources": sorted(merged[(principal, resource, action)]),
            }
        )
    return result


def _source_sets(snapshot):
    """Map each logical permission in a snapshot to its set of sources."""
    result = {}
    for row in snapshot["grants"]:
        key = (row["principal"], row["resource"], row["action"])
        result.setdefault(key, set()).add(row["source"])
    return result


def _canonical_from(key, sources):
    principal, resource, action = key
    return {
        "principal": principal,
        "resource": resource,
        "action": action,
        "sources": sorted(sources),
    }


def load_snapshot(records) -> dict:
    """Build the principal and resource indexes for one permission snapshot.

    ``records`` is an iterable of permission records.  The returned mapping has
    exactly these keys:

    * ``grants``: every distinct record, sorted by
      ``(principal, resource, action, source)``;
    * ``by_principal``: a dict from principal id to that principal's records,
      sorted by ``(resource, action, source)``;
    * ``by_resource``: a dict from resource to that resource's records, sorted
      by ``(principal, action, source)``.

    Both indexes contain every record.  In particular, two resources held by
    the same principal must both remain visible; indexing by resource alone
    must not let one resource overwrite another.  Records identical in all four
    fields are collapsed, while records that differ in source remain separate
    because provenance is retained.  Logical deduplication happens only in the
    reporting functions.  The returned containers and lists are new; input
    records and the input sequence are not mutated.
    """
    # Defect 1 fix: keep every distinct row; both indexes are lists keyed by
    # principal/resource, so one resource can never overwrite another.
    seen = set()
    rows = []
    for record in records:
        row = dict(record)
        key = (
            row["principal"],
            row["resource"],
            row["action"],
            row["source"],
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    grants = sorted(
        rows,
        key=lambda r: (
            r["principal"],
            r["resource"],
            r["action"],
            r["source"],
        ),
    )

    by_principal = {}
    for row in grants:
        by_principal.setdefault(row["principal"], []).append(row)
    for principal, principal_rows in by_principal.items():
        by_principal[principal] = sorted(
            principal_rows,
            key=lambda r: (r["resource"], r["action"], r["source"]),
        )

    by_resource = {}
    for row in grants:
        by_resource.setdefault(row["resource"], []).append(row)
    for resource, resource_rows in by_resource.items():
        by_resource[resource] = sorted(
            resource_rows,
            key=lambda r: (r["principal"], r["action"], r["source"]),
        )

    return {
        "grants": grants,
        "by_principal": by_principal,
        "by_resource": by_resource,
    }


def diff_snapshots(old, new) -> dict:
    """Compare two snapshots and return added, removed and changed permissions.

    Both arguments use the snapshot shape returned by :func:`load_snapshot`.
    Logical identity is ``(principal, resource, action)``; sources are
    aggregated per identity.  The result has exactly three keys:

    * ``added``: canonical grants whose identity exists only in ``new``;
    * ``removed``: canonical grants whose identity exists only in ``old``;
    * ``changed``: mappings of the form ``{"before": grant, "after": grant}``
      for identities present in both snapshots whose source sets differ.

    A new source on an existing permission is a change, not an addition.
    Unchanged permissions appear nowhere.  Each list is sorted by
    ``(principal, resource, action)``, and every canonical grant has sorted,
    unique ``sources``.  If the snapshots describe the same permissions with
    the same sources, all three lists are empty.
    """
    # Defect 2 fix: report removals and source changes as well as additions,
    # keying the comparison on the logical permission rather than on rows.
    old_sources = _source_sets(old)
    new_sources = _source_sets(new)

    added = []
    removed = []
    changed = []
    for key in sorted(set(old_sources) | set(new_sources)):
        if key not in old_sources:
            added.append(_canonical_from(key, new_sources[key]))
        elif key not in new_sources:
            removed.append(_canonical_from(key, old_sources[key]))
        elif old_sources[key] != new_sources[key]:
            changed.append(
                {
                    "before": _canonical_from(key, old_sources[key]),
                    "after": _canonical_from(key, new_sources[key]),
                }
            )

    return {"added": added, "removed": removed, "changed": changed}


def orphan_grants(snapshot, directory) -> list:
    """Return permissions whose principal is not a live directory entry.

    ``directory`` maps a principal id to a mapping with a ``status`` key.  A
    principal is live only when that status is exactly ``"active"``.  An empty
    principal id, a principal missing from the directory and a principal with
    any other status are all orphaned.  A departed principal is therefore an
    orphan even though its id is non-empty.

    Every orphaned logical permission is returned once as a canonical grant
    with merged, sorted, unique sources.  Results are sorted by
    ``(principal, resource, action)``.  The snapshot is not mutated.
    """
    # Defect 3 fix: consult the directory status instead of only testing for
    # an empty principal; departed and unknown principals are orphaned too.
    findings = []
    for grant in _canonical_grants(snapshot["grants"]):
        entry = directory.get(grant["principal"])
        if not isinstance(entry, dict) or entry.get("status") != "active":
            findings.append(grant)
    return findings


def high_risk(grants, rules) -> list:
    """Return canonical grants matched by at least one high-risk rule.

    Each rule must match on both dimensions: ``rule["resource"]`` must equal the
    grant's resource exactly and ``rule["action"]`` must equal its action
    exactly.  Prefix resources, case variants and action wildcards never match,
    so a read-only grant is not high risk merely because its resource has a
    matching rule.

    ``grants`` may contain permission records, which carry ``source``, or
    canonical grants produced by another reporting function, which carry
    ``sources``.  A logical permission is returned once even when several rules
    match it and even when several source rows contribute to it.  Sources are
    merged, sorted and unique.  Results are sorted by
    ``(principal, resource, action)``.
    """
    # Defects 4 and 5 fix: match on exact (resource, action) pairs only, so
    # prefix resources and read-only actions are never treated as high risk.
    rule_pairs = {(rule["resource"], rule["action"]) for rule in rules}

    matched = {}
    for grant in grants:
        if (grant["resource"], grant["action"]) not in rule_pairs:
            continue
        key = (grant["principal"], grant["resource"], grant["action"])
        matched.setdefault(key, set()).update(_row_sources(grant))

    return [_canonical_from(key, sources) for key, sources in sorted(matched.items())]


def approval_valid(grant, approvals, now, ttl) -> bool:
    """Return whether at least one approval covers the grant and is fresh.

    An approval covers a grant only when ``principal``, ``resource`` and
    ``action`` all match exactly.  An approval for another principal, another
    resource or another action is out of scope and must not be accepted.

    An approval is fresh when ``issued_at`` is an integer, is not later than
    ``now`` and is not older than ``ttl``: ``now - ttl <= issued_at <= now``.
    The boundary is inclusive.  ``ttl`` must be a positive integer.  Any one
    valid approval is sufficient.  Missing, expired, future-dated and
    out-of-scope approvals do not make the grant valid.
    """
    # Defects 6 and 7 fix: require an exact three-dimensional scope match plus
    # a fresh, in-window issued_at; expired, future-dated and scoped-to-elsewhere
    # approvals are all rejected.
    for approval in approvals:
        if (
            approval["principal"] != grant["principal"]
            or approval["resource"] != grant["resource"]
            or approval["action"] != grant["action"]
        ):
            continue
        issued_at = approval["issued_at"]
        if isinstance(issued_at, bool) or not isinstance(issued_at, int):
            continue
        if now - ttl <= issued_at <= now:
            return True
    return False


def review(snapshot, directory, policy, now) -> dict:
    """Run one access review and return categorized findings and counts.

    ``policy`` supplies ``high_risk_rules`` and ``approval_ttl``.  Orphan
    checking runs only when ``policy["check_orphans"]`` is exactly true;
    otherwise the orphan category is empty.  ``policy`` may also supply an
    ``approvals`` sequence, which is validated with ``approval_ttl``.  A
    missing approvals key means that no approval exists.

    The result contains exactly these keys:

    * ``orphans``: canonical grants that are orphaned;
    * ``high_risk``: canonical grants matched by the high-risk rules;
    * ``unapproved``: canonical grants with no valid approval;
    * ``counts``: ``grants``, ``orphans``, ``high_risk`` and ``unapproved``,
      where ``grants`` is the number of distinct logical permissions in the
      snapshot.

    Every category is deduplicated by logical identity, uses merged sorted
    sources and is sorted by ``(principal, resource, action)``.  A grant may
    appear in more than one category, but it appears at most once per category.
    Multiple source rows for one permission never inflate a list or a count.
    """
    # Defect 8 fix: every category is built from canonical grants, so one
    # logical permission is counted once regardless of its source rows.
    grants = _canonical_grants(snapshot["grants"])
    approvals = policy.get("approvals", [])
    ttl = policy["approval_ttl"]

    if policy.get("check_orphans") is True:
        orphans = orphan_grants(snapshot, directory)
    else:
        orphans = []

    risky = high_risk(grants, policy["high_risk_rules"])

    unapproved = [
        grant
        for grant in grants
        if not approval_valid(grant, approvals, now, ttl)
    ]

    return {
        "orphans": orphans,
        "high_risk": risky,
        "unapproved": unapproved,
        "counts": {
            "grants": len(grants),
            "orphans": len(orphans),
            "high_risk": len(risky),
            "unapproved": len(unapproved),
        },
    }


def validate_policy(policy) -> list[str]:
    """Return problems that make a review policy unsafe, in this order.

    Exactly these strings are possible:

    * ``"missing high risk rules"`` when ``high_risk_rules`` is absent, is not
      a sequence, is a string or is empty;
    * ``"missing approval ttl"`` when ``approval_ttl`` is absent, is a bool, is
      not an integer or is not positive;
    * ``"orphan check disabled"`` when ``check_orphans`` is not exactly true.

    The function reports every problem rather than stopping at the first one.
    An empty list means the policy passed.  A policy without high-risk rules,
    without a positive approval lifetime or without orphan checking must never
    pass, because the review would silently omit a required control.
    """
    # Defect 9 fix: high-risk rule configuration is itself a required control
    # and is validated alongside the ttl and orphan-check settings.
    problems = []

    rules = policy.get("high_risk_rules")
    if (
        isinstance(rules, (str, bytes))
        or not isinstance(rules, (list, tuple))
        or len(rules) == 0
    ):
        problems.append("missing high risk rules")

    ttl = policy.get("approval_ttl")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        problems.append("missing approval ttl")

    if policy.get("check_orphans") is not True:
        problems.append("orphan check disabled")

    return problems


def review_batch(batches, policy, now) -> dict:
    """Review independent batches without sharing snapshot or principal state.

    ``batches`` is a sequence of mappings, each with an ``id``, a ``records``
    sequence and a ``directory`` mapping.  Every batch is loaded into its own
    snapshot and reviewed with the same ``policy`` and ``now``.  A principal
    seen in one batch must not make the same id live in another batch, and
    records from one batch must not leak into another batch.

    The result contains exactly:

    * ``batches``: a dict from batch id to the result that :func:`review`
      produces for that batch alone, preserving input order;
    * ``counts``: ``batches``, ``grants``, ``orphans``, ``high_risk`` and
      ``unapproved``, summed over the independent batch reviews.

    Each batch value has exactly the shape returned by :func:`review`.
    """
    # Defect 10 fix: each batch gets a freshly loaded snapshot and its own
    # directory; no index or principal set is reused across batches.
    batch_results = {}
    totals = {"grants": 0, "orphans": 0, "high_risk": 0, "unapproved": 0}

    for batch in batches:
        snapshot = load_snapshot(batch["records"])
        result = review(snapshot, batch["directory"], policy, now)
        batch_results[batch["id"]] = result
        for key in totals:
            totals[key] += result["counts"][key]

    return {
        "batches": batch_results,
        "counts": {"batches": len(batch_results), **totals},
    }
