# P00 supplemental tests

Command:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/capabilities/tests -p 'test_*.py' -v
```

Result: exit 0, 8 tests passed.

Covered assertions:

- exact 34-file accepted ADR register;
- unchanged Apache-2.0 license bytes;
- seven exact data-class identifiers and F01 through F28 flow coverage;
- explicit cutover/decommission consent contract and dual-write deferral;
- absence of stale binding claims;
- exact 69 capability and 10 incapability IDs;
- complete 253-anchor registry coverage;
- frozen 213 numbered-occurrence and 40 addendum-heading counts.
