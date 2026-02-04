#!/usr/bin/env python3
"""Compare Criterion means between two benchmark runs and fail on regressions."""

from __future__ import annotations

import json
import pathlib
import sys


def load_means(target_dir: pathlib.Path) -> dict[str, float]:
    root = target_dir / "criterion" / "evaluate"
    if not root.exists():
        raise SystemExit(f"missing criterion output directory: {root}")

    means: dict[str, float] = {}
    for estimates in sorted(root.glob("*/new/estimates.json")):
        scenario = estimates.parents[1].name
        data = json.loads(estimates.read_text())
        means[scenario] = float(data["mean"]["point_estimate"])

    if not means:
        raise SystemExit(f"no scenario estimates found under: {root}")

    return means


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: compare_criterion.py <base_target_dir> <head_target_dir> <max_regression_pct>",
            file=sys.stderr,
        )
        return 2

    base_dir = pathlib.Path(sys.argv[1]).resolve()
    head_dir = pathlib.Path(sys.argv[2]).resolve()
    threshold_pct = float(sys.argv[3])
    threshold_ratio = 1.0 + (threshold_pct / 100.0)

    base = load_means(base_dir)
    head = load_means(head_dir)

    missing = sorted(set(base) ^ set(head))
    if missing:
        print("scenario mismatch between baseline and head:", ", ".join(missing), file=sys.stderr)
        return 3

    failures: list[str] = []

    print("Scenario                          Base(ns)      Head(ns)      Delta")
    print("-------------------------------  -----------  -----------  --------")

    for name in sorted(base):
        base_ns = base[name]
        head_ns = head[name]
        ratio = head_ns / base_ns if base_ns else float("inf")
        delta_pct = (ratio - 1.0) * 100.0
        print(f"{name:31}  {base_ns:11.0f}  {head_ns:11.0f}  {delta_pct:>7.2f}%")
        if ratio > threshold_ratio:
            failures.append(
                f"{name}: regression {delta_pct:.2f}% exceeds threshold {threshold_pct:.2f}%"
            )

    if failures:
        print("\nRegressions detected:", file=sys.stderr)
        for line in failures:
            print(f"- {line}", file=sys.stderr)
        return 4

    print(f"\nOK: no scenario regressed more than {threshold_pct:.2f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
