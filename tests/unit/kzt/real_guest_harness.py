#!/usr/bin/env python3
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import select
import shutil
import signal
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache


PRIMARY_TIME_METRICS = (
    "startup_process_total_ns",
    "launch_to_first_result_ns",
    "steady_total_ns",
)
GUEST_LAZY_COMPARISON_METRICS = (
    "startup_process_total_ns",
    "launch_to_first_result_ns",
)
GUEST_FIRST_BINDING_METRIC = "first_binding_ns"
PERFORMANCE_MARKER = "KZT_GUEST_PERF_OK"
HARNESS_SCHEMA_VERSION = 2
REPORT_ARTIFACT_TYPE = "kzt-real-guest-performance-report"
METADATA_ARTIFACT_TYPE = "kzt-real-guest-performance-run-metadata"
OWNERSHIP_MARKER = ".kzt-real-guest-harness-owner"
MIN_FAIL_PAIRS = 400
FORMAL_AA_MIN_PAIRS = 200
MEDIAN_NONINFERIORITY_LOG = math.log(1.01)
P95_NONINFERIORITY_LOG = math.log(1.02)
FIRST_BINDING_NONINFERIORITY_LOG = 0.0
AA_STABILITY_LOG_LIMIT = math.log(1.005)
AA_COMPARISON_COUNT = len(PRIMARY_TIME_METRICS) * 3 * 2
AA_FAMILY_ALPHA = 0.01
AA_INTERVAL_ALPHA = AA_FAMILY_ALPHA / AA_COMPARISON_COUNT
AA_TEMPORAL_INDEPENDENCE_ASSUMPTION = (
    "time-ordered early/late paired contrasts are independent across pair indices"
)
AB_COMPARISON_COUNT = len(PRIMARY_TIME_METRICS) * 2
AB_FAMILY_ALPHA = 0.01
P95_BOOTSTRAP_RESAMPLES = 20000
PERFORMANCE_EXECUTABLE = "kzt_guest_perf_main"
PERFORMANCE_LIBRARY = "libkzt_guest_perf_probe.so"
PERFORMANCE_MODES = ("startup", "first", "steady")
CPU_SYSFS_ROOT = Path("/sys/devices/system/cpu")
NATIVE_APPLY_SYMBOL = "dlerror"
EAGER_FINAL = "EAGER_FINAL"
LAZY_TO_GUEST_FINAL = "LAZY_TO_GUEST_FINAL"
LAZY_TO_NATIVE_FINAL = "LAZY_TO_NATIVE_FINAL"
PREBOUND_NATIVE_FINAL = "PREBOUND_NATIVE_FINAL"
BASELINE_BINDING_STATES = (
    EAGER_FINAL,
    LAZY_TO_GUEST_FINAL,
    LAZY_TO_NATIVE_FINAL,
)


def comparison_metrics_for_baseline_state(baseline_binding_state):
    if baseline_binding_state not in BASELINE_BINDING_STATES:
        raise ValueError("invalid baseline binding state")
    if baseline_binding_state == LAZY_TO_GUEST_FINAL:
        return GUEST_LAZY_COMPARISON_METRICS
    return PRIMARY_TIME_METRICS
COMMON_KZT_ENVIRONMENT = {
    # AOT forks a detached compiler at guest exit.  It is unrelated to the
    # measured lazy call and can overlap the following pinned sample.
    "LATX_AOT": "0",
    "LATX_KZT": "2",
    "LATX_KZT_LAZY_DIAGNOSTICS": "0",
    "LATX_KZT_REGISTRY_DIAGNOSTICS": "0",
}
CANDIDATE_WRITER_ENVIRONMENT = {
    "LATX_KZT_PATCH_SPIKE": "1",
    "LATX_KZT_PATCH_SPIKE_WRITE": "1",
    "LATX_KZT_PATCH_SPIKE_BUDGET": "1",
}
SANITIZED_RUNTIME_VARIABLES = (
    "LAT_DFILTER",
    "LAT_GDB",
    "LAT_LOG",
    "LAT_LOG_FILENAME",
    "LAT_SINGLESTEP",
    "LAT_STRACE",
    "LAT_STRACE_ERROR",
    "LAT_TRACE",
    "LD_AUDIT",
    "LD_BIND_NOW",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_PROFILE",
    "QEMU_LOG",
    "QEMU_STRACE",
)


class GateResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class AAResult(str, Enum):
    STABLE = "STABLE"
    DRIFT = "DRIFT"
    INCONCLUSIVE = "INCONCLUSIVE"


class GuestCorrectnessError(RuntimeError):
    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details


class PrerequisiteError(RuntimeError):
    pass


@dataclass(frozen=True)
class HarnessConfig:
    baseline_latx: Path
    candidate_latx: Path
    guest_root: Path
    fixture_dir: Path
    cpu: int
    warmup: int
    samples: int
    max_samples: int
    aa_samples: int
    steady_calls: int
    seed: int
    output_dir: Path
    timeout: float = 60.0
    baseline_binding_state: str = EAGER_FINAL
    isolate_harness_cpu: bool = False
    aa_only: bool = False


def percentile(values, quantile):
    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between zero and one")
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _derived_seed(seed, *parts):
    material = ":".join([str(seed), *(str(part) for part in parts)])
    return int.from_bytes(
        hashlib.sha256(material.encode("ascii")).digest()[:8], "big"
    )


def randomized_pair_orders(pair_count, seed, labels):
    if pair_count < 0:
        raise ValueError("pair_count must be non-negative")
    if len(labels) != 2 or labels[0] == labels[1]:
        raise ValueError("labels must contain two distinct values")
    rng = random.Random(seed)
    orientations = [0, 1] * (pair_count // 2)
    if pair_count % 2:
        orientations.append(rng.randrange(2))
    rng.shuffle(orientations)
    forward = tuple(labels)
    reverse = tuple(reversed(labels))
    return [forward if orientation == 0 else reverse
            for orientation in orientations]


def _sample_statistic(values, statistic):
    if statistic == "median":
        return statistics.median(values)
    if statistic == "p95":
        return percentile(values, 0.95)
    raise ValueError(f"Unsupported statistic: {statistic}")


def _parse_integer(record, name):
    try:
        return int(record[name], 0)
    except KeyError as error:
        raise GuestCorrectnessError(
            f"Performance record is missing {name}."
        ) from error
    except ValueError as error:
        raise GuestCorrectnessError(
            f"Performance record has invalid {name}: {record[name]}"
        ) from error


def parse_guest_record(output, expected_steady_calls, *, expected_mode=None):
    records = []
    for line in output.splitlines():
        marker_at = line.find(PERFORMANCE_MARKER)
        if marker_at < 0:
            continue
        fields = {}
        for field in line[marker_at:].split()[1:]:
            if "=" not in field:
                continue
            name, value = field.split("=", 1)
            fields[name] = value
        records.append(fields)
    if len(records) != 1:
        raise GuestCorrectnessError(
            "Expected exactly one KZT_GUEST_PERF_OK record, "
            f"found {len(records)}."
        )

    fields = records[0]
    mode = fields.get("mode")
    if expected_mode is not None and mode != expected_mode:
        raise GuestCorrectnessError(
            f"Guest ran mode {mode!r}, expected {expected_mode!r}."
        )
    if mode is not None and mode not in PERFORMANCE_MODES:
        raise GuestCorrectnessError(f"Guest reported unknown mode {mode!r}.")
    steady_calls = _parse_integer(fields, "steady_calls")
    slot = _parse_integer(fields, "slot")
    before = _parse_integer(fields, "before")
    after_first = _parse_integer(fields, "after_first")
    after_steady = _parse_integer(fields, "after_steady")
    first_ns = _parse_integer(fields, "first_ns")
    steady_total_ns = _parse_integer(fields, "steady_total_ns")
    steady_per_call_ns = _parse_integer(fields, "steady_per_call_ns")
    checksum = _parse_integer(fields, "checksum")

    if mode == "startup":
        if any((steady_calls, slot, before, after_first, after_steady,
                first_ns, steady_total_ns, steady_per_call_ns, checksum)):
            raise GuestCorrectnessError(
                "Guest startup mode must not call dlerror or report slot data."
            )
    elif mode == "first":
        if steady_calls != 0 or slot <= 0 or before <= 0 or \
           after_first <= 0 or after_steady != after_first or \
           first_ns <= 0 or steady_total_ns != 0 or \
           steady_per_call_ns != 0 or checksum != 1:
            raise GuestCorrectnessError(
                "Guest first mode did not report one stable NULL dlerror call."
            )
    elif mode == "steady":
        if steady_calls != expected_steady_calls or slot <= 0 or before <= 0 or \
           after_first <= 0 or after_steady != after_first or \
           first_ns <= 0 or steady_total_ns <= 0 or \
           steady_per_call_ns <= 0 or \
           steady_per_call_ns != steady_total_ns // steady_calls or \
           checksum != steady_calls + 1:
            raise GuestCorrectnessError(
                "Guest steady mode did not report stable NULL dlerror calls."
            )
    else:
        if steady_calls != expected_steady_calls:
            raise GuestCorrectnessError(
                f"Guest ran {steady_calls} steady calls, expected "
                f"{expected_steady_calls}."
            )
        if slot == 0 or before == 0 or checksum == 0:
            raise GuestCorrectnessError(
                "Guest reported an invalid slot, initial value, or checksum."
            )
        if after_first == before:
            raise GuestCorrectnessError(
                "The first call did not resolve the lazy binding slot: "
                f"before=0x{before:x} after_first=0x{after_first:x}."
            )
        if after_steady != after_first:
            raise GuestCorrectnessError(
                "The lazy binding slot changed during steady calls: "
                f"after_first=0x{after_first:x} after_steady=0x{after_steady:x}."
            )
        if first_ns <= 0 or steady_total_ns <= 0 or steady_per_call_ns <= 0:
            raise GuestCorrectnessError("Guest reported a non-positive timing.")
        if steady_per_call_ns != steady_total_ns // steady_calls:
            raise GuestCorrectnessError(
                "Guest steady per-call timing does not match its total."
            )
    return {
        "mode": mode,
        "steady_calls": steady_calls,
        "slot": slot,
        "before": before,
        "after_first": after_first,
        "after_steady": after_steady,
        "first_binding_ns": first_ns,
        "steady_total_ns": steady_total_ns,
        "steady_per_call_ns": steady_per_call_ns,
        "checksum": checksum,
    }


def validate_role_mode_record(role, mode, guest, *, baseline_binding_state=None):
    if role not in ("baseline", "candidate"):
        raise ValueError(f"Unknown benchmark role: {role}")
    if mode not in ("first", "steady"):
        raise ValueError(f"Mode has no binding state: {mode}")
    try:
        before = guest["before"]
        after_first = guest["after_first"]
        after_steady = guest["after_steady"]
    except KeyError as error:
        raise GuestCorrectnessError(
            f"{role} {mode} record is missing slot evidence: {error.args[0]}"
        ) from error
    if role == "baseline":
        expected_state = (EAGER_FINAL if baseline_binding_state is None
                          else baseline_binding_state)
        if expected_state not in BASELINE_BINDING_STATES:
            raise ValueError(
                "baseline binding state must be EAGER_FINAL, "
                "LAZY_TO_GUEST_FINAL, or LAZY_TO_NATIVE_FINAL."
            )
        if (expected_state == EAGER_FINAL and
                before == after_first == after_steady):
            return EAGER_FINAL
        if (expected_state in (LAZY_TO_GUEST_FINAL, LAZY_TO_NATIVE_FINAL) and
                before != after_first == after_steady):
            return expected_state
        raise GuestCorrectnessError(
            f"baseline {mode} must be {expected_state}: "
            f"before=0x{before:x} after_first=0x{after_first:x} "
            f"after_steady=0x{after_steady:x}."
        )
    if before == after_first == after_steady:
        return PREBOUND_NATIVE_FINAL
    if before != after_first == after_steady:
        return LAZY_TO_NATIVE_FINAL
    raise GuestCorrectnessError(
        f"candidate {mode} must be LAZY_TO_NATIVE_FINAL: "
        f"before=0x{before:x} after_first=0x{after_first:x} "
        f"after_steady=0x{after_steady:x}."
    )


def _metric_values(pairs, label, metric):
    try:
        return [pair[label][metric] for pair in pairs]
    except KeyError as error:
        raise ValueError(
            f"Pair is missing {label}.{metric}."
        ) from error


@lru_cache(maxsize=None)
def _binomial_cdf(count, trials, probability):
    if count < 0:
        return 0.0
    if count >= trials:
        return 1.0
    if probability <= 0.0:
        return 1.0
    if probability >= 1.0:
        return 0.0
    log_probability = math.log(probability)
    log_complement = math.log1p(-probability)
    log_terms = [
        math.lgamma(trials + 1) - math.lgamma(value + 1) -
        math.lgamma(trials - value + 1) +
        value * log_probability + (trials - value) * log_complement
        for value in range(count + 1)
    ]
    maximum = max(log_terms)
    return min(
        1.0,
        math.exp(maximum) * math.fsum(
            math.exp(term - maximum) for term in log_terms
        ),
    )


def _order_statistic_interval(values, *, quantile, alpha,
                              confidence, method):
    if not values:
        raise ValueError("order-statistic interval requires samples")
    if not 0.0 < quantile < 1.0:
        raise ValueError("quantile must be strictly between zero and one")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be strictly between zero and one")
    ordered = sorted(values)
    count = len(ordered)
    lower_rank = max(
        (rank for rank in range(1, count + 1)
         if _binomial_cdf(rank - 1, count, quantile) <= alpha / 2),
        default=None,
    )
    upper_rank = next(
        (rank for rank in range(1, count + 1)
         if _binomial_cdf(rank - 1, count, quantile) >= 1.0 - alpha / 2),
        None,
    )
    estimate = percentile(values, quantile)
    return {
        "estimate": estimate,
        "lower": ordered[lower_rank - 1] if lower_rank else None,
        "upper": ordered[upper_rank - 1] if upper_rank else None,
        "ratio": math.exp(estimate),
        "confidence": confidence,
        "alpha": alpha,
        "sample_count": count,
        "lower_rank": lower_rank,
        "upper_rank": upper_rank,
        "method": method,
    }


def _one_sided_quantile_bounds(values, *, quantile, alpha, log_scale=True):
    if not values:
        raise ValueError("order-statistic bounds require samples")
    if not 0.0 < quantile < 1.0:
        raise ValueError("quantile must be strictly between zero and one")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be strictly between zero and one")
    ordered = sorted(values)
    count = len(ordered)
    lower_rank = max(
        (rank for rank in range(1, count + 1)
         if _binomial_cdf(rank - 1, count, quantile) <= alpha),
        default=None,
    )
    upper_rank = next(
        (rank for rank in range(1, count + 1)
         if _binomial_cdf(rank - 1, count, quantile) >= 1.0 - alpha),
        None,
    )
    estimate = percentile(values, quantile)
    return {
        "estimate": estimate,
        "lower": ordered[lower_rank - 1] if lower_rank else None,
        "upper": ordered[upper_rank - 1] if upper_rank else None,
        "ratio": math.exp(estimate) if log_scale else None,
        "one_sided_confidence": 1.0 - alpha,
        "alpha": alpha,
        "sample_count": count,
        "lower_rank": lower_rank,
        "upper_rank": upper_rank,
        "method": "exact binomial quantile order-statistic bounds",
        "estimate_method": "linear interpolated sample quantile",
    }


@lru_cache(maxsize=128)
def _paired_index_bootstrap_p95_cached(baseline, candidate, alpha, seed,
                                       resamples):
    if len(baseline) != len(candidate) or not baseline:
        raise ValueError("paired P95 bootstrap requires equal non-empty samples")
    if any(value <= 0 for value in baseline + candidate):
        raise ValueError("paired P95 bootstrap samples must be positive")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be strictly between zero and one")
    if resamples < 1:
        raise ValueError("paired P95 bootstrap requires resamples")
    rng = random.Random(seed)
    population = range(len(baseline))
    bootstrap_log_ratios = []
    for _ in range(resamples):
        indices = rng.choices(population, k=len(baseline))
        baseline_p95 = percentile(
            [baseline[index] for index in indices], 0.95
        )
        candidate_p95 = percentile(
            [candidate[index] for index in indices], 0.95
        )
        bootstrap_log_ratios.append(
            math.log(candidate_p95 / baseline_p95)
        )
    estimate = math.log(
        percentile(candidate, 0.95) / percentile(baseline, 0.95)
    )
    return {
        "estimate": estimate,
        "lower": percentile(bootstrap_log_ratios, alpha),
        "upper": percentile(bootstrap_log_ratios, 1.0 - alpha),
        "ratio": math.exp(estimate),
        "one_sided_confidence": 1.0 - alpha,
        "alpha": alpha,
        "sample_count": len(baseline),
        "bootstrap_resamples": resamples,
        "bootstrap_seed": seed,
        "resampling_unit": "paired sample index",
        "method": "paired-index percentile bootstrap P95 log-ratio bounds",
        "estimate_method": (
            "log(linear-interpolated candidate P95 / "
            "linear-interpolated baseline P95)"
        ),
    }


def _paired_index_bootstrap_p95_bounds(baseline, candidate, *, alpha, seed,
                                       resamples=P95_BOOTSTRAP_RESAMPLES):
    return dict(_paired_index_bootstrap_p95_cached(
        tuple(baseline), tuple(candidate), alpha, seed, resamples
    ))


def _ab_ratio_bound_alpha(analysis_look_count,
                          comparison_count=AB_COMPARISON_COUNT):
    if analysis_look_count < 1:
        raise ValueError("analysis_look_count must be positive")
    if comparison_count <= 0:
        raise ValueError("comparison_count must be positive")
    return AB_FAMILY_ALPHA / (analysis_look_count * comparison_count)


def analyze_ab_pairs(pairs, *, seed, formal_stage_count=1,
                     analysis_look_count=None,
                     metrics=PRIMARY_TIME_METRICS, tail_metrics=None):
    if not pairs:
        raise ValueError("A/B analysis requires at least one pair")
    metrics = tuple(metrics)
    if not metrics:
        raise ValueError("A/B analysis requires at least one metric")
    tail_metrics = tuple(metrics if tail_metrics is None else tail_metrics)
    if any(metric not in metrics for metric in tail_metrics):
        raise ValueError("A/B tail metrics must be comparison metrics")
    if analysis_look_count is None:
        analysis_look_count = formal_stage_count
    comparison_count = len(metrics) + len(tail_metrics)
    ratio_bound_alpha = _ab_ratio_bound_alpha(
        analysis_look_count, comparison_count
    )
    metric_details = {}
    for metric in metrics:
        baseline = _metric_values(pairs, "baseline", metric)
        candidate = _metric_values(pairs, "candidate", metric)
        if any(value <= 0 for value in baseline + candidate):
            raise ValueError(f"{metric} samples must be positive")
        log_ratios = [
            math.log(candidate_value / baseline_value)
            for baseline_value, candidate_value in zip(baseline, candidate)
        ]
        details = {
            "baseline": {
                "median": statistics.median(baseline),
                "p95": percentile(baseline, 0.95),
            },
            "candidate": {
                "median": statistics.median(candidate),
                "p95": percentile(candidate, 0.95),
            },
            "paired_log_ratio": {
                "median": _one_sided_quantile_bounds(
                    log_ratios,
                    quantile=0.5,
                    alpha=ratio_bound_alpha,
                ),
            },
            "required_statistics": (
                ("median", "p95") if metric in tail_metrics else ("median",)
            ),
            "noninferiority_log": {
                "median": (FIRST_BINDING_NONINFERIORITY_LOG
                           if metric == GUEST_FIRST_BINDING_METRIC
                           else MEDIAN_NONINFERIORITY_LOG),
            },
        }
        if metric in tail_metrics:
            paired_p95 = _paired_index_bootstrap_p95_bounds(
                baseline,
                candidate,
                alpha=ratio_bound_alpha,
                seed=seed,
            )
            details["paired_index_bootstrap_p95_log_ratio"] = {
                "p95": paired_p95
            }
            details["noninferiority_log"]["p95"] = \
                P95_NONINFERIORITY_LOG
        metric_details[metric] = details
    return {
        "pair_count": len(pairs),
        "metrics": metric_details,
        "comparison_count": comparison_count,
        "formal_stage_count": formal_stage_count,
        "analysis_look_count": analysis_look_count,
        "per_ratio_bound_alpha": ratio_bound_alpha,
        "per_ratio_bound_confidence": 1.0 - ratio_bound_alpha,
        "pass_upper_family_confidence": 1.0 - AB_FAMILY_ALPHA,
        "fail_lower_family_confidence": 1.0 - AB_FAMILY_ALPHA,
    }


def _interval_exceeds_aa_stability_limit(interval):
    return ((interval["lower"] is not None and
             interval["lower"] > AA_STABILITY_LOG_LIMIT) or
            (interval["upper"] is not None and
             interval["upper"] < -AA_STABILITY_LOG_LIMIT))


def _interval_is_within_aa_stability_limit(interval):
    return (interval["lower"] is not None and interval["upper"] is not None
            and interval["lower"] >= -AA_STABILITY_LOG_LIMIT
            and interval["upper"] <= AA_STABILITY_LOG_LIMIT)


def assess_aa_pairs(pairs, *, seed, metrics=PRIMARY_TIME_METRICS):
    if len(pairs) < 4:
        raise ValueError("A/A stability analysis requires at least four pairs")
    metrics = tuple(metrics)
    if not metrics:
        raise ValueError("A/A stability analysis requires at least one metric")
    comparison_count = len(metrics) * 3 * 2
    interval_alpha = AA_FAMILY_ALPHA / comparison_count
    metric_details = {}
    for metric in metrics:
        a_values = _metric_values(pairs, "a", metric)
        b_values = _metric_values(pairs, "b", metric)
        label_interval = _order_statistic_interval(
            [math.log(b / a) for a, b in zip(a_values, b_values)],
            quantile=0.5,
            alpha=interval_alpha,
            confidence=1.0 - interval_alpha,
            method="exact binomial median order-statistic interval",
        )
        order_interval = _order_statistic_interval(
            [
                math.log(pair[pair["order"][1]][metric] /
                         pair[pair["order"][0]][metric])
                for pair in pairs
            ],
            quantile=0.5,
            alpha=interval_alpha,
            confidence=1.0 - interval_alpha,
            method="exact binomial median order-statistic interval",
        )
        pair_centers = [
            math.sqrt(a * b) for a, b in zip(a_values, b_values)
        ]
        half = len(pair_centers) // 2
        early = pair_centers[:half]
        late = pair_centers[-half:]
        temporal_interval = _order_statistic_interval(
            [math.log(later / earlier) for earlier, later in zip(early, late)],
            quantile=0.5,
            alpha=interval_alpha,
            confidence=1.0 - interval_alpha,
            method=(
                "exact binomial median order-statistic interval over "
                "time-ordered early/late paired contrasts"
            ),
        )
        metric_details[metric] = {
            "label": label_interval,
            "execution_order": order_interval,
            "temporal": temporal_interval,
        }
    intervals = [
        interval
        for details in metric_details.values()
        for interval in details.values()
    ]
    drift = any(_interval_exceeds_aa_stability_limit(interval)
                for interval in intervals)
    stable = all(_interval_is_within_aa_stability_limit(interval)
                 for interval in intervals)
    if drift:
        result = AAResult.DRIFT
    elif stable and len(pairs) >= FORMAL_AA_MIN_PAIRS:
        result = AAResult.STABLE
    else:
        result = AAResult.INCONCLUSIVE
    reasons = []
    for metric, details in metric_details.items():
        for name, interval in details.items():
            if _interval_exceeds_aa_stability_limit(interval):
                reasons.append(f"{metric}: A/A {name} drift")
    return {
        "result": result.value,
        "stable": result == AAResult.STABLE,
        "reasons": reasons,
        "metrics": metric_details,
        "mode": "formal" if len(pairs) >= FORMAL_AA_MIN_PAIRS else "screening",
        "pair_count": len(pairs),
        "comparison_count": comparison_count,
        "family_confidence": 1.0 - AA_FAMILY_ALPHA,
        "per_interval_confidence": 1.0 - interval_alpha,
        "stability_log_limit": AA_STABILITY_LOG_LIMIT,
        "stability_percent_limit": 0.5,
        "temporal_design": "time-ordered early/late paired contrasts",
        "temporal_independence_assumption": AA_TEMPORAL_INDEPENDENCE_ASSUMPTION,
    }


def assess_dual_aa(baseline_pairs, candidate_pairs, *, seed,
                   metrics=PRIMARY_TIME_METRICS):
    metrics = tuple(metrics)
    baseline = assess_aa_pairs(
        baseline_pairs,
        seed=_derived_seed(seed, "baseline-aa"),
        metrics=metrics,
    )
    candidate = assess_aa_pairs(
        candidate_pairs,
        seed=_derived_seed(seed, "candidate-aa"),
        metrics=metrics,
    )
    results = {baseline["result"], candidate["result"]}
    if AAResult.DRIFT.value in results:
        result = AAResult.DRIFT
    elif results == {AAResult.STABLE.value}:
        result = AAResult.STABLE
    else:
        result = AAResult.INCONCLUSIVE
    return {
        "result": result.value,
        "stable": result == AAResult.STABLE,
        "baseline": baseline,
        "candidate": candidate,
        "comparison_count": len(metrics) * 3 * 2,
        "family_confidence": 1.0 - AA_FAMILY_ALPHA,
    }


def classify_gate(analysis, *, pair_count, formal_aa_stable):
    all_supported_non_slowdown = True
    clearly_slower_statistics = []
    for metric, details in analysis["metrics"].items():
        for statistic in details["required_statistics"]:
            family = ("paired_log_ratio" if statistic == "median" else
                      "paired_index_bootstrap_p95_log_ratio")
            interval = details[family][statistic]
            threshold = details["noninferiority_log"][statistic]
            all_supported_non_slowdown &= (
                interval["upper"] is not None and
                interval["upper"] <= threshold
            )
            if (interval["lower"] is not None and
                    interval["lower"] > threshold):
                clearly_slower_statistics.append(f"{metric}.{statistic}")
    analysis["clearly_slower_statistics"] = clearly_slower_statistics
    analysis["all_metrics_support_non_slowdown"] = (
        all_supported_non_slowdown
    )
    if (all_supported_non_slowdown and pair_count >= MIN_FAIL_PAIRS and
            formal_aa_stable):
        return GateResult.PASS
    if (clearly_slower_statistics and pair_count >= MIN_FAIL_PAIRS and
            formal_aa_stable):
        return GateResult.FAIL
    return GateResult.INCONCLUSIVE


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _command_output(command, timeout=10.0):
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _git_metadata(path):
    commit = _command_output(
        ["git", "-C", str(path.parent), "rev-parse", "HEAD"]
    )
    root = _command_output(
        ["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"]
    )
    if not commit:
        return {"commit": None, "git_root": None, "git_dirty": None}
    dirty_output = _command_output(
        [
            "git",
            "-C",
            str(path.parent),
            "status",
            "--porcelain",
            "--untracked-files=no",
        ]
    )
    return {
        "commit": commit,
        "git_root": root,
        "git_dirty": bool(dirty_output),
    }


def _elf_build_id(path):
    readelf = shutil.which("readelf") or shutil.which("llvm-readelf")
    if not readelf:
        return None
    output = _command_output([readelf, "-n", str(path)])
    if not output:
        return None
    for line in output.splitlines():
        if "Build ID:" in line:
            return line.split("Build ID:", 1)[1].strip()
    return None


def _elf_compiler(path):
    readelf = shutil.which("readelf") or shutil.which("llvm-readelf")
    if not readelf:
        return None
    return _command_output(
        [readelf, "--string-dump=.comment", str(path)]
    )


def collect_binary_metadata(path):
    metadata = {"path": str(path)}
    if not path.is_file():
        metadata.update({
            "exists": False,
            "sha256": None,
            "build_id": None,
            "compiler": None,
            "commit": None,
            "git_root": None,
            "git_dirty": None,
        })
        return metadata
    metadata.update({
        "exists": True,
        "size_bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
        "build_id": _elf_build_id(path),
        "compiler": _elf_compiler(path),
    })
    metadata.update(_git_metadata(path))
    return metadata


def _read_optional_text(path):
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace").strip()


def guest_compiler_metadata():
    command = os.environ.get(
        "KZT_GUEST_CC", "x86_64-linux-gnu-gcc"
    ).split()[0]
    return {
        "command": command,
        "path": shutil.which(command),
        "available": shutil.which(command) is not None,
    }


def collect_fixture_metadata(fixture_dir):
    executable = fixture_dir / PERFORMANCE_EXECUTABLE
    library = fixture_dir / PERFORMANCE_LIBRARY
    metadata = {
        "path": str(fixture_dir),
        "compiler": _read_optional_text(
            fixture_dir / "guest-compiler.txt"
        ),
        "build_parameters": _read_optional_text(
            fixture_dir / "guest-build-parameters.txt"
        ),
        "builder": guest_compiler_metadata(),
        "performance_executable": collect_binary_metadata(executable),
        "performance_library": collect_binary_metadata(library),
    }
    if metadata["compiler"] is None and executable.is_file():
        metadata["compiler"] = metadata["performance_executable"][
            "compiler"
        ]
    return metadata


def _affinity_snapshot():
    if not hasattr(os, "sched_getaffinity"):
        return None
    try:
        return sorted(os.sched_getaffinity(0))
    except OSError:
        return None


def _parse_cpu_list(value):
    cpus = set()
    for part in value.strip().split(","):
        if not part:
            raise ValueError("CPU list contains an empty item")
        bounds = part.split("-", 1)
        try:
            first = int(bounds[0])
            last = int(bounds[-1])
        except ValueError as error:
            raise ValueError(f"invalid CPU list item: {part}") from error
        if first < 0 or last < first:
            raise ValueError(f"invalid CPU list range: {part}")
        cpus.update(range(first, last + 1))
    if not cpus:
        raise ValueError("CPU list is empty")
    return sorted(cpus)


def _thread_siblings_path(guest_cpu):
    return (
        CPU_SYSFS_ROOT / f"cpu{guest_cpu}" / "topology" /
        "thread_siblings_list"
    )


def _thread_siblings(guest_cpu):
    path = _thread_siblings_path(guest_cpu)
    try:
        siblings = _parse_cpu_list(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, ValueError) as error:
        raise PrerequisiteError(
            f"cannot verify thread siblings from {path}: {error}"
        ) from error
    if guest_cpu not in siblings:
        raise PrerequisiteError(
            f"thread siblings from {path} do not contain guest CPU {guest_cpu}"
        )
    return path, siblings


def _cpu_isolation_record(enabled, guest_cpu, initial=None):
    if initial is None:
        initial = _affinity_snapshot()
    return {
        "requested": bool(enabled),
        "applied": False,
        "guest_cpu": guest_cpu,
        "topology_source": str(_thread_siblings_path(guest_cpu)),
        "thread_siblings": None,
        "initial_affinity": initial,
        "active_affinity": initial,
        "parent_cpus": {
            "initial": initial,
            "expected": initial,
            "active": initial,
        },
        "excluded_cpus": [],
        "verification": {
            "passed": False,
            "siblings_excluded": None,
            "active_matches_expected": None,
            "error": (None if enabled else
                      "physical-core isolation was not requested"),
        },
    }


def activate_harness_cpu_isolation(enabled, guest_cpu):
    initial = _affinity_snapshot()
    isolation = _cpu_isolation_record(enabled, guest_cpu, initial)
    if not enabled:
        return isolation
    try:
        if not hasattr(os, "sched_setaffinity"):
            raise PrerequisiteError("harness CPU isolation is unavailable")
        if initial is None or guest_cpu not in initial:
            raise PrerequisiteError(
                f"guest CPU {guest_cpu} is unavailable for harness isolation"
            )
        topology_source, siblings = _thread_siblings(guest_cpu)
        active = [cpu for cpu in initial if cpu not in siblings]
        isolation["topology_source"] = str(topology_source)
        isolation["thread_siblings"] = siblings
        isolation["excluded_cpus"] = sorted(set(initial) & set(siblings))
        isolation["parent_cpus"]["expected"] = active
        if not active:
            raise PrerequisiteError(
                "harness isolation requires a CPU outside the guest core"
            )
        os.sched_setaffinity(0, set(active))
        isolation["applied"] = True
        observed = _affinity_snapshot()
        isolation["active_affinity"] = observed
        isolation["parent_cpus"]["active"] = observed
        siblings_excluded = (
            observed is not None and not set(observed).intersection(siblings)
        )
        active_matches = observed == active
        isolation["verification"].update({
            "siblings_excluded": siblings_excluded,
            "active_matches_expected": active_matches,
            "passed": siblings_excluded and active_matches,
        })
        if not isolation["verification"]["passed"]:
            raise PrerequisiteError(
                "harness CPU isolation verification failed: expected "
                f"{active}, observed {observed}, siblings {siblings}"
            )
    except (PrerequisiteError, OSError) as error:
        isolation["verification"]["error"] = str(error)
    return isolation


def restore_harness_cpu_isolation(isolation):
    if not isolation.get("applied") or "restored_affinity" in isolation:
        return isolation
    initial = isolation.get("initial_affinity")
    if initial is None:
        return isolation
    os.sched_setaffinity(0, set(initial))
    isolation["restored_affinity"] = _affinity_snapshot()
    return isolation


def host_load_snapshot():
    affinity = _affinity_snapshot()
    cpu_capacity = len(affinity) if affinity else os.cpu_count()
    try:
        load_average = list(os.getloadavg())
    except (AttributeError, OSError):
        load_average = None
    oversubscribed = bool(
        load_average and cpu_capacity and load_average[0] > cpu_capacity
    )
    return {
        "captured_at": _utc_now(),
        "load_average_1_5_15": load_average,
        "available_cpu_count": cpu_capacity,
        "oversubscribed": oversubscribed,
    }


def collect_host_metadata(cpu, taskset):
    uname = platform.uname()
    return {
        "hostname": uname.node,
        "system": uname.system,
        "release": uname.release,
        "machine": uname.machine,
        "processor": uname.processor,
        "python": platform.python_version(),
        "requested_cpu": cpu,
        "process_affinity": _affinity_snapshot(),
        "taskset": taskset,
        "max_rss_unit": "KiB" if uname.system == "Linux" else "bytes",
    }


def prerequisite_issues(config):
    issues = []
    for label, path in (
        ("baseline LATX", config.baseline_latx),
        ("candidate LATX", config.candidate_latx),
    ):
        if not path.is_file():
            issues.append(f"{label} does not exist: {path}")
        elif not os.access(path, os.X_OK):
            issues.append(f"{label} is not executable: {path}")
    if not config.guest_root.is_dir():
        issues.append(f"guest root does not exist: {config.guest_root}")
    fixture_unavailable = False
    if not config.fixture_dir.is_dir():
        issues.append(f"fixture directory does not exist: {config.fixture_dir}")
        fixture_unavailable = True
    else:
        missing_fixture = []
        for name in (PERFORMANCE_EXECUTABLE, PERFORMANCE_LIBRARY):
            if not (config.fixture_dir / name).is_file():
                missing_fixture.append(name)
        if missing_fixture:
            issues.append(
                "fixture is missing " + ", ".join(missing_fixture)
            )
            fixture_unavailable = True
    if fixture_unavailable:
        compiler = guest_compiler_metadata()
        if compiler["available"]:
            issues.append(
                "x86-64 guest compiler is available at "
                + compiler["path"]
                + "; build the performance fixture before rerunning"
            )
        else:
            issues.append(
                "x86-64 guest compiler is unavailable: "
                + compiler["command"]
            )

    taskset = shutil.which("taskset")
    if not taskset:
        issues.append("taskset is unavailable; CPU pinning cannot be enforced")
    affinity = _affinity_snapshot()
    if affinity is not None and config.cpu not in affinity:
        issues.append(
            f"CPU {config.cpu} is outside process affinity {affinity}"
        )
    if taskset and not any("outside process affinity" in issue
                           for issue in issues):
        true_command = shutil.which("true")
        if not true_command:
            issues.append("true is unavailable for the taskset preflight")
        else:
            try:
                completed = subprocess.run(
                    [taskset, "--cpu-list", str(config.cpu), true_command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=5.0,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                issues.append(f"taskset preflight failed: {error}")
            else:
                if completed.returncode != 0:
                    issues.append(
                        "taskset cannot pin CPU " + str(config.cpu) + ": "
                        + completed.stdout.strip()
                    )
    return issues, taskset


def benchmark_environment_profile(role, baseline_binding_state):
    if baseline_binding_state not in BASELINE_BINDING_STATES:
        raise ValueError(
            "baseline binding state must be EAGER_FINAL, "
            "LAZY_TO_GUEST_FINAL, or LAZY_TO_NATIVE_FINAL."
        )
    if role == "candidate":
        return "candidate"
    if role == "baseline":
        if baseline_binding_state == LAZY_TO_NATIVE_FINAL:
            return "candidate"
        return "baseline"
    raise ValueError(f"Unknown benchmark role: {role}")


def benchmark_environment(config, role, fixture_dir=None):
    profile = benchmark_environment_profile(
        role, config.baseline_binding_state
    )
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("LATX_KZT"):
            environment.pop(name)
    for name in SANITIZED_RUNTIME_VARIABLES:
        environment.pop(name, None)
    environment.update(COMMON_KZT_ENVIRONMENT)
    if profile == "candidate":
        environment.update(CANDIDATE_WRITER_ENVIRONMENT)
    if fixture_dir is not None:
        environment["LD_LIBRARY_PATH"] = str(fixture_dir)
    return environment


def runtime_environment_snapshot(config, role):
    environment = benchmark_environment(config, role, config.fixture_dir)
    return {
        name: value
        for name, value in sorted(environment.items())
        if name.startswith(("LAT_", "LATX_", "QEMU_"))
        or name.startswith("LD_")
    }


def benchmark_command(config, role, mode, taskset=None):
    if taskset is None:
        taskset = mode
        mode = "steady"
    if mode not in PERFORMANCE_MODES:
        raise ValueError(f"Unknown performance mode: {mode}")
    latx = (
        config.candidate_latx if role == "candidate"
        else config.baseline_latx
    )
    command = [
        taskset,
        "--cpu-list",
        str(config.cpu),
        str(latx),
        "-L",
        str(config.guest_root),
        str(config.fixture_dir / PERFORMANCE_EXECUTABLE),
    ]
    command.append(mode)
    if mode == "steady":
        command.append(str(config.steady_calls))
    return command


def native_apply_preflight_environment(config, role):
    environment = benchmark_environment(config, role, config.fixture_dir)
    environment["LATX_KZT_LAZY_DIAGNOSTICS"] = "1"
    environment["LATX_KZT_REGISTRY_DIAGNOSTICS"] = "1"
    return environment


def _diagnostic_records(output, marker, symbol):
    records = []
    for line in output.splitlines():
        marker_at = line.find(marker)
        if marker_at < 0:
            continue
        fields = {}
        for field in line[marker_at:].split()[1:]:
            if "=" not in field:
                continue
            name, value = field.split("=", 1)
            fields[name] = value
        if fields.get("symbol") == symbol:
            records.append(fields)
    return records


def _preflight_address(record, record_name, field_name, details):
    try:
        value = int(record[field_name], 0)
    except KeyError as error:
        raise GuestCorrectnessError(
            f"Native-apply preflight is missing {record_name}.{field_name}.",
            details,
        ) from error
    except ValueError as error:
        raise GuestCorrectnessError(
            "Native-apply preflight has invalid "
            f"{record_name}.{field_name}: {record[field_name]}",
            details,
        ) from error
    if value <= 0:
        raise GuestCorrectnessError(
            f"Native-apply preflight has non-positive "
            f"{record_name}.{field_name}.",
            details,
        )
    return value


def verify_native_apply_preflight(config, taskset, role="candidate"):
    if role not in ("baseline", "candidate"):
        raise ValueError(f"Unknown benchmark role: {role}")
    if (role == "baseline" and
            config.baseline_binding_state != LAZY_TO_NATIVE_FINAL):
        raise ValueError(
            "baseline native-apply preflight requires "
            "LAZY_TO_NATIVE_FINAL."
        )
    command = benchmark_command(config, role, "first", taskset)
    execution = execute_with_rusage(
        command,
        native_apply_preflight_environment(config, role),
        config.timeout,
    )
    details = {"role": role, "command": command, **execution}
    if execution["timed_out"]:
        raise GuestCorrectnessError(
            "Native-apply preflight timed out.", details
        )
    if execution["returncode"] != 0:
        raise GuestCorrectnessError(
            "Native-apply preflight failed with "
            f"{execution['returncode']}.", details
        )

    lazy_records = _diagnostic_records(
        execution["output"], "kzt_lazy_diagnostic ", NATIVE_APPLY_SYMBOL
    )
    rela_records = _diagnostic_records(
        execution["output"], "kzt_rela_diagnostic ", NATIVE_APPLY_SYMBOL
    )
    direct_records = _diagnostic_records(
        execution["output"], "kzt_lazy_direct ", NATIVE_APPLY_SYMBOL
    )
    publication_records = _diagnostic_records(
        execution["output"], "kzt_lazy_prebind_publish ",
        NATIVE_APPLY_SYMBOL
    )
    guest_first_path = (
        len(lazy_records) == 1 and len(rela_records) == 1 and
        not direct_records
    )
    direct_path = (
        len(direct_records) == 1 and
        not lazy_records and not rela_records
    )
    prebound_path = (
        publication_records and not lazy_records and not rela_records and
        not direct_records and
        all(record.get("result") == "APPLIED" for record in publication_records)
    )
    if not guest_first_path and not direct_path and not prebound_path:
        raise GuestCorrectnessError(
            "Native-apply preflight requires exactly one native route: "
            "either one guest-first lazy/relocation pair or one evidence-backed "
            f"direct/prebound record for {NATIVE_APPLY_SYMBOL}.", details
        )
    try:
        guest = parse_guest_record(
            execution["output"], expected_steady_calls=config.steady_calls,
            expected_mode="first",
        )
    except GuestCorrectnessError as error:
        raise GuestCorrectnessError(
            f"Native-apply preflight guest slot evidence is invalid: {error}",
            details,
        ) from error
    if (guest_first_path and
            guest["before"] == guest["after_first"] ==
            guest["after_steady"]):
        raise GuestCorrectnessError(
            "Native-apply guest-first route did not update its lazy slot: "
            f"before=0x{guest['before']:x} "
            f"after_first=0x{guest['after_first']:x} "
            f"after_steady=0x{guest['after_steady']:x}.", details
        )
    if prebound_path:
        publication = publication_records[-1]
        bridge_target = _preflight_address(
            publication, "prebind", "bridge", details
        )
        if (bridge_target != guest["before"] or
                bridge_target != guest["after_first"] or
                bridge_target != guest["after_steady"]):
            raise GuestCorrectnessError(
                "Native-apply prebound slot evidence mismatch: "
                f"prebind.bridge=0x{bridge_target:x} "
                f"guest.before=0x{guest['before']:x} "
                f"guest.after_first=0x{guest['after_first']:x} "
                f"guest.after_steady=0x{guest['after_steady']:x}.",
                details,
            )
    elif direct_path:
        direct = direct_records[0]
        if direct.get("route_status") != "NATIVE_APPLIED" or \
           direct.get("writer_result") != "APPLIED":
            raise GuestCorrectnessError(
                "Native-apply direct route did not apply its guarded CAS.",
                details,
            )
        slot_before = _preflight_address(
            direct, "direct", "slot_before", details
        )
        slot_after = _preflight_address(
            direct, "direct", "slot_after", details
        )
        selected_target = _preflight_address(
            direct, "direct", "selected_target", details
        )
        if (slot_before != guest["before"] or
                slot_after != selected_target or
                slot_after != guest["after_first"] or
                slot_after != guest["after_steady"]):
            raise GuestCorrectnessError(
                "Native-apply direct slot evidence mismatch: "
                f"direct.slot_before=0x{slot_before:x} "
                f"guest.before=0x{guest['before']:x} "
                f"direct.slot_after=0x{slot_after:x} "
                f"direct.selected_target=0x{selected_target:x} "
                f"guest.after_first=0x{guest['after_first']:x} "
                f"guest.after_steady=0x{guest['after_steady']:x}.",
                details,
            )
    else:
        lazy = lazy_records[0]
        rela = rela_records[0]
        if lazy.get("completion_route_status") != "NATIVE_APPLIED" or \
           rela.get("decision") != "APPROVED" or \
           rela.get("writer_result") != "APPLIED" or \
           rela.get("legacy_fallback") != "0":
            raise GuestCorrectnessError(
                "Native-apply preflight did not observe an applied lazy route "
                "with an applied writer and no legacy fallback.", details
            )
        lazy_target = _preflight_address(
            lazy, "lazy", "selected_second_target", details
        )
        bridge_target = _preflight_address(
            rela, "rela", "bridge_target", details
        )
        guest_after_first = guest["after_first"]
        guest_after_steady = guest["after_steady"]
        if (lazy_target != bridge_target or
                lazy_target != guest_after_first or
                lazy_target != guest_after_steady):
            raise GuestCorrectnessError(
                "Native-apply preflight slot evidence mismatch: "
                f"lazy.selected_second_target=0x{lazy_target:x} "
                f"rela.bridge_target=0x{bridge_target:x} "
                f"guest.after_first=0x{guest_after_first:x} "
                f"guest.after_steady=0x{guest_after_steady:x}.",
                details,
            )
    try:
        validate_role_mode_record(
            role,
            "first",
            guest,
            baseline_binding_state=(config.baseline_binding_state
                                    if role == "baseline" else None),
        )
    except GuestCorrectnessError as error:
        raise GuestCorrectnessError(str(error), details) from error
    if prebound_path:
        return {
            "path": "prebound", "publication": publication_records,
            "guest": guest, **details
        }
    if direct_path:
        return {
            "path": "direct", "direct": direct, "guest": guest, **details
        }
    return {
        "path": "guest_first", "lazy": lazy, "rela": rela,
        "guest": guest, **details
    }


def verify_guest_preserved_preflight(config, taskset):
    if config.baseline_binding_state != LAZY_TO_GUEST_FINAL:
        raise ValueError(
            "baseline guest-preserved preflight requires "
            "LAZY_TO_GUEST_FINAL."
        )
    command = benchmark_command(config, "baseline", "first", taskset)
    execution = execute_with_rusage(
        command,
        native_apply_preflight_environment(config, "baseline"),
        config.timeout,
    )
    details = {"role": "baseline", "command": command, **execution}
    if execution["timed_out"]:
        raise GuestCorrectnessError(
            "Guest-preserved preflight timed out.", details
        )
    if execution["returncode"] != 0:
        raise GuestCorrectnessError(
            "Guest-preserved preflight failed with "
            f"{execution['returncode']}.", details
        )

    lazy_records = _diagnostic_records(
        execution["output"], "kzt_lazy_diagnostic ", NATIVE_APPLY_SYMBOL
    )
    rela_records = _diagnostic_records(
        execution["output"], "kzt_rela_diagnostic ", NATIVE_APPLY_SYMBOL
    )
    if len(lazy_records) != 1 or len(rela_records) != 1:
        raise GuestCorrectnessError(
            "Guest-preserved preflight requires exactly one lazy and "
            f"relocation record for {NATIVE_APPLY_SYMBOL}.", details
        )
    lazy = lazy_records[0]
    rela = rela_records[0]
    if lazy.get("completion_route_status") != "GUEST_PRESERVED" or \
       rela.get("decision") != "APPROVED" or \
       rela.get("writer_result") != "DISABLED" or \
       rela.get("legacy_fallback") != "0":
        raise GuestCorrectnessError(
            "Guest-preserved preflight did not observe an approved route "
            "with the writer disabled and no legacy fallback.", details
        )
    try:
        guest = parse_guest_record(
            execution["output"], expected_steady_calls=config.steady_calls,
            expected_mode="first",
        )
    except GuestCorrectnessError as error:
        raise GuestCorrectnessError(
            f"Guest-preserved preflight slot evidence is invalid: {error}",
            details,
        ) from error

    selected_target = _preflight_address(
        lazy, "lazy", "selected_second_target", details
    )
    slot_after_guest = _preflight_address(
        lazy, "lazy", "slot_after_guest", details
    )
    bridge_target = _preflight_address(
        rela, "rela", "bridge_target", details
    )
    if (selected_target != slot_after_guest or
            selected_target != guest["after_first"] or
            selected_target != guest["after_steady"] or
            bridge_target == selected_target):
        raise GuestCorrectnessError(
            "Guest-preserved preflight slot evidence mismatch: "
            f"lazy.selected_second_target=0x{selected_target:x} "
            f"lazy.slot_after_guest=0x{slot_after_guest:x} "
            f"rela.bridge_target=0x{bridge_target:x} "
            f"guest.after_first=0x{guest['after_first']:x} "
            f"guest.after_steady=0x{guest['after_steady']:x}.",
            details,
        )
    try:
        validate_role_mode_record(
            "baseline",
            "first",
            guest,
            baseline_binding_state=config.baseline_binding_state,
        )
    except GuestCorrectnessError as error:
        raise GuestCorrectnessError(str(error), details) from error
    return {"lazy": lazy, "rela": rela, "guest": guest, **details}


def _rusage_record(usage):
    if usage is None:
        return None
    return {
        "user_time_ns": int(usage.ru_utime * 1_000_000_000),
        "system_time_ns": int(usage.ru_stime * 1_000_000_000),
        "max_rss": usage.ru_maxrss,
        "minor_faults": usage.ru_minflt,
        "major_faults": usage.ru_majflt,
        "voluntary_context_switches": usage.ru_nvcsw,
        "involuntary_context_switches": usage.ru_nivcsw,
    }


def _kill_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, AttributeError):
        process.kill()


def _wait4_with_pidfd(process, timeout):
    if not hasattr(os, "pidfd_open"):
        return None
    try:
        pidfd = os.pidfd_open(process.pid)
    except OSError:
        return None
    try:
        readable, _, _ = select.select([pidfd], [], [], timeout)
        timed_out = not readable
        if timed_out:
            _kill_process_group(process)
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        return timed_out, usage
    finally:
        os.close(pidfd)


def execute_with_rusage(command, environment, timeout):
    started_ns = time.perf_counter_ns()
    timed_out = False
    usage = None
    wait_method = "subprocess.wait"
    with tempfile.TemporaryFile(mode="w+b") as output_file:
        try:
            process = subprocess.Popen(
                command,
                env=environment,
                stdout=output_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            raise PrerequisiteError(
                f"Could not start benchmark command: {error}"
            ) from error

        if hasattr(os, "wait4"):
            pidfd_result = _wait4_with_pidfd(process, timeout)
            if pidfd_result is not None:
                timed_out, usage = pidfd_result
                wait_method = "pidfd+os.wait4"
            else:
                wait_method = "os.wait4 polling fallback"
                deadline = time.monotonic() + timeout
                while True:
                    waited_pid, status, usage = os.wait4(
                        process.pid, os.WNOHANG
                    )
                    if waited_pid == process.pid:
                        process.returncode = os.waitstatus_to_exitcode(status)
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _kill_process_group(process)
                        _, status, usage = os.wait4(process.pid, 0)
                        process.returncode = os.waitstatus_to_exitcode(status)
                        break
                    time.sleep(0.001)
        else:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(process)
                process.wait()

        finished_ns = time.perf_counter_ns()
        output_file.seek(0)
        output = output_file.read().decode("utf-8", errors="replace")
    return {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "process_total_ns": finished_ns - started_ns,
        "rusage": _rusage_record(usage),
        "wait_method": wait_method,
        "output": output,
    }


def run_guest_mode(config, role, mode, taskset):
    command = benchmark_command(config, role, mode, taskset)
    execution = execute_with_rusage(
        command,
        benchmark_environment(config, role, config.fixture_dir),
        config.timeout,
    )
    details = {
        "role": role,
        "command": command,
        **execution,
    }
    if execution["timed_out"]:
        raise GuestCorrectnessError(
            f"{role} {mode} LATX timed out after {config.timeout} seconds.",
            details,
        )
    if execution["returncode"] != 0:
        raise GuestCorrectnessError(
            f"{role} {mode} LATX exited with {execution['returncode']}.",
            details,
        )
    try:
        guest = parse_guest_record(
            execution["output"], config.steady_calls, expected_mode=mode
        )
    except GuestCorrectnessError as error:
        error.details = details
        raise
    result = {
        **guest,
        "process_total_ns": execution["process_total_ns"],
        "rusage": execution["rusage"],
        "output": execution["output"],
        "command": command,
        "role": role,
    }
    if mode in ("first", "steady"):
        result["binding_state"] = validate_role_mode_record(
            role,
            mode,
            guest,
            baseline_binding_state=(config.baseline_binding_state
                                    if role == "baseline" else None),
        )
    return result


def run_guest_sample(config, role, taskset):
    startup = run_guest_mode(config, role, "startup", taskset)
    first = run_guest_mode(config, role, "first", taskset)
    steady = run_guest_mode(config, role, "steady", taskset)
    if first["binding_state"] != steady["binding_state"]:
        raise GuestCorrectnessError(
            f"{role} binding state changed between first and steady: "
            f"{first['binding_state']} -> {steady['binding_state']}.",
            {"startup": startup, "first": first, "steady": steady},
        )
    return {
        "startup_process_total_ns": startup["process_total_ns"],
        "launch_to_first_result_ns": first["process_total_ns"],
        "steady_total_ns": steady["steady_total_ns"],
        GUEST_FIRST_BINDING_METRIC: first["first_binding_ns"],
        "binding_state": first["binding_state"],
        "startup": startup,
        "first": first,
        "steady": steady,
        "role": role,
    }


def verify_role_modes_preflight(config, role, taskset):
    return {
        mode: run_guest_mode(config, role, mode, taskset)
        for mode in PERFORMANCE_MODES
    }


class RawSampleWriter:
    def __init__(self, path):
        self.path = path
        self._output = None

    def __enter__(self):
        self._output = self.path.open("w", encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._output.close()

    def write(self, record):
        self._output.write(json.dumps(record, sort_keys=True) + "\n")
        self._output.flush()


def _run_pair(config, taskset, raw_samples, phase, pair_index, order,
              roles):
    pair = {"order": list(order)}
    for position, label in enumerate(order):
        role = roles[label]
        try:
            sample = run_guest_sample(config, role, taskset)
        except GuestCorrectnessError as error:
            raw_samples.write({
                "phase": phase,
                "pair_index": pair_index,
                "position": position,
                "label": label,
                "role": role,
                "error": str(error),
                "details": error.details,
            })
            raise
        pair[label] = sample
        raw_samples.write({
            "phase": phase,
            "pair_index": pair_index,
            "position": position,
            "label": label,
            "pair_order": list(order),
            "sample": sample,
        })
    return pair


def _checkpoint_targets(initial_samples, max_samples):
    targets = [initial_samples]
    if initial_samples < MIN_FAIL_PAIRS <= max_samples:
        targets.append(MIN_FAIL_PAIRS)
    while targets[-1] < max_samples:
        current = targets[-1]
        targets.append(min(max_samples, max(current + 1, current * 2)))
    return targets


def _config_record(config):
    return {
        "baseline_latx": str(config.baseline_latx),
        "baseline_binding_state": config.baseline_binding_state,
        "comparison_metrics": list(
            comparison_metrics_for_baseline_state(
                config.baseline_binding_state
            )
        ),
        "candidate_latx": str(config.candidate_latx),
        "guest_root": str(config.guest_root),
        "fixture_dir": str(config.fixture_dir),
        "cpu": config.cpu,
        "warmup": config.warmup,
        "samples": config.samples,
        "max_samples": config.max_samples,
        "aa_samples": config.aa_samples,
        "steady_calls": config.steady_calls,
        "seed": config.seed,
        "output_dir": str(config.output_dir),
        "timeout": config.timeout,
        "isolate_harness_cpu": config.isolate_harness_cpu,
        "aa_only": config.aa_only,
    }


def _formal_stage_count(samples, max_samples):
    return sum(target >= MIN_FAIL_PAIRS
               for target in _checkpoint_targets(samples, max_samples))


def _statistics_record(samples=80, max_samples=800,
                       metrics=PRIMARY_TIME_METRICS, ab_metrics=None,
                       tail_metrics=None):
    metrics = tuple(metrics)
    ab_metrics = tuple(metrics if ab_metrics is None else ab_metrics)
    tail_metrics = tuple(ab_metrics if tail_metrics is None else tail_metrics)
    if not metrics or not ab_metrics:
        raise ValueError("statistics require at least one metric")
    if any(metric not in ab_metrics for metric in tail_metrics):
        raise ValueError("statistics tail metrics must be A/B metrics")
    aa_comparison_count = len(metrics) * 3 * 2
    ab_comparison_count = len(ab_metrics) + len(tail_metrics)
    aa_interval_alpha = AA_FAMILY_ALPHA / aa_comparison_count
    formal_stage_count = _formal_stage_count(samples, max_samples)
    analysis_look_count = max(1, formal_stage_count)
    ratio_bound_alpha = (
        _ab_ratio_bound_alpha(analysis_look_count, ab_comparison_count)
    )
    return {
        "method": (
            "paired log-ratio median exact-binomial bounds and paired-index "
            "bootstrap marginal P95-ratio bounds"
        ),
        "comparison_metrics": list(metrics),
        "ab_comparison_metrics": list(ab_metrics),
        "aa": {
            "result_states": [
                AAResult.STABLE.value,
                AAResult.DRIFT.value,
                AAResult.INCONCLUSIVE.value,
            ],
            "comparison_count": aa_comparison_count,
            "family_confidence": 1.0 - AA_FAMILY_ALPHA,
            "per_interval_alpha": aa_interval_alpha,
            "per_interval_confidence": 1.0 - aa_interval_alpha,
            "formal_min_pairs_per_role": FORMAL_AA_MIN_PAIRS,
            "screening_pairs": 50,
            "stability_log_limit": AA_STABILITY_LOG_LIMIT,
            "stability_percent_limit": 0.5,
            "temporal_design": "time-ordered early/late paired contrasts",
            "temporal_independence_assumption": (
                AA_TEMPORAL_INDEPENDENCE_ASSUMPTION
            ),
        },
        "ab": {
            "comparison_count": ab_comparison_count,
            "formal_stage_count": formal_stage_count,
            "analysis_look_count": analysis_look_count,
            "per_ratio_bound_alpha": ratio_bound_alpha,
            "per_ratio_bound_confidence": (
                1.0 - ratio_bound_alpha if ratio_bound_alpha else None
            ),
            "pass_upper_family": {
                "confidence": 1.0 - AB_FAMILY_ALPHA,
                "comparison_count": ab_comparison_count,
                "formal_stage_count": formal_stage_count,
            },
            "fail_lower_family": {
                "confidence": 1.0 - AB_FAMILY_ALPHA,
                "comparison_count": ab_comparison_count,
                "formal_stage_count": formal_stage_count,
            },
            "median_method": "paired log-ratio median",
            "p95_method": (
                "paired-index percentile bootstrap of "
                "log(P95(candidate) / P95(baseline)) with "
                "family-and-look-adjusted alpha"
            ),
            "p95_bootstrap_resamples": P95_BOOTSTRAP_RESAMPLES,
            "p95_resampling_unit": "paired sample index",
            "median_noninferiority_percent": 1.0,
            "p95_noninferiority_percent": 2.0,
            "median_noninferiority_log": MEDIAN_NONINFERIORITY_LOG,
            "p95_noninferiority_log": P95_NONINFERIORITY_LOG,
            "guest_first_binding_metric": GUEST_FIRST_BINDING_METRIC,
            "guest_first_binding_median_noninferiority_log": (
                FIRST_BINDING_NONINFERIORITY_LOG
            ),
            "min_formal_pairs": MIN_FAIL_PAIRS,
            "max_formal_pairs": max_samples,
            "decision_rule": (
                f"PASS requires all {ab_comparison_count} upper bounds within "
                "threshold; "
                "FAIL requires any lower bound beyond threshold; otherwise "
                "INCONCLUSIVE"
            ),
        },
    }


def _write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _inconclusive_details(analysis):
    crossing = []
    for metric, details in analysis["metrics"].items():
        for statistic in details["required_statistics"]:
            family = ("paired_log_ratio" if statistic == "median" else
                      "paired_index_bootstrap_p95_log_ratio")
            interval = details[family][statistic]
            threshold = details["noninferiority_log"][statistic]
            lower = interval["lower"]
            upper = interval["upper"]
            if (lower is None or upper is None or
                    lower <= threshold < upper):
                crossing.append(f"{metric}.{statistic}")
    if crossing:
        return (
            "Separate 99% PASS-upper and FAIL-lower decision-family "
            "bounds are inconclusive for: " + ", ".join(crossing)
        )
    return "Primary timing metrics do not jointly support PASS or FAIL."


def _prepare_output_directory(output_dir):
    if output_dir.exists():
        if not output_dir.is_dir():
            raise PrerequisiteError(
                f"Output path is not a directory: {output_dir}"
            )
        if any(output_dir.iterdir()):
            raise PrerequisiteError(
                f"Output directory already contains evidence: {output_dir}"
            )
    else:
        output_dir.mkdir(parents=True)


def _acquire_output_ownership(output_dir):
    owner_path = output_dir / OWNERSHIP_MARKER
    try:
        descriptor = os.open(owner_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                             0o600)
    except FileExistsError as error:
        raise PrerequisiteError(
            f"Output directory is already owned by another harness run: "
            f"{output_dir}"
        ) from error
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def _validate_sampling_configuration(config):
    if config.cpu < 0:
        raise PrerequisiteError("cpu must not be negative.")
    if config.warmup < 0:
        raise PrerequisiteError("warmup must not be negative.")
    if config.steady_calls < 100000:
        raise PrerequisiteError("steady_calls must be at least 100000.")
    if not math.isfinite(config.timeout) or config.timeout <= 0:
        raise PrerequisiteError("timeout must be finite and greater than zero.")
    if config.baseline_binding_state not in BASELINE_BINDING_STATES:
        raise PrerequisiteError(
            "baseline_binding_state must be EAGER_FINAL, "
            "LAZY_TO_GUEST_FINAL, or LAZY_TO_NATIVE_FINAL."
        )
    if config.samples not in (80, 400, 800, 1600):
        raise PrerequisiteError(
            "samples must be one of 80, 400, 800, or 1600."
        )
    if config.max_samples not in (80, 400, 800, 1600):
        raise PrerequisiteError(
            "max_samples must be one of 80, 400, 800, or 1600."
        )
    if config.samples > config.max_samples:
        raise PrerequisiteError("samples must not exceed max_samples.")
    if config.aa_samples != 50 and config.aa_samples < FORMAL_AA_MIN_PAIRS:
        raise PrerequisiteError(
            "A/A pairs must be 50 for screening or at least 200 for "
            "formal inference."
        )
    if config.aa_samples == 50 and config.max_samples != 80:
        raise PrerequisiteError(
            "50-pair A/A screening requires an 80-pair directional A/B run."
        )


def _harness_error_report(config, raw_path, started_ns, error):
    return {
        "schema_version": HARNESS_SCHEMA_VERSION,
        "artifact_type": REPORT_ARTIFACT_TYPE,
        "ownership": {
            "marker": OWNERSHIP_MARKER,
            "mode": "exclusive_create",
        },
        "started_at": _utc_now(),
        "finished_at": _utc_now(),
        "configuration": _config_record(config),
        "binaries": None,
        "fixture": None,
        "host": None,
        "environment": None,
        "statistics": _statistics_record(
            config.samples,
            config.max_samples,
            comparison_metrics_for_baseline_state(
                config.baseline_binding_state
            ),
        ),
        "measurement": None,
        "command_templates": None,
        "raw_samples": str(raw_path),
        "load": {"before": None, "after": None},
        "preflight_issues": None,
        "mode_preflight": None,
        "native_apply_preflight": None,
        "baseline_native_apply_preflight": None,
        "baseline_guest_preserved_preflight": None,
        "result": GateResult.INCONCLUSIVE.value,
        "result_scope": "harness_error",
        "reason": f"Harness error ({type(error).__name__}): {error}",
        "harness_error": {
            "type": type(error).__name__,
            "message": str(error),
        },
        "harness_elapsed_ns": time.perf_counter_ns() - started_ns,
    }


def _write_harness_error_artifacts(output_dir, report_path, report):
    metadata = dict(report)
    metadata["artifact_type"] = METADATA_ARTIFACT_TYPE
    for path, value in (
            (output_dir / "run-metadata.json", metadata),
            (report_path, report)):
        try:
            _write_json(path, value)
        except Exception:
            # The caller still receives the original setup exception.  A
            # failed artifact write is recorded only when storage permits it.
            pass


def run_performance_gate(config):
    _validate_sampling_configuration(config)
    comparison_metrics = comparison_metrics_for_baseline_state(
        config.baseline_binding_state
    )
    ab_metrics = comparison_metrics + (GUEST_FIRST_BINDING_METRIC,)
    _prepare_output_directory(config.output_dir)
    ownership_descriptor = _acquire_output_ownership(config.output_dir)
    raw_path = config.output_dir / "raw-samples.jsonl"
    report_path = config.output_dir / "report.json"
    started_ns = time.perf_counter_ns()
    report = None
    cpu_isolation = _cpu_isolation_record(
        config.isolate_harness_cpu, config.cpu
    )
    try:
        issues, taskset = prerequisite_issues(config)
        if (_formal_stage_count(config.samples, config.max_samples) and
                not config.isolate_harness_cpu):
            issues.append(
                "formal performance requires verified physical-core isolation"
            )
        if not issues:
            cpu_isolation = activate_harness_cpu_isolation(
                config.isolate_harness_cpu, config.cpu
            )
            if (config.isolate_harness_cpu and
                    not cpu_isolation["verification"]["passed"]):
                issues.append(
                    "physical-core isolation could not be verified: "
                    + (cpu_isolation["verification"]["error"] or
                       "unknown isolation error")
                )
        report = {
        "schema_version": HARNESS_SCHEMA_VERSION,
        "artifact_type": REPORT_ARTIFACT_TYPE,
        "ownership": {
            "marker": OWNERSHIP_MARKER,
            "mode": "exclusive_create",
        },
        "started_at": _utc_now(),
        "configuration": _config_record(config),
        "binaries": {
            "baseline": collect_binary_metadata(config.baseline_latx),
            "candidate": collect_binary_metadata(config.candidate_latx),
        },
        "fixture": collect_fixture_metadata(config.fixture_dir),
        "host": collect_host_metadata(config.cpu, taskset),
        "environment": {
            "baseline": runtime_environment_snapshot(config, "baseline"),
            "candidate": runtime_environment_snapshot(config, "candidate"),
            "diagnostics_enabled": False,
            "sanitized_variables": list(SANITIZED_RUNTIME_VARIABLES),
        },
        "statistics": _statistics_record(
            config.samples,
            config.max_samples,
            comparison_metrics,
            ab_metrics=ab_metrics,
            tail_metrics=comparison_metrics,
        ),
        "measurement": {
            "process_timer": "time.perf_counter_ns",
            "guest_timer": "CLOCK_MONOTONIC_RAW",
            "resource_collector": (
                "os.wait4" if hasattr(os, "wait4") else "unavailable"
            ),
            "external_time_command": None,
        },
        "command_templates": {
            role: {
                mode: benchmark_command(
                    config, role, mode, taskset or "<taskset>"
                )
                for mode in PERFORMANCE_MODES
            }
            for role in ("baseline", "candidate")
        },
        "raw_samples": str(raw_path),
        "load": {"before": host_load_snapshot()},
        "harness_cpu_isolation": cpu_isolation,
        "preflight_issues": issues,
        "mode_preflight": None,
        "native_apply_preflight": None,
        "baseline_native_apply_preflight": None,
        "baseline_guest_preserved_preflight": None,
        }
        metadata = dict(report)
        metadata["artifact_type"] = METADATA_ARTIFACT_TYPE
        _write_json(config.output_dir / "run-metadata.json", metadata)

        result = GateResult.INCONCLUSIVE
        reason = "Benchmark did not run."
        result_scope = "environment_inconclusive"
        with RawSampleWriter(raw_path) as raw_samples:
            if issues:
                reason = "Missing benchmark prerequisites: " + "; ".join(issues)
            else:
                try:
                    report["mode_preflight"] = {
                        role: verify_role_modes_preflight(config, role, taskset)
                        for role in ("baseline", "candidate")
                    }
                    report["native_apply_preflight"] = \
                        verify_native_apply_preflight(config, taskset)
                    if config.baseline_binding_state == LAZY_TO_NATIVE_FINAL:
                        report["baseline_native_apply_preflight"] = \
                            verify_native_apply_preflight(
                                config, taskset, role="baseline"
                            )
                    elif config.baseline_binding_state == LAZY_TO_GUEST_FINAL:
                        report["baseline_guest_preserved_preflight"] = \
                            verify_guest_preserved_preflight(config, taskset)
                    warmup_orders = randomized_pair_orders(
                        config.warmup,
                        _derived_seed(config.seed, "warmup-order"),
                        ("baseline", "candidate"),
                    )
                    for index, order in enumerate(warmup_orders, 1):
                        _run_pair(
                            config,
                            taskset,
                            raw_samples,
                            "warmup",
                            index,
                            order,
                            {"baseline": "baseline", "candidate": "candidate"},
                        )
                    report["warmup_pairs"] = config.warmup

                    aa_pairs = {}
                    for role in ("baseline", "candidate"):
                        orders = randomized_pair_orders(
                            config.aa_samples,
                            _derived_seed(config.seed, role, "aa-order"),
                            ("a", "b"),
                        )
                        aa_pairs[role] = [
                            _run_pair(
                                config,
                                taskset,
                                raw_samples,
                                role + "-aa",
                                index,
                                order,
                                {"a": role, "b": role},
                            )
                            for index, order in enumerate(orders, 1)
                        ]
                    aa_assessment = assess_dual_aa(
                        aa_pairs["baseline"],
                        aa_pairs["candidate"],
                        seed=_derived_seed(config.seed, "dual-aa-interval"),
                        metrics=comparison_metrics,
                    )
                    report["aa_stability"] = aa_assessment
                    screening_aa = config.aa_samples == 50
                    report["aa_mode"] = (
                        "screening" if screening_aa else "formal"
                    )
                    report["load"]["after_aa"] = host_load_snapshot()
                    load_abnormal = (
                        report["load"]["before"]["oversubscribed"]
                        or report["load"]["after_aa"]["oversubscribed"]
                    )
                    if config.aa_only:
                        result_scope = "aa_screening"
                        reason = (
                            "A/A-only "
                            + report["aa_mode"]
                            + " completed with "
                            + aa_assessment["result"]
                            + "; A/B was not run."
                        )
                    elif aa_assessment["result"] == AAResult.DRIFT.value:
                        drifting = [
                            role for role in ("baseline", "candidate")
                            if aa_assessment[role]["result"] == AAResult.DRIFT.value
                        ]
                        reason = "A/A stability check detected drift for: " + \
                            ", ".join(drifting)
                    elif (aa_assessment["result"] == AAResult.INCONCLUSIVE.value
                          and not screening_aa):
                        reason = (
                            "Formal A/A result is INCONCLUSIVE; formal A/B is "
                            "blocked."
                        )
                    elif load_abnormal:
                        reason = (
                            "Host load exceeded available CPU capacity during "
                            "the stability phase."
                        )
                    else:
                        formal_stage_count = _formal_stage_count(
                            config.samples, config.max_samples
                        )
                        analysis_look_count = max(1, formal_stage_count)
                        exploratory_ab = (
                            screening_aa or config.max_samples < MIN_FAIL_PAIRS
                        )
                        report["ab_mode"] = (
                            "exploratory" if exploratory_ab else "formal"
                        )
                        ab_orders = randomized_pair_orders(
                            config.max_samples,
                            _derived_seed(config.seed, "ab-order"),
                            ("baseline", "candidate"),
                        )
                        ab_pairs = []
                        checkpoints = []
                        for target in _checkpoint_targets(
                                config.samples, config.max_samples):
                            for index in range(len(ab_pairs), target):
                                ab_pairs.append(_run_pair(
                                    config,
                                    taskset,
                                    raw_samples,
                                    "ab",
                                    index + 1,
                                    ab_orders[index],
                                    {
                                        "baseline": "baseline",
                                        "candidate": "candidate",
                                    },
                                ))
                            checkpoint_load = host_load_snapshot()
                            if checkpoint_load["oversubscribed"]:
                                checkpoints.append({
                                    "pair_count": len(ab_pairs),
                                    "decision": GateResult.INCONCLUSIVE.value,
                                    "mode": report["ab_mode"],
                                    "analysis": None,
                                    "load": checkpoint_load,
                                })
                                result = GateResult.INCONCLUSIVE
                                reason = (
                                    "Host load exceeded available CPU capacity "
                                    "during the A/B phase."
                                )
                                break
                            analysis = analyze_ab_pairs(
                                ab_pairs,
                                seed=_derived_seed(
                                    config.seed, "ab-interval", target
                                ),
                                formal_stage_count=formal_stage_count,
                                analysis_look_count=analysis_look_count,
                                metrics=ab_metrics,
                                tail_metrics=comparison_metrics,
                            )
                            decision = classify_gate(
                                analysis,
                                pair_count=len(ab_pairs),
                                formal_aa_stable=not exploratory_ab,
                            )
                            checkpoints.append({
                                "pair_count": len(ab_pairs),
                                "decision": decision.value,
                                "mode": report["ab_mode"],
                                "analysis": analysis,
                                "load": checkpoint_load,
                            })
                            if decision == GateResult.PASS:
                                result = decision
                                result_scope = "performance_conclusion"
                                reason = (
                                    "All primary paired median plus paired-index "
                                    "bootstrap marginal P95-ratio "
                                    "PASS-decision-family 99% upper bounds satisfy "
                                    "non-inferiority."
                                )
                                break
                            if decision == GateResult.FAIL:
                                result = decision
                                result_scope = "performance_conclusion"
                                reason = (
                                    "Candidate is clearly and persistently slower "
                                    "under the FAIL-decision-family 99% lower "
                                    "bounds after at least 400 pairs for: "
                                    + ", ".join(
                                        analysis["clearly_slower_statistics"]
                                    )
                                )
                                break
                            if target == config.max_samples:
                                result = GateResult.INCONCLUSIVE
                                result_scope = "performance_conclusion"
                                if exploratory_ab:
                                    reason = (
                                        "A/B is exploratory; final result remains "
                                        "INCONCLUSIVE because "
                                        + (
                                            "A/A used 50-pair screening."
                                            if screening_aa else
                                            "fewer than 400 A/B pairs were allowed."
                                        )
                                    )
                                else:
                                    reason = _inconclusive_details(analysis)
                                break
                        report["ab_checkpoints"] = checkpoints
                except GuestCorrectnessError as error:
                    result = GateResult.FAIL
                    result_scope = "correctness_failure"
                    reason = "Correctness failure: " + str(error)
                    report["correctness_error"] = {
                        "message": str(error),
                        "details": error.details,
                    }
                except PrerequisiteError as error:
                    result = GateResult.INCONCLUSIVE
                    result_scope = "environment_inconclusive"
                    reason = "Benchmark prerequisite failed at runtime: " + str(error)
                except Exception as error:
                    result = GateResult.INCONCLUSIVE
                    result_scope = "harness_error"
                    reason = (
                        f"Harness error ({type(error).__name__}): {error}"
                    )

        report["load"]["after"] = host_load_snapshot()
        restore_harness_cpu_isolation(cpu_isolation)
        report["result"] = result.value
        report["result_scope"] = result_scope
        report["reason"] = reason
        report["finished_at"] = _utc_now()
        report["harness_elapsed_ns"] = time.perf_counter_ns() - started_ns
        _write_json(report_path, report)
        return report
    except Exception as error:
        if report is None:
            report = _harness_error_report(config, raw_path, started_ns, error)
        else:
            report["result"] = GateResult.INCONCLUSIVE.value
            report["result_scope"] = "harness_error"
            report["reason"] = (
                f"Harness error ({type(error).__name__}): {error}"
            )
            report["harness_error"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
            report["finished_at"] = _utc_now()
            report["harness_elapsed_ns"] = time.perf_counter_ns() - started_ns
        _write_harness_error_artifacts(config.output_dir, report_path, report)
        raise
    finally:
        restore_harness_cpu_isolation(cpu_isolation)
        os.close(ownership_descriptor)
