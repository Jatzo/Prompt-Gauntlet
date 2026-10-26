"""Renders a baseline report and its verdict as the plain-text table `baseline` prints."""

from arena.baselines import NOT_CONFIGURED, Verdict
from arena.schemas import BaselineReport, Metric


def _metric(metric: Metric | None) -> str:
    if metric is None:
        return "-"
    return f"{metric.value:.2f} [{metric.ci_low:.2f}, {metric.ci_high:.2f}]"


def render(report: BaselineReport, verdict: Verdict) -> str:
    lines = [
        "T1 baselines (dev, threshold from calibration)",
        f"{'arm':<20}{'kind':<12}{'TPR at target FPR':<24}{'achieved FPR':<14}"
        f"{'AUC':<22}{'valid':>7}{'invalid':>9}{'unscorable':>12}",
    ]
    for row in report.detection:
        if row.target_unreachable:
            lines.append(
                f"{row.arm:<20}{row.score_kind:<12}target FPR unreachable "
                f"({row.unscorable} unscorable)"
            )
            continue
        fpr = "-" if row.achieved_fpr is None else f"{row.achieved_fpr:.2%}"
        lines.append(
            f"{row.arm:<20}{row.score_kind:<12}{_metric(row.tpr):<24}{fpr:<14}"
            f"{_metric(row.auc):<22}{row.valid_attacks:>7}{row.invalid_attacks:>9}"
            f"{row.unscorable:>12}"
        )
    for row in report.detection:
        if row.disabled_rules:
            lines.append(
                f"{row.arm}: rules disabled after a regex timeout: {', '.join(row.disabled_rules)}"
            )
    for name in NOT_CONFIGURED:
        lines.append(f"{name:<20}not configured: no open-weights model has been chosen")

    lines += [
        "",
        "End to end (dev injection suite)",
        f"{'arm':<20}{'target':<34}{'ASR':<24}{'utility':<24}",
    ]
    for row in report.end_to_end:
        lines.append(
            f"{row.arm:<20}{row.target:<34}{_metric(row.asr):<24}{_metric(row.utility):<24}"
        )

    probe_line = "  ".join(
        f"{row.probe} {row.tpr.value:.2f}" if row.tpr else f"{row.probe} -" for row in report.probes
    )
    if not verdict.headline_measurable:
        state = (
            f"Benchmark UNMEASURABLE: the headline arm {report.headline_arm} cannot reach the "
            "target FPR on calibration, so the probes have nothing to compare against."
        )
    else:
        state = (
            f"Benchmark {'VALID' if verdict.benchmark_valid else 'INVALID'}: the best probe "
            f"({verdict.worst_probe}) reaches {verdict.worst_probe_tpr:.2f} against the "
            f"headline arm {report.headline_arm}."
        )
    lines += [
        "",
        f"Shortcut probes (TPR; limit {verdict.probe_limit:.2f}): {probe_line}",
        state,
        f"Baseline-ASR gate: {verdict.gate.status}. {verdict.gate.reason}",
    ]
    power = verdict.power
    if power.tpr_delta is not None:
        lines.append(f"Power: smallest detectable TPR difference {power.tpr_delta:.3f}")
    if power.asr_delta is not None:
        lines.append(f"Power: smallest detectable ASR difference {power.asr_delta:.3f}")
    cost = verdict.cost
    lines.append(
        f"Cost per detector experiment: about {cost.detector_items} calls, "
        f"{cost.tokens_per_detector_experiment:,} tokens ({cost.tokens_per_call:.0f} per call)"
    )
    for name, metric in sorted(report.label_error.items()):
        lines.append(f"Label error ({name}): {_metric(metric)}")
    lines.append(
        "Fingerprints: "
        + "  ".join(f"{name} {value[:12]}" for name, value in sorted(report.fingerprints.items()))
    )
    return "\n".join(lines)
