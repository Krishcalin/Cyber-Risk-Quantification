#!/usr/bin/env python3
"""
Cyber Risk Quantification (CRQ) Engine
FAIR-based Monte Carlo simulation platform for quantifying cyber risk
in financial terms.

Based on the FAIR (Factor Analysis of Information Risk) model:
  Risk = Loss Event Frequency (LEF) × Loss Magnitude (LM)

Version : 1.0.0
Author  : Phalanx Cyber / Krishnendu De
License : MIT
"""

import argparse
import io
import json
import math
import os
import random
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any

# Fix Windows console encoding for Unicode characters
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────

__version__ = "1.0.0"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[38;5;208m",  # orange
    "MEDIUM":   "\033[93m",   # yellow
    "LOW":      "\033[92m",   # green
    "INFO":     "\033[96m",   # cyan
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"

DEFAULT_SIMULATIONS = 10_000
PERCENTILES = [5, 10, 25, 50, 75, 90, 95]

# Risk score thresholds (ALE P90 as % of revenue)
RISK_THRESHOLDS = {
    "CRITICAL": 5.0,   # >=5% of revenue
    "HIGH":     2.0,   # >=2%
    "MEDIUM":   0.5,   # >=0.5%
    "LOW":      0.0,   # <0.5%
}

# Threat community base capability ranges
THREAT_COMMUNITIES = {
    "nation_state":        {"tc_base": (70, 95), "persistence": "high"},
    "organized_crime":     {"tc_base": (55, 85), "persistence": "high"},
    "hacktivist":          {"tc_base": (30, 65), "persistence": "medium"},
    "insider_malicious":   {"tc_base": (50, 80), "persistence": "medium"},
    "insider_accidental":  {"tc_base": (10, 40), "persistence": "low"},
    "script_kiddie":       {"tc_base": (10, 35), "persistence": "low"},
    "competitor":          {"tc_base": (40, 70), "persistence": "medium"},
}

# Industry loss multipliers (relative to base)
INDUSTRY_MULTIPLIERS = {
    "financial_services": 1.3,
    "healthcare":         1.25,
    "technology":         1.1,
    "retail":             1.0,
    "manufacturing":      0.95,
    "government":         1.15,
    "energy":             1.2,
    "education":          0.85,
    "default":            1.0,
}


# ──────────────────────────────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────────────────────────────

@dataclass
class PERTParams:
    """Min / Likely / Max parameters for PERT distribution sampling."""
    min: float
    likely: float
    max: float

    @classmethod
    def from_dict(cls, d: dict) -> "PERTParams":
        return cls(min=d["min"], likely=d["likely"], max=d["max"])


@dataclass
class SimulationResult:
    """Output of a single scenario's Monte Carlo simulation."""
    scenario_id: str
    scenario_name: str
    iterations: int
    ale_distribution: list = field(default_factory=list)
    lef_distribution: list = field(default_factory=list)
    lm_distribution: list = field(default_factory=list)
    percentiles: dict = field(default_factory=dict)       # {5: val, 10: val, ...}
    mean_ale: float = 0.0
    std_ale: float = 0.0
    mean_lef: float = 0.0
    mean_lm: float = 0.0
    risk_score: float = 0.0
    severity: str = "LOW"
    loss_exceedance: list = field(default_factory=list)   # [(threshold, probability), ...]
    primary_loss_breakdown: dict = field(default_factory=dict)
    secondary_loss_breakdown: dict = field(default_factory=dict)


@dataclass
class ControlAnalysis:
    """Analysis of a single control's effectiveness."""
    control_id: str
    control_name: str
    category: str
    annual_cost: float
    effectiveness_mean: float
    rs_boost: float
    risk_reduction_pct: float = 0.0
    ale_reduction: float = 0.0
    roi: float = 0.0   # (ale_reduction - annual_cost) / annual_cost


@dataclass
class Finding:
    """Individual risk finding — one per scenario."""
    scenario_id: str
    scenario_name: str
    risk_score: float
    severity: str
    ale_p50: float
    ale_p90: float
    ale_p95: float
    mean_lef: float
    mean_lm: float
    description: str
    threat_community: str
    recommendations: list = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# FAIR Engine — Core Math
# ──────────────────────────────────────────────────────────────────────

class FAIREngine:
    """Implements the FAIR model mathematics with Monte Carlo simulation."""

    def __init__(self, simulations: int = DEFAULT_SIMULATIONS,
                 seed: int | None = None, verbose: bool = False):
        self.simulations = simulations
        self.verbose = verbose
        self._rng = random.Random(seed)

    # ── PERT sampling ────────────────────────────────────────────────

    def _pert_sample(self, p: PERTParams) -> float:
        """Sample from a PERT (beta) distribution.

        PERT uses a modified beta distribution:
          alpha = 1 + 4*(likely - min) / (max - min)
          beta  = 1 + 4*(max - likely) / (max - min)
        """
        if p.max <= p.min:
            return p.likely
        range_val = p.max - p.min
        if range_val == 0:
            return p.min
        alpha = 1.0 + 4.0 * (p.likely - p.min) / range_val
        beta  = 1.0 + 4.0 * (p.max - p.likely) / range_val
        sample = self._rng.betavariate(alpha, beta)
        return p.min + range_val * sample

    # ── FAIR formulas ────────────────────────────────────────────────

    @staticmethod
    def _calc_vulnerability(tc: float, rs: float) -> float:
        """Vulnerability = clamp((TC - RS + 50) / 100, 0, 1).

        When TC == RS, vulnerability is 50%.
        Higher TC or lower RS increases vulnerability.
        """
        v = (tc - rs + 50.0) / 100.0
        return max(0.0, min(1.0, v))

    @staticmethod
    def _calc_tef(contact_freq: float, prob_action: float) -> float:
        """Threat Event Frequency = Contact Frequency × Probability of Action."""
        return contact_freq * prob_action

    @staticmethod
    def _calc_lef(tef: float, vulnerability: float) -> float:
        """Loss Event Frequency = TEF × Vulnerability."""
        return tef * vulnerability

    def _calc_loss_magnitude(self, primary: dict, secondary: dict,
                             industry_mult: float) -> tuple:
        """Sample total loss magnitude from primary + secondary components.

        Returns (total_lm, primary_breakdown, secondary_breakdown).
        """
        pri_components = {}
        for key in ("productivity", "response", "replacement"):
            if key in primary:
                pri_components[key] = self._pert_sample(PERTParams.from_dict(primary[key]))
            else:
                pri_components[key] = 0.0

        sec_components = {}
        for key in ("fines", "reputation", "competitive_advantage"):
            if key in secondary:
                sec_components[key] = self._pert_sample(PERTParams.from_dict(secondary[key]))
            else:
                sec_components[key] = 0.0

        primary_total = sum(pri_components.values())
        secondary_total = sum(sec_components.values())
        total = (primary_total + secondary_total) * industry_mult

        return total, pri_components, sec_components

    # ── Monte Carlo simulation ───────────────────────────────────────

    def simulate_scenario(self, scenario: dict, controls: list,
                          org: dict) -> SimulationResult:
        """Run Monte Carlo simulation for a single risk scenario.

        Args:
            scenario: Scenario dict from JSON input.
            controls: List of control dicts that apply to this scenario.
            org: Organization dict with revenue, industry, etc.

        Returns:
            SimulationResult with full distribution and percentiles.
        """
        sid = scenario["id"]
        sname = scenario["name"]
        industry = org.get("industry", "default")
        industry_mult = INDUSTRY_MULTIPLIERS.get(industry,
                            INDUSTRY_MULTIPLIERS["default"])
        revenue = org.get("revenue", 1_000_000_000)

        # Parse PERT params
        cf_params = PERTParams.from_dict(scenario["contact_frequency"])
        pa_params = PERTParams.from_dict(scenario["probability_of_action"])
        tc_params = PERTParams.from_dict(scenario["threat_capability"])
        rs_params = PERTParams.from_dict(scenario["resistance_strength"])

        # Calculate control boost to Resistance Strength
        rs_boost = self._calc_control_boost(controls)

        ale_dist = []
        lef_dist = []
        lm_dist = []
        pri_accum = {"productivity": 0.0, "response": 0.0, "replacement": 0.0}
        sec_accum = {"fines": 0.0, "reputation": 0.0, "competitive_advantage": 0.0}
        loss_events_count = 0

        for _ in range(self.simulations):
            # Sample FAIR parameters
            cf  = self._pert_sample(cf_params)
            pa  = self._pert_sample(pa_params)
            tc  = self._pert_sample(tc_params)
            rs  = self._pert_sample(rs_params)

            # Apply control boost (diminishing returns)
            rs_effective = min(rs + rs_boost, 99.0)

            # FAIR calculations
            tef = self._calc_tef(cf, pa)
            vuln = self._calc_vulnerability(tc, rs_effective)
            lef = self._calc_lef(tef, vuln)

            # Sample loss magnitude
            lm, pri_bd, sec_bd = self._calc_loss_magnitude(
                scenario.get("primary_loss", {}),
                scenario.get("secondary_loss", {}),
                industry_mult
            )

            # ALE = LEF × LM (annualized)
            ale = lef * lm

            ale_dist.append(ale)
            lef_dist.append(lef)
            lm_dist.append(lm)

            if lef > 0:
                loss_events_count += 1
                for k in pri_bd:
                    pri_accum[k] += pri_bd[k]
                for k in sec_bd:
                    sec_accum[k] += sec_bd[k]

        # Calculate percentiles
        ale_sorted = sorted(ale_dist)
        percentiles = {}
        for p in PERCENTILES:
            idx = int(len(ale_sorted) * p / 100)
            idx = min(idx, len(ale_sorted) - 1)
            percentiles[p] = ale_sorted[idx]

        # Mean and std
        mean_ale = sum(ale_dist) / len(ale_dist)
        mean_lef = sum(lef_dist) / len(lef_dist)
        mean_lm  = sum(lm_dist) / len(lm_dist)
        variance = sum((x - mean_ale) ** 2 for x in ale_dist) / len(ale_dist)
        std_ale  = math.sqrt(variance)

        # Loss exceedance curve
        loss_exceedance = self._calc_loss_exceedance(ale_sorted)

        # Risk score (log-scale, 0-100)
        risk_score = self._calc_risk_score(percentiles.get(90, 0), revenue)

        # Severity
        severity = self._calc_severity(percentiles.get(90, 0), revenue)

        # Normalize loss breakdowns
        n_events = max(loss_events_count, 1)
        pri_avg = {k: v / n_events for k, v in pri_accum.items()}
        sec_avg = {k: v / n_events for k, v in sec_accum.items()}

        return SimulationResult(
            scenario_id=sid,
            scenario_name=sname,
            iterations=self.simulations,
            ale_distribution=ale_dist,
            lef_distribution=lef_dist,
            lm_distribution=lm_dist,
            percentiles=percentiles,
            mean_ale=mean_ale,
            std_ale=std_ale,
            mean_lef=mean_lef,
            mean_lm=mean_lm,
            risk_score=risk_score,
            severity=severity,
            loss_exceedance=loss_exceedance,
            primary_loss_breakdown=pri_avg,
            secondary_loss_breakdown=sec_avg,
        )

    # ── Control effectiveness ────────────────────────────────────────

    def _calc_control_boost(self, controls: list) -> float:
        """Calculate combined RS boost from controls (diminishing returns).

        Each control contributes: effectiveness * (1 - accumulated/100).
        This models overlapping/diminishing returns.
        """
        if not controls:
            return 0.0

        accumulated = 0.0
        for ctrl in controls:
            eff_params = PERTParams.from_dict(ctrl["effectiveness"])
            eff = self._pert_sample(eff_params) / 100.0
            # Diminishing returns: each control's marginal contribution decreases
            boost = eff * (1.0 - accumulated / 100.0) * 15.0  # max ~15 RS points per control
            accumulated += boost

        return min(accumulated, 40.0)  # cap total boost at 40 RS points

    # ── Loss exceedance curve ────────────────────────────────────────

    @staticmethod
    def _calc_loss_exceedance(ale_sorted: list) -> list:
        """Calculate loss exceedance curve data points.

        Returns list of (threshold, exceedance_probability) tuples.
        """
        n = len(ale_sorted)
        if n == 0:
            return []

        max_ale = ale_sorted[-1]
        if max_ale == 0:
            return [(0, 1.0)]

        # Generate 20 evenly-spaced thresholds
        points = []
        for i in range(21):
            threshold = max_ale * i / 20
            # Count how many simulations exceed this threshold
            exceed_count = sum(1 for x in ale_sorted if x > threshold)
            prob = exceed_count / n
            points.append((round(threshold, 2), round(prob, 4)))

        return points

    # ── Risk scoring ─────────────────────────────────────────────────

    @staticmethod
    def _calc_risk_score(ale_p90: float, revenue: float) -> float:
        """Calculate risk score (0-100) using log-scale normalization.

        Based on ALE P90 as a fraction of organization revenue.
        """
        if revenue <= 0 or ale_p90 <= 0:
            return 0.0

        ratio = ale_p90 / revenue
        # Log scale: 0.0001% → ~0, 10% → ~100
        if ratio <= 0:
            return 0.0
        score = (math.log10(ratio * 10000) / math.log10(10000)) * 100
        return max(0.0, min(100.0, round(score, 1)))

    @staticmethod
    def _calc_severity(ale_p90: float, revenue: float) -> str:
        """Determine severity based on ALE P90 as % of revenue."""
        if revenue <= 0:
            return "LOW"
        pct = (ale_p90 / revenue) * 100
        if pct >= RISK_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif pct >= RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        elif pct >= RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        else:
            return "LOW"


# ──────────────────────────────────────────────────────────────────────
# CRQ Engine — Orchestration & Reporting
# ──────────────────────────────────────────────────────────────────────

class CRQEngine:
    """Orchestrates FAIR simulations and generates reports."""

    def __init__(self, simulations: int = DEFAULT_SIMULATIONS,
                 seed: int | None = None, verbose: bool = False):
        self.fair = FAIREngine(simulations=simulations, seed=seed,
                               verbose=verbose)
        self.simulations = simulations
        self.verbose = verbose
        self.data: dict = {}
        self.results: list[SimulationResult] = []
        self.findings: list[Finding] = []
        self.control_analyses: list[ControlAnalysis] = []

    # ── Load ─────────────────────────────────────────────────────────

    def load_scenarios(self, path: str) -> None:
        """Load scenarios from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            self.data = json.load(f)

        # Validate required keys
        for key in ("organization", "scenarios"):
            if key not in self.data:
                raise ValueError(f"Missing required key '{key}' in JSON input")

        org = self.data["organization"]
        for key in ("name", "revenue"):
            if key not in org:
                raise ValueError(f"Missing required key 'organization.{key}'")

        scenarios = self.data["scenarios"]
        if not scenarios:
            raise ValueError("No scenarios defined in JSON input")

        self._vprint(f"Loaded {len(scenarios)} scenarios for "
                     f"{org['name']} (revenue: ${org['revenue']:,.0f})")

    # ── Run simulations ──────────────────────────────────────────────

    def run_all(self) -> list[SimulationResult]:
        """Run Monte Carlo simulation for all scenarios."""
        org = self.data["organization"]
        scenarios = self.data["scenarios"]
        controls = self.data.get("controls", [])
        assets = self.data.get("assets", [])

        self.results = []
        self.findings = []

        self._vprint(f"\nRunning {self.simulations:,} Monte Carlo iterations "
                     f"per scenario...\n")

        for scenario in scenarios:
            sid = scenario["id"]
            # Resolve controls for this scenario
            scenario_controls = [
                c for c in controls
                if sid in c.get("applies_to", [])
            ]

            t0 = time.time()
            result = self.fair.simulate_scenario(scenario, scenario_controls, org)
            elapsed = time.time() - t0

            self.results.append(result)

            # Create finding
            finding = Finding(
                scenario_id=result.scenario_id,
                scenario_name=result.scenario_name,
                risk_score=result.risk_score,
                severity=result.severity,
                ale_p50=result.percentiles.get(50, 0),
                ale_p90=result.percentiles.get(90, 0),
                ale_p95=result.percentiles.get(95, 0),
                mean_lef=result.mean_lef,
                mean_lm=result.mean_lm,
                description=scenario.get("description", ""),
                threat_community=scenario.get("threat_community", "unknown"),
            )
            self.findings.append(finding)

            self._vprint(f"  [{result.severity:8s}] {result.scenario_name:<40s} "
                         f"ALE P90: ${result.percentiles.get(90, 0):>14,.0f}  "
                         f"Score: {result.risk_score:5.1f}  ({elapsed:.2f}s)")

        # Run control analysis
        self._analyze_controls()

        # Sort findings by risk score descending
        self.findings.sort(key=lambda f: f.risk_score, reverse=True)
        self.results.sort(key=lambda r: r.risk_score, reverse=True)

        return self.results

    # ── Control analysis ─────────────────────────────────────────────

    def _analyze_controls(self) -> None:
        """Analyze each control's cost-effectiveness."""
        controls = self.data.get("controls", [])
        org = self.data["organization"]
        revenue = org.get("revenue", 1_000_000_000)

        self.control_analyses = []

        for ctrl in controls:
            eff = ctrl["effectiveness"]
            eff_mean = (eff["min"] + 4 * eff["likely"] + eff["max"]) / 6
            rs_boost = eff_mean / 100.0 * 15.0  # approximate single-control boost

            # Estimate ALE reduction across applicable scenarios
            applicable = [r for r in self.results
                          if r.scenario_id in ctrl.get("applies_to", [])]
            total_ale = sum(r.mean_ale for r in applicable)
            # Approximate: each RS point reduces vulnerability by ~1%
            reduction_pct = min(rs_boost * 1.0, 30.0)  # cap at 30% reduction
            ale_reduction = total_ale * (reduction_pct / 100.0)
            cost = ctrl.get("annual_cost", 0)
            roi = ((ale_reduction - cost) / cost) if cost > 0 else 0.0

            self.control_analyses.append(ControlAnalysis(
                control_id=ctrl["id"],
                control_name=ctrl["name"],
                category=ctrl.get("category", "unknown"),
                annual_cost=cost,
                effectiveness_mean=round(eff_mean, 1),
                rs_boost=round(rs_boost, 2),
                risk_reduction_pct=round(reduction_pct, 1),
                ale_reduction=round(ale_reduction, 2),
                roi=round(roi, 2),
            ))

        # Sort by ROI descending
        self.control_analyses.sort(key=lambda c: c.roi, reverse=True)

    # ── Filtering ────────────────────────────────────────────────────

    def filter_severity(self, min_severity: str) -> None:
        """Filter findings and results to only include >= min_severity."""
        threshold = SEVERITY_ORDER.get(min_severity.upper(), 4)
        self.findings = [f for f in self.findings
                         if SEVERITY_ORDER.get(f.severity, 4) <= threshold]
        filtered_ids = {f.scenario_id for f in self.findings}
        self.results = [r for r in self.results
                        if r.scenario_id in filtered_ids]

    # ── Console report ───────────────────────────────────────────────

    def print_report(self) -> None:
        """Print colored console report."""
        org = self.data["organization"]
        revenue = org.get("revenue", 0)

        # Header
        print(f"\n{BOLD}{'═' * 78}{RESET}")
        print(f"{BOLD}  CYBER RISK QUANTIFICATION REPORT{RESET}")
        print(f"{BOLD}  {org['name']}{RESET}")
        print(f"{DIM}  FAIR-Based Monte Carlo Analysis • {self.simulations:,} iterations{RESET}")
        print(f"{BOLD}{'═' * 78}{RESET}\n")

        # Executive summary
        self._print_executive_summary(revenue)

        # Per-scenario details
        print(f"\n{BOLD}{'─' * 78}{RESET}")
        print(f"{BOLD}  SCENARIO ANALYSIS{RESET}")
        print(f"{BOLD}{'─' * 78}{RESET}\n")

        for result in self.results:
            self._print_scenario(result, revenue)

        # Control effectiveness
        if self.control_analyses:
            self._print_control_analysis()

        # Footer
        print(f"\n{BOLD}{'═' * 78}{RESET}")
        print(f"{DIM}  CRQ Engine v{__version__} • FAIR Model • "
              f"Phalanx Cyber{RESET}")
        print(f"{BOLD}{'═' * 78}{RESET}\n")

    def _print_executive_summary(self, revenue: float) -> None:
        """Print executive summary section."""
        if not self.results:
            print("  No scenarios analyzed.\n")
            return

        total_ale_p50 = sum(r.percentiles.get(50, 0) for r in self.results)
        total_ale_p90 = sum(r.percentiles.get(90, 0) for r in self.results)
        total_ale_p95 = sum(r.percentiles.get(95, 0) for r in self.results)
        max_risk = max(r.risk_score for r in self.results)
        crit_count = sum(1 for r in self.results if r.severity == "CRITICAL")
        high_count = sum(1 for r in self.results if r.severity == "HIGH")
        med_count  = sum(1 for r in self.results if r.severity == "MEDIUM")
        low_count  = sum(1 for r in self.results if r.severity == "LOW")

        print(f"  {BOLD}EXECUTIVE SUMMARY{RESET}\n")
        print(f"  Total Annualized Loss Exposure:")
        print(f"    Expected (P50):   ${total_ale_p50:>16,.0f}")
        print(f"    Likely Max (P90): ${total_ale_p90:>16,.0f}")
        print(f"    Worst Case (P95): ${total_ale_p95:>16,.0f}")
        if revenue > 0:
            print(f"    % of Revenue:     {total_ale_p90/revenue*100:>15.2f}%")
        print()

        # Risk score gauge (text-based)
        gauge = self._text_gauge(max_risk)
        print(f"  Highest Risk Score: {gauge} {max_risk:.1f}/100")
        print()

        # Severity distribution
        print(f"  Severity Distribution:")
        if crit_count:
            print(f"    {SEVERITY_COLOR['CRITICAL']}■{RESET} CRITICAL : {crit_count}")
        if high_count:
            print(f"    {SEVERITY_COLOR['HIGH']}■{RESET} HIGH     : {high_count}")
        if med_count:
            print(f"    {SEVERITY_COLOR['MEDIUM']}■{RESET} MEDIUM   : {med_count}")
        if low_count:
            print(f"    {SEVERITY_COLOR['LOW']}■{RESET} LOW      : {low_count}")
        print(f"    {'─' * 20}")
        print(f"    Total    : {len(self.results)}")

    @staticmethod
    def _text_gauge(score: float) -> str:
        """Create a text-based risk gauge."""
        filled = int(score / 5)
        empty = 20 - filled
        if score >= 75:
            color = SEVERITY_COLOR["CRITICAL"]
        elif score >= 50:
            color = SEVERITY_COLOR["HIGH"]
        elif score >= 25:
            color = SEVERITY_COLOR["MEDIUM"]
        else:
            color = SEVERITY_COLOR["LOW"]
        return f"[{color}{'█' * filled}{DIM}{'░' * empty}{RESET}]"

    def _print_scenario(self, result: SimulationResult, revenue: float) -> None:
        """Print details for a single scenario."""
        color = SEVERITY_COLOR.get(result.severity, RESET)
        print(f"  {color}● {result.severity:8s}{RESET}  "
              f"{BOLD}{result.scenario_name}{RESET}")
        print(f"  {'─' * 60}")
        print(f"    Risk Score:        {self._text_gauge(result.risk_score)} "
              f"{result.risk_score:.1f}")
        print(f"    Mean LEF:          {result.mean_lef:.2f} events/year")
        print(f"    Mean Loss/Event:   ${result.mean_lm:>14,.0f}")
        print()
        print(f"    ALE Distribution:")
        print(f"      P5  (best):      ${result.percentiles.get(5, 0):>14,.0f}")
        print(f"      P25 (optimistic):${result.percentiles.get(25, 0):>14,.0f}")
        print(f"      P50 (expected):  ${result.percentiles.get(50, 0):>14,.0f}")
        print(f"      P75 (pessimistic):${result.percentiles.get(75, 0):>13,.0f}")
        print(f"      P90 (likely max):${result.percentiles.get(90, 0):>14,.0f}")
        print(f"      P95 (worst):     ${result.percentiles.get(95, 0):>14,.0f}")
        if revenue > 0:
            print(f"      % Revenue (P90): "
                  f"{result.percentiles.get(90, 0)/revenue*100:>13.3f}%")

        # Loss breakdown
        pri = result.primary_loss_breakdown
        sec = result.secondary_loss_breakdown
        if any(pri.values()) or any(sec.values()):
            print(f"\n    Average Loss Breakdown (per event):")
            if pri.get("productivity", 0) > 0:
                print(f"      Productivity:    ${pri['productivity']:>14,.0f}")
            if pri.get("response", 0) > 0:
                print(f"      Response:        ${pri['response']:>14,.0f}")
            if pri.get("replacement", 0) > 0:
                print(f"      Replacement:     ${pri['replacement']:>14,.0f}")
            if sec.get("fines", 0) > 0:
                print(f"      Fines/Penalties: ${sec['fines']:>14,.0f}")
            if sec.get("reputation", 0) > 0:
                print(f"      Reputation:      ${sec['reputation']:>14,.0f}")
            if sec.get("competitive_advantage", 0) > 0:
                print(f"      Competitive:     ${sec['competitive_advantage']:>14,.0f}")

        print()

    def _print_control_analysis(self) -> None:
        """Print control effectiveness analysis."""
        print(f"\n{BOLD}{'─' * 78}{RESET}")
        print(f"{BOLD}  CONTROL EFFECTIVENESS ANALYSIS{RESET}")
        print(f"{BOLD}{'─' * 78}{RESET}\n")

        print(f"  {'Control':<35s} {'Type':<12s} {'Eff%':>5s} "
              f"{'ALE Reduction':>15s} {'Cost':>12s} {'ROI':>8s}")
        print(f"  {'─' * 35} {'─' * 12} {'─' * 5} {'─' * 15} {'─' * 12} {'─' * 8}")

        for ca in self.control_analyses:
            roi_color = SEVERITY_COLOR["LOW"] if ca.roi > 0 else SEVERITY_COLOR["CRITICAL"]
            print(f"  {ca.control_name:<35s} {ca.category:<12s} "
                  f"{ca.effectiveness_mean:>4.0f}% "
                  f"${ca.ale_reduction:>14,.0f} "
                  f"${ca.annual_cost:>11,.0f} "
                  f"{roi_color}{ca.roi:>7.1f}x{RESET}")

    def summary(self) -> dict:
        """Return summary statistics."""
        if not self.results:
            return {"total_scenarios": 0}

        org = self.data["organization"]
        revenue = org.get("revenue", 0)

        return {
            "organization": org["name"],
            "revenue": revenue,
            "total_scenarios": len(self.results),
            "total_ale_p50": sum(r.percentiles.get(50, 0) for r in self.results),
            "total_ale_p90": sum(r.percentiles.get(90, 0) for r in self.results),
            "total_ale_p95": sum(r.percentiles.get(95, 0) for r in self.results),
            "highest_risk_score": max(r.risk_score for r in self.results),
            "critical_count": sum(1 for r in self.results if r.severity == "CRITICAL"),
            "high_count": sum(1 for r in self.results if r.severity == "HIGH"),
            "medium_count": sum(1 for r in self.results if r.severity == "MEDIUM"),
            "low_count": sum(1 for r in self.results if r.severity == "LOW"),
        }

    # ── JSON report ──────────────────────────────────────────────────

    def save_json(self, path: str) -> None:
        """Save full structured JSON report."""
        org = self.data["organization"]
        revenue = org.get("revenue", 0)

        report = {
            "meta": {
                "engine": "CRQ Engine",
                "version": __version__,
                "model": "FAIR (Factor Analysis of Information Risk)",
                "simulations": self.simulations,
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "organization": org,
            "summary": self.summary(),
            "scenarios": [],
            "controls": [],
        }

        for result in self.results:
            scenario_data = {
                "id": result.scenario_id,
                "name": result.scenario_name,
                "severity": result.severity,
                "risk_score": result.risk_score,
                "iterations": result.iterations,
                "ale": {
                    "mean": round(result.mean_ale, 2),
                    "std": round(result.std_ale, 2),
                    "percentiles": {
                        str(k): round(v, 2)
                        for k, v in result.percentiles.items()
                    },
                },
                "lef": {
                    "mean": round(result.mean_lef, 4),
                },
                "loss_magnitude": {
                    "mean": round(result.mean_lm, 2),
                    "primary_breakdown": {
                        k: round(v, 2)
                        for k, v in result.primary_loss_breakdown.items()
                    },
                    "secondary_breakdown": {
                        k: round(v, 2)
                        for k, v in result.secondary_loss_breakdown.items()
                    },
                },
                "loss_exceedance_curve": [
                    {"threshold": t, "probability": p}
                    for t, p in result.loss_exceedance
                ],
            }
            report["scenarios"].append(scenario_data)

        for ca in self.control_analyses:
            report["controls"].append(asdict(ca))

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n  {BOLD}JSON report saved:{RESET} {path}")

    # ── HTML report ──────────────────────────────────────────────────

    def save_html(self, path: str) -> None:
        """Save HTML dashboard report with inline SVG charts."""
        org = self.data["organization"]
        revenue = org.get("revenue", 0)
        summ = self.summary()

        scenarios_html = ""
        for result in self.results:
            scenarios_html += self._html_scenario_card(result, revenue)

        controls_html = self._html_controls_table()
        gauge_svg = self._svg_risk_gauge(summ.get("highest_risk_score", 0))
        heatmap_svg = self._svg_heatmap()
        lec_svg = self._svg_loss_exceedance()
        ctrl_bars_svg = self._svg_control_bars()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CRQ Dashboard — {self._esc(org['name'])}</title>
<style>
:root {{
  --bg-primary: #0a0e1a;
  --bg-card: rgba(15, 23, 42, 0.8);
  --bg-card-hover: rgba(20, 30, 55, 0.9);
  --border: rgba(99, 102, 241, 0.2);
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --accent: #6366f1;
  --accent-glow: rgba(99, 102, 241, 0.3);
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #22c55e;
  --info: #06b6d4;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
}}
.container {{ max-width: 1280px; margin: 0 auto; padding: 2rem; }}
h1 {{ font-size: 1.8rem; font-weight: 700; margin-bottom: 0.25rem; }}
h2 {{
  font-size: 1.3rem; font-weight: 600; margin: 2rem 0 1rem;
  padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
}}
h3 {{ font-size: 1.1rem; font-weight: 600; margin-bottom: 0.5rem; }}
.subtitle {{ color: var(--text-secondary); font-size: 0.9rem; }}
.header {{
  display: flex; justify-content: space-between; align-items: center;
  padding: 1.5rem 0; border-bottom: 1px solid var(--border);
  margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;
}}
.badge {{
  display: inline-block; padding: 0.2rem 0.7rem; border-radius: 999px;
  font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
}}
.badge-critical {{ background: rgba(239,68,68,0.15); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }}
.badge-high {{ background: rgba(249,115,22,0.15); color: var(--high); border: 1px solid rgba(249,115,22,0.3); }}
.badge-medium {{ background: rgba(234,179,8,0.15); color: var(--medium); border: 1px solid rgba(234,179,8,0.3); }}
.badge-low {{ background: rgba(34,197,94,0.15); color: var(--low); border: 1px solid rgba(34,197,94,0.3); }}

/* Summary cards */
.summary-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem; margin-bottom: 2rem;
}}
.summary-card {{
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 12px; padding: 1.25rem; text-align: center;
}}
.summary-card .label {{ color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
.summary-card .value {{ font-size: 1.6rem; font-weight: 700; margin-top: 0.25rem; }}
.summary-card .sub {{ color: var(--text-secondary); font-size: 0.8rem; margin-top: 0.25rem; }}

/* Charts grid */
.charts-grid {{
  display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem;
}}
.chart-card {{
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 12px; padding: 1.5rem;
}}
.chart-card h3 {{ margin-bottom: 1rem; }}
.chart-card svg {{ width: 100%; height: auto; }}

/* Scenario cards */
.scenario-card {{
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem;
  transition: background 0.2s;
}}
.scenario-card:hover {{ background: var(--bg-card-hover); }}
.scenario-header {{
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem;
}}
.scenario-stats {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 0.75rem;
}}
.stat {{ padding: 0.75rem; background: rgba(0,0,0,0.2); border-radius: 8px; }}
.stat .label {{ font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; }}
.stat .value {{ font-size: 1.1rem; font-weight: 600; margin-top: 0.15rem; }}

/* Loss breakdown */
.breakdown {{ margin-top: 1rem; }}
.breakdown-bar {{
  display: flex; align-items: center; margin: 0.3rem 0; font-size: 0.85rem;
}}
.breakdown-bar .bar-label {{ width: 130px; color: var(--text-secondary); }}
.breakdown-bar .bar-track {{
  flex: 1; height: 8px; background: rgba(255,255,255,0.05); border-radius: 4px;
  overflow: hidden; margin: 0 0.75rem;
}}
.breakdown-bar .bar-fill {{ height: 100%; border-radius: 4px; }}
.breakdown-bar .bar-value {{ width: 100px; text-align: right; font-size: 0.8rem; }}

/* Controls table */
.ctrl-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
.ctrl-table th {{
  text-align: left; padding: 0.75rem; border-bottom: 2px solid var(--border);
  color: var(--text-secondary); font-weight: 600; text-transform: uppercase;
  font-size: 0.75rem; letter-spacing: 0.05em;
}}
.ctrl-table td {{ padding: 0.75rem; border-bottom: 1px solid rgba(99,102,241,0.1); }}
.roi-positive {{ color: var(--low); }}
.roi-negative {{ color: var(--critical); }}

/* Footer */
.footer {{
  margin-top: 3rem; padding: 1.5rem 0; border-top: 1px solid var(--border);
  text-align: center; color: var(--text-secondary); font-size: 0.8rem;
}}

/* Risk gauge center text */
.gauge-text {{ font-family: 'Segoe UI', system-ui, sans-serif; }}

@media (max-width: 768px) {{
  .charts-grid {{ grid-template-columns: 1fr; }}
  .scenario-stats {{ grid-template-columns: 1fr 1fr; }}
  .summary-grid {{ grid-template-columns: 1fr 1fr; }}
}}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <div>
    <h1>Cyber Risk Quantification Dashboard</h1>
    <p class="subtitle">{self._esc(org['name'])} &bull; FAIR Model &bull;
       {self.simulations:,} Monte Carlo Iterations</p>
  </div>
  <div>
    <span class="badge badge-{summ.get('highest_risk_score', 0) >= 75 and 'critical'
        or summ.get('highest_risk_score', 0) >= 50 and 'high'
        or summ.get('highest_risk_score', 0) >= 25 and 'medium'
        or 'low'}">
      Peak Risk: {summ.get('highest_risk_score', 0):.1f}/100
    </span>
  </div>
</div>

<!-- Executive Summary -->
<div class="summary-grid">
  <div class="summary-card">
    <div class="label">Total ALE (P50)</div>
    <div class="value">${summ.get('total_ale_p50', 0):,.0f}</div>
    <div class="sub">Expected annual loss</div>
  </div>
  <div class="summary-card">
    <div class="label">Total ALE (P90)</div>
    <div class="value" style="color: var(--high)">${summ.get('total_ale_p90', 0):,.0f}</div>
    <div class="sub">{summ.get('total_ale_p90', 0)/revenue*100:.2f}% of revenue</div>
  </div>
  <div class="summary-card">
    <div class="label">Total ALE (P95)</div>
    <div class="value" style="color: var(--critical)">${summ.get('total_ale_p95', 0):,.0f}</div>
    <div class="sub">Worst-case exposure</div>
  </div>
  <div class="summary-card">
    <div class="label">Scenarios</div>
    <div class="value">{len(self.results)}</div>
    <div class="sub">{summ.get('critical_count', 0)} Critical &bull; {summ.get('high_count', 0)} High</div>
  </div>
</div>

<!-- Charts -->
<div class="charts-grid">
  <div class="chart-card">
    <h3>Risk Score Gauge</h3>
    {gauge_svg}
  </div>
  <div class="chart-card">
    <h3>Risk Heatmap (Likelihood × Impact)</h3>
    {heatmap_svg}
  </div>
  <div class="chart-card">
    <h3>Loss Exceedance Curve (Aggregate)</h3>
    {lec_svg}
  </div>
  <div class="chart-card">
    <h3>Control Effectiveness</h3>
    {ctrl_bars_svg}
  </div>
</div>

<!-- Scenario Details -->
<h2>Scenario Analysis</h2>
{scenarios_html}

<!-- Control Analysis -->
<h2>Control Effectiveness</h2>
{controls_html}

<div class="footer">
  CRQ Engine v{__version__} &bull; FAIR Model &bull; Phalanx Cyber &bull;
  Generated {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}
</div>

</div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"\n  {BOLD}HTML dashboard saved:{RESET} {path}")

    # ── HTML helpers ─────────────────────────────────────────────────

    @staticmethod
    def _esc(s: str) -> str:
        """Escape HTML entities."""
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    def _html_scenario_card(self, result: SimulationResult,
                            revenue: float) -> str:
        """Generate HTML card for a single scenario."""
        sev_class = result.severity.lower()
        p90_pct = (result.percentiles.get(90, 0) / revenue * 100
                   if revenue > 0 else 0)

        # Loss breakdown bars
        pri = result.primary_loss_breakdown
        sec = result.secondary_loss_breakdown
        all_losses = {**pri, **sec}
        max_loss = max(all_losses.values()) if all_losses and max(all_losses.values()) > 0 else 1

        breakdown_html = ""
        loss_colors = {
            "productivity": "#6366f1", "response": "#8b5cf6",
            "replacement": "#a78bfa", "fines": "#ef4444",
            "reputation": "#f97316", "competitive_advantage": "#eab308",
        }
        for key, val in all_losses.items():
            if val > 0:
                pct = val / max_loss * 100
                color = loss_colors.get(key, "#6366f1")
                label = key.replace("_", " ").title()
                breakdown_html += f"""
        <div class="breakdown-bar">
          <span class="bar-label">{label}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{pct:.0f}%;background:{color}"></div></div>
          <span class="bar-value">${val:,.0f}</span>
        </div>"""

        return f"""
<div class="scenario-card">
  <div class="scenario-header">
    <h3>{self._esc(result.scenario_name)}</h3>
    <span class="badge badge-{sev_class}">{result.severity} — Score {result.risk_score:.1f}</span>
  </div>
  <div class="scenario-stats">
    <div class="stat">
      <div class="label">ALE Expected (P50)</div>
      <div class="value">${result.percentiles.get(50, 0):,.0f}</div>
    </div>
    <div class="stat">
      <div class="label">ALE Likely Max (P90)</div>
      <div class="value" style="color:var(--high)">${result.percentiles.get(90, 0):,.0f}</div>
    </div>
    <div class="stat">
      <div class="label">ALE Worst (P95)</div>
      <div class="value" style="color:var(--critical)">${result.percentiles.get(95, 0):,.0f}</div>
    </div>
    <div class="stat">
      <div class="label">Mean LEF</div>
      <div class="value">{result.mean_lef:.2f}/yr</div>
    </div>
    <div class="stat">
      <div class="label">Mean Loss/Event</div>
      <div class="value">${result.mean_lm:,.0f}</div>
    </div>
    <div class="stat">
      <div class="label">% of Revenue (P90)</div>
      <div class="value">{p90_pct:.3f}%</div>
    </div>
  </div>
  <div class="breakdown">
    <h3 style="font-size:0.85rem;color:var(--text-secondary);margin-top:1rem">Average Loss Breakdown (per event)</h3>
    {breakdown_html}
  </div>
</div>"""

    def _html_controls_table(self) -> str:
        """Generate HTML controls table."""
        if not self.control_analyses:
            return "<p style='color:var(--text-secondary)'>No controls defined.</p>"

        rows = ""
        for ca in self.control_analyses:
            roi_class = "roi-positive" if ca.roi > 0 else "roi-negative"
            rows += f"""
    <tr>
      <td>{self._esc(ca.control_name)}</td>
      <td>{self._esc(ca.category)}</td>
      <td style="text-align:right">{ca.effectiveness_mean:.0f}%</td>
      <td style="text-align:right">${ca.ale_reduction:,.0f}</td>
      <td style="text-align:right">${ca.annual_cost:,.0f}</td>
      <td style="text-align:right" class="{roi_class}">{ca.roi:.1f}x</td>
    </tr>"""

        return f"""
<table class="ctrl-table">
  <thead>
    <tr>
      <th>Control</th><th>Type</th><th style="text-align:right">Effectiveness</th>
      <th style="text-align:right">ALE Reduction</th><th style="text-align:right">Annual Cost</th>
      <th style="text-align:right">ROI</th>
    </tr>
  </thead>
  <tbody>{rows}
  </tbody>
</table>"""

    # ── SVG Charts ───────────────────────────────────────────────────

    def _svg_risk_gauge(self, score: float) -> str:
        """Generate SVG donut gauge for risk score."""
        # Donut chart: 270 degrees max
        angle = score / 100 * 270
        rad_start = math.radians(135)  # start at bottom-left
        rad_end = math.radians(135 + angle)

        cx, cy, r = 100, 100, 70
        # SVG arc
        x1 = cx + r * math.cos(rad_start)
        y1 = cy + r * math.sin(rad_start)
        x2 = cx + r * math.cos(rad_end)
        y2 = cy + r * math.sin(rad_end)
        large_arc = 1 if angle > 180 else 0

        if score >= 75:
            color = "#ef4444"
        elif score >= 50:
            color = "#f97316"
        elif score >= 25:
            color = "#eab308"
        else:
            color = "#22c55e"

        # Background arc (full 270°)
        bg_end = math.radians(135 + 270)
        bx2 = cx + r * math.cos(bg_end)
        by2 = cy + r * math.sin(bg_end)

        sev = ("CRITICAL" if score >= 75 else "HIGH" if score >= 50
               else "MEDIUM" if score >= 25 else "LOW")

        return f"""<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
  <path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 1 1 {bx2:.1f} {by2:.1f}"
        fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="14" stroke-linecap="round"/>
  <path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 {large_arc} 1 {x2:.1f} {y2:.1f}"
        fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"/>
  <text x="100" y="95" text-anchor="middle" fill="{color}" font-size="32" font-weight="700"
        class="gauge-text">{score:.0f}</text>
  <text x="100" y="115" text-anchor="middle" fill="#94a3b8" font-size="12"
        class="gauge-text">{sev}</text>
</svg>"""

    def _svg_heatmap(self) -> str:
        """Generate SVG risk heatmap (likelihood × impact grid)."""
        if not self.results:
            return "<svg viewBox='0 0 300 250'></svg>"

        svg = """<svg viewBox="0 0 320 280" xmlns="http://www.w3.org/2000/svg">
  <!-- Grid labels -->
  <text x="160" y="270" text-anchor="middle" fill="#94a3b8" font-size="11">Likelihood (LEF)</text>
  <text x="10" y="130" text-anchor="middle" fill="#94a3b8" font-size="11"
        transform="rotate(-90, 10, 130)">Impact ($)</text>
  <!-- Grid -->"""

        # 5x5 grid
        cell_w, cell_h = 52, 42
        ox, oy = 45, 15
        likelihood_labels = ["Rare", "Low", "Med", "High", "V.High"]
        impact_labels = ["V.High", "High", "Med", "Low", "Neg."]

        for i, label in enumerate(likelihood_labels):
            svg += f'\n  <text x="{ox + i * cell_w + cell_w//2}" y="{oy + 5 * cell_h + 15}" text-anchor="middle" fill="#64748b" font-size="9">{label}</text>'
        for j, label in enumerate(impact_labels):
            svg += f'\n  <text x="{ox - 5}" y="{oy + j * cell_h + cell_h//2 + 3}" text-anchor="end" fill="#64748b" font-size="9">{label}</text>'

        # Background cells with risk gradient
        risk_colors = [
            ["#ef4444", "#ef4444", "#f97316", "#eab308", "#22c55e"],  # V.High impact
            ["#ef4444", "#f97316", "#f97316", "#eab308", "#22c55e"],  # High impact
            ["#f97316", "#f97316", "#eab308", "#22c55e", "#22c55e"],  # Med impact
            ["#eab308", "#eab308", "#22c55e", "#22c55e", "#22c55e"],  # Low impact
            ["#22c55e", "#22c55e", "#22c55e", "#22c55e", "#22c55e"],  # Neg impact
        ]

        for row in range(5):
            for col in range(5):
                x = ox + col * cell_w
                y = oy + row * cell_h
                color = risk_colors[row][4 - col]  # flip column order
                svg += f'\n  <rect x="{x}" y="{y}" width="{cell_w}" height="{cell_h}" rx="4" fill="{color}" opacity="0.15" stroke="{color}" stroke-width="0.5" stroke-opacity="0.3"/>'

        # Plot scenarios
        for result in self.results:
            # Normalize LEF to 0-4 grid position
            lef = result.mean_lef
            if lef >= 10:
                col = 4
            elif lef >= 5:
                col = 3
            elif lef >= 1:
                col = 2
            elif lef >= 0.1:
                col = 1
            else:
                col = 0

            # Normalize LM to 0-4 grid position
            lm = result.mean_lm
            if lm >= 10_000_000:
                row = 0
            elif lm >= 1_000_000:
                row = 1
            elif lm >= 100_000:
                row = 2
            elif lm >= 10_000:
                row = 3
            else:
                row = 4

            cx = ox + col * cell_w + cell_w // 2
            cy = oy + row * cell_h + cell_h // 2

            sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316",
                          "MEDIUM": "#eab308", "LOW": "#22c55e"}
            dot_color = sev_colors.get(result.severity, "#6366f1")

            # Abbreviate name
            abbrev = result.scenario_name[:3].upper()
            svg += f'\n  <circle cx="{cx}" cy="{cy}" r="14" fill="{dot_color}" opacity="0.8"/>'
            svg += f'\n  <text x="{cx}" y="{cy + 3}" text-anchor="middle" fill="white" font-size="8" font-weight="600">{abbrev}</text>'

        svg += "\n</svg>"
        return svg

    def _svg_loss_exceedance(self) -> str:
        """Generate SVG loss exceedance curve (aggregate)."""
        if not self.results:
            return "<svg viewBox='0 0 300 200'></svg>"

        # Aggregate ALE distribution
        all_ale = []
        for r in self.results:
            all_ale.extend(r.ale_distribution)
        all_ale.sort()

        if not all_ale or all_ale[-1] == 0:
            return "<svg viewBox='0 0 300 200'></svg>"

        n = len(all_ale)
        max_ale = all_ale[-1]

        # Generate curve points
        w, h = 300, 180
        ox, oy = 50, 10
        pw, ph = w - ox - 10, h - oy - 30

        points = []
        for i in range(51):
            threshold = max_ale * i / 50
            exceed = sum(1 for x in all_ale if x > threshold) / n
            px = ox + (i / 50) * pw
            py = oy + (1 - exceed) * ph
            points.append(f"{px:.1f},{py:.1f}")

        polyline = " ".join(points)

        # Format axis labels
        def fmt_money(v: float) -> str:
            if v >= 1_000_000:
                return f"${v/1_000_000:.0f}M"
            elif v >= 1_000:
                return f"${v/1_000:.0f}K"
            return f"${v:.0f}"

        svg = f"""<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg">
  <!-- Axes -->
  <line x1="{ox}" y1="{oy}" x2="{ox}" y2="{oy+ph}" stroke="#334155" stroke-width="1"/>
  <line x1="{ox}" y1="{oy+ph}" x2="{ox+pw}" y2="{oy+ph}" stroke="#334155" stroke-width="1"/>

  <!-- Y axis labels (probability) -->
  <text x="{ox-5}" y="{oy+5}" text-anchor="end" fill="#64748b" font-size="9">100%</text>
  <text x="{ox-5}" y="{oy+ph/2+3}" text-anchor="end" fill="#64748b" font-size="9">50%</text>
  <text x="{ox-5}" y="{oy+ph+3}" text-anchor="end" fill="#64748b" font-size="9">0%</text>

  <!-- X axis labels (loss) -->
  <text x="{ox}" y="{oy+ph+15}" text-anchor="start" fill="#64748b" font-size="9">$0</text>
  <text x="{ox+pw/2}" y="{oy+ph+15}" text-anchor="middle" fill="#64748b" font-size="9">{fmt_money(max_ale/2)}</text>
  <text x="{ox+pw}" y="{oy+ph+15}" text-anchor="end" fill="#64748b" font-size="9">{fmt_money(max_ale)}</text>

  <!-- Grid lines -->
  <line x1="{ox}" y1="{oy+ph/4}" x2="{ox+pw}" y2="{oy+ph/4}" stroke="#1e293b" stroke-width="0.5"/>
  <line x1="{ox}" y1="{oy+ph/2}" x2="{ox+pw}" y2="{oy+ph/2}" stroke="#1e293b" stroke-width="0.5"/>
  <line x1="{ox}" y1="{oy+3*ph/4}" x2="{ox+pw}" y2="{oy+3*ph/4}" stroke="#1e293b" stroke-width="0.5"/>

  <!-- Curve -->
  <polyline points="{polyline}" fill="none" stroke="#6366f1" stroke-width="2"/>

  <!-- Fill area -->
  <polygon points="{ox},{oy} {polyline} {ox+pw},{oy+ph} {ox},{oy+ph}"
           fill="url(#lec-grad)" opacity="0.3"/>

  <defs>
    <linearGradient id="lec-grad" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#6366f1" stop-opacity="0.4"/>
      <stop offset="100%" stop-color="#6366f1" stop-opacity="0"/>
    </linearGradient>
  </defs>

  <!-- Axis titles -->
  <text x="{ox+pw/2}" y="{oy+ph+28}" text-anchor="middle" fill="#94a3b8" font-size="9">Annual Loss ($)</text>
</svg>"""
        return svg

    def _svg_control_bars(self) -> str:
        """Generate SVG horizontal bar chart for control effectiveness."""
        if not self.control_analyses:
            return "<svg viewBox='0 0 300 200'><text x='150' y='100' text-anchor='middle' fill='#64748b' font-size='11'>No controls</text></svg>"

        n = len(self.control_analyses)
        bar_h = 24
        gap = 8
        h = n * (bar_h + gap) + 20
        w = 300
        ox = 140

        max_eff = max(ca.effectiveness_mean for ca in self.control_analyses)
        if max_eff == 0:
            max_eff = 100

        svg = f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg">'

        for i, ca in enumerate(self.control_analyses):
            y = i * (bar_h + gap) + 5
            bar_w = (ca.effectiveness_mean / 100) * (w - ox - 10)

            # Color based on ROI
            if ca.roi >= 2:
                color = "#22c55e"
            elif ca.roi >= 0:
                color = "#eab308"
            else:
                color = "#ef4444"

            # Truncate name
            name = ca.control_name[:20]
            if len(ca.control_name) > 20:
                name += "…"

            svg += f"""
  <text x="{ox-5}" y="{y+bar_h//2+3}" text-anchor="end" fill="#94a3b8" font-size="9">{self._esc(name)}</text>
  <rect x="{ox}" y="{y}" width="{w-ox-10}" height="{bar_h}" rx="4" fill="rgba(255,255,255,0.03)"/>
  <rect x="{ox}" y="{y}" width="{bar_w:.0f}" height="{bar_h}" rx="4" fill="{color}" opacity="0.7"/>
  <text x="{ox+bar_w+5}" y="{y+bar_h//2+3}" fill="#e2e8f0" font-size="9">{ca.effectiveness_mean:.0f}% (ROI: {ca.roi:.1f}x)</text>"""

        svg += "\n</svg>"
        return svg

    # ── Utility ──────────────────────────────────────────────────────

    def _vprint(self, msg: str) -> None:
        """Print if verbose mode is on."""
        if self.verbose:
            print(msg)


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="crq_engine",
        description="FAIR-based Cyber Risk Quantification Engine — "
                    "Monte Carlo simulation for cyber risk scenarios.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python crq_engine.py sample_scenarios.json
  python crq_engine.py scenarios.json --json report.json --html dashboard.html
  python crq_engine.py scenarios.json --severity HIGH --simulations 50000
  python crq_engine.py scenarios.json --seed 42 -v
""",
    )
    parser.add_argument("scenarios", help="Path to scenarios JSON file")
    parser.add_argument("--json", metavar="FILE",
                        help="Save JSON report to FILE")
    parser.add_argument("--html", metavar="FILE",
                        help="Save HTML dashboard to FILE")
    parser.add_argument("--severity", metavar="LEVEL",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity to include (default: all)")
    parser.add_argument("--simulations", type=int, default=DEFAULT_SIMULATIONS,
                        metavar="N",
                        help=f"Monte Carlo iterations (default: {DEFAULT_SIMULATIONS:,})")
    parser.add_argument("--seed", type=int, default=None, metavar="N",
                        help="Random seed for reproducibility")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--version", action="version",
                        version=f"CRQ Engine v{__version__}")

    args = parser.parse_args()

    # Validate input file
    if not os.path.isfile(args.scenarios):
        print(f"\n  {SEVERITY_COLOR['CRITICAL']}ERROR:{RESET} "
              f"File not found: {args.scenarios}")
        return 2

    # Initialize engine
    engine = CRQEngine(simulations=args.simulations, seed=args.seed,
                       verbose=args.verbose)

    try:
        engine.load_scenarios(args.scenarios)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"\n  {SEVERITY_COLOR['CRITICAL']}ERROR:{RESET} "
              f"Invalid input: {e}")
        return 2

    # Run simulations
    t0 = time.time()
    engine.run_all()
    elapsed = time.time() - t0

    if args.verbose:
        print(f"\n  Simulation completed in {elapsed:.2f}s")

    # Apply severity filter
    if args.severity:
        engine.filter_severity(args.severity)

    # Generate reports
    engine.print_report()

    if args.json:
        engine.save_json(args.json)
    if args.html:
        engine.save_html(args.html)

    # Summary line
    summ = engine.summary()
    print(f"\n  {BOLD}Analysis complete:{RESET} "
          f"{summ['total_scenarios']} scenarios, "
          f"Total ALE P90: ${summ.get('total_ale_p90', 0):,.0f}, "
          f"Highest Risk Score: {summ.get('highest_risk_score', 0):.1f}/100")

    # Exit code
    has_critical_or_high = (summ.get("critical_count", 0) > 0
                            or summ.get("high_count", 0) > 0)
    return 1 if has_critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
