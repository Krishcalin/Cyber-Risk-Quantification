# Cyber Risk Quantification (CRQ) Engine

## Project Overview

FAIR-based Monte Carlo simulation platform for quantifying cyber risk in financial terms. Single-file Python CLI tool with zero external dependencies.

- **Repo**: `c:\KRISHNENDU\PROJECTS\Cyber-Risk-Quantification\Cyber-Risk-Quantification`
- **Main file**: `crq_engine.py` v1.0.0
- **Input**: `sample_scenarios.json` (8 scenarios, 8 assets, 12 controls)
- **Language**: Python 3.10+
- **Dependencies**: None (stdlib only)

## Architecture

### Single file: `crq_engine.py`

| Component | Purpose |
|-----------|---------|
| `FAIREngine` | FAIR model math: PERT sampling (`random.betavariate`), vulnerability calc, LEF/LM computation, Monte Carlo simulation |
| `CRQEngine` | Orchestration: load JSON scenarios, run simulations, control analysis, console/JSON/HTML reports |
| `Finding` | Dataclass — per-scenario risk finding (score, severity, ALE percentiles) |
| `SimulationResult` | Dataclass — full simulation output (distributions, percentiles, loss exceedance) |
| `ControlAnalysis` | Dataclass — per-control effectiveness, ROI, ALE reduction |

### FAIR Model

```
Risk = LEF x LM
  LEF = TEF x Vulnerability
    TEF = Contact Frequency x Probability of Action
    Vulnerability = clamp((TC - RS + 50) / 100, 0, 1)
  LM = (Primary + Secondary) x Industry Multiplier
    Primary = Productivity + Response + Replacement
    Secondary = Fines + Reputation + Competitive Advantage
```

All inputs use min/likely/max ranges sampled via PERT (beta) distribution.

### Key Constants

- `DEFAULT_SIMULATIONS = 10,000`
- `PERCENTILES = [5, 10, 25, 50, 75, 90, 95]`
- Risk severity thresholds (ALE P90 as % of revenue): CRITICAL >= 5%, HIGH >= 2%, MEDIUM >= 0.5%, LOW < 0.5%
- Control RS boost capped at 40 points, individual control max ~15 points (diminishing returns)
- Risk score: log-scale normalization of ALE P90 / revenue, mapped 0-100

## CLI

```bash
python crq_engine.py <scenarios.json> [--json FILE] [--html FILE] [--severity LEVEL] [--simulations N] [--seed N] [-v] [--version]
```

Exit codes: 0 = no CRITICAL/HIGH, 1 = CRITICAL/HIGH found, 2 = input error.

## Scenario JSON Structure

```
organization: { name, revenue, employees, industry, headquarters }
assets[]:     { id, name, type, records, value{min,likely,max}, description }
controls[]:   { id, name, category, effectiveness{min,likely,max}, annual_cost, applies_to[], description }
scenarios[]:  { id, name, description, threat_community, asset_ids[],
                contact_frequency{}, probability_of_action{}, threat_capability{}, resistance_strength{},
                primary_loss{productivity{},response{},replacement{}},
                secondary_loss{fines{},reputation{},competitive_advantage{}} }
```

## Reports

- **Console**: Colored terminal output with text gauges, ALE percentile tables, control ROI table
- **JSON** (`--json`): Full structured output with percentiles, loss exceedance data, control analysis
- **HTML** (`--html`): Dark-themed dashboard with inline SVG charts (risk gauge donut, heatmap, loss exceedance curve, control bars)

## Conventions

- Follows Phalanx Cyber scanner pattern: Finding class, severity-based exit codes, `--json`/`--html`/`--severity`/`--verbose`/`--version` CLI flags
- Rule ID equivalent: scenario IDs (`scenario-001` through `scenario-008`)
- Control IDs: `ctrl-001` through `ctrl-012`
- Asset IDs: `asset-001` through `asset-008`
- Industry multipliers: financial_services=1.3, healthcare=1.25, technology=1.1, etc.
- Windows stdout encoding fix via `sys.stdout.reconfigure(encoding="utf-8")`

## Testing

```bash
# Basic run
python crq_engine.py sample_scenarios.json

# Reproducible with seed
python crq_engine.py sample_scenarios.json --seed 42 --simulations 1000

# Full report generation
python crq_engine.py sample_scenarios.json --json report.json --html dashboard.html

# Severity filter
python crq_engine.py sample_scenarios.json --severity HIGH
```

## Future Enhancements

- Agentic AI integration for automated scenario generation
- Real-time data feeds (threat intelligence, vulnerability scanners)
- FAIR-CAM (Controls Analytics Model) and FAIR-MAM (Materiality Assessment Model)
- Risk aggregation across business units
- What-if analysis for control investment decisions
- Integration with GRC platforms (ServiceNow, Archer)
