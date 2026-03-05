"""
@purpose: Module entry point — invoked via `python -m gcp_risk_analyzer`.
@note: Reads GCP_PROJECT_ID from the environment, validates it via GCPRiskAnalyzer.__init__,
       runs all checks, and exits with code 1 on configuration errors.
"""
from __future__ import annotations

import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("gcp_risk_analyzer")


def main() -> None:
    """
    @purpose: CLI entry point — read project ID from env, run analyzer, print report.
    @note: Exits with code 1 if GCP_PROJECT_ID is unset or invalid.
    """
    project_id = os.environ.get("GCP_PROJECT_ID", "").strip()
    if not project_id:
        logger.error("GCP_PROJECT_ID environment variable is not set or is empty.")
        sys.exit(1)

    # Import here so logging is configured before any module-level side effects.
    from gcp_risk_analyzer.analyzer import GCPRiskAnalyzer  # noqa: PLC0415

    try:
        analyzer = GCPRiskAnalyzer(project_id)
    except ValueError as exc:
        logger.error("Invalid project ID: %s", exc)
        sys.exit(1)

    analyzer.run_all_checks()


if __name__ == "__main__":
    main()
