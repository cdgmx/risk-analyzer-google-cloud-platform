"""
@purpose: Public surface of the gcp_risk_analyzer package.
@note: Exposes GCPRiskAnalyzer and the Finding/Severity model for programmatic use.
"""
from gcp_risk_analyzer.analyzer import GCPRiskAnalyzer
from gcp_risk_analyzer.models.finding import Finding, Severity

__version__ = "0.1.0"
__all__ = ["GCPRiskAnalyzer", "Finding", "Severity"]
