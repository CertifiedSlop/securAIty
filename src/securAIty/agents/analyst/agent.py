"""
Security Analyst Agent

Security event analysis, incident investigation, and threat
intelligence correlation for security operations.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional

from ..events.correlation import CorrelationContext
from ..events.schema import EventStatus, EventType, SecurityEvent, Severity
from .base import AgentConfig, BaseAgent


@dataclass
class Incident:
    """
    Security incident information.

    Attributes:
        incident_id: Unique incident identifier
        title: Incident title
        severity: Incident severity
        status: Incident status
        affected_resources: List of affected resources
        indicators: IOCs and evidence
        timeline: Incident timeline
        root_cause: Root cause analysis
        remediation_steps: Remediation actions
    """

    incident_id: str
    title: str
    severity: str
    status: str = "open"
    affected_resources: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    root_cause: str = ""
    remediation_steps: list[str] = field(default_factory=list)


@dataclass
class ThreatIntelligence:
    """
    Threat intelligence information.

    Attributes:
        threat_actor: Threat actor name
        ttps: Tactics, techniques, procedures
        iocs: Indicators of compromise
        confidence: Intelligence confidence
        source: Intelligence source
    """

    threat_actor: str
    ttps: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    confidence: float = 0.0
    source: str = ""


class AnalystAgent(BaseAgent):
    """
    Security Analyst agent for incident investigation.

    Analyzes security events, correlates threats, investigates
    incidents, and provides actionable intelligence.

    Capabilities:
        - Event analysis and triage
        - Incident investigation
        - Threat correlation
        - Root cause analysis
        - Intelligence enrichment
    """

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        """
        Initialize security analyst agent.

        Args:
            config: Optional agent configuration
        """
        if config is None:
            config = AgentConfig(
                agent_id="analyst_agent",
                name="Security Analyst Agent",
                description="Security event analysis and incident investigation",
                capabilities=[
                    {
                        "name": "event_analysis",
                        "description": "Analyze and triage security events",
                        "priority": 10,
                    },
                    {
                        "name": "incident_investigation",
                        "description": "Investigate security incidents",
                        "priority": 20,
                    },
                    {
                        "name": "threat_correlation",
                        "description": "Correlate threats across events",
                        "priority": 30,
                    },
                    {
                        "name": "root_cause_analysis",
                        "description": "Determine root causes",
                        "priority": 40,
                    },
                    {
                        "name": "intelligence_enrichment",
                        "description": "Enrich with threat intelligence",
                        "priority": 50,
                    },
                ],
                max_concurrent_tasks=10,
                task_timeout=300.0,
            )

        super().__init__(config)

        self._incidents: dict[str, Incident] = {}
        self._analyzed_events: list[dict[str, Any]] = []
        self._threat_intel: dict[str, ThreatIntelligence] = {}
        self._event_callback: Optional[callable] = None

    def set_event_callback(self, callback: callable) -> None:
        """Set callback for emitting security events."""
        self._event_callback = callback

    async def _execute(
        self,
        input_data: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Execute security analysis.

        Args:
            input_data: Analysis request data
            context: Execution context
            correlation_context: Correlation tracking

        Returns:
            Analysis results
        """
        analysis_type = input_data.get("analysis_type", "triage")

        if analysis_type == "triage":
            return await self._triage_event(input_data, correlation_context)

        elif analysis_type == "investigate":
            return await self._investigate_incident(input_data, correlation_context)

        elif analysis_type == "correlate":
            return await self._correlate_threats(input_data, correlation_context)

        elif analysis_type == "enrich":
            return await self._enrich_intelligence(input_data, correlation_context)

        else:
            return await self._comprehensive_analysis(input_data, correlation_context)

    async def _triage_event(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Triage security event.

        Args:
            input_data: Event data for triage
            correlation_context: Correlation tracking

        Returns:
            Triage results with priority
        """
        event_data = input_data.get("event", {})
        event_type = event_data.get("event_type", "unknown")
        severity = event_data.get("severity", "MEDIUM")

        priority_score = self._calculate_priority(event_data)
        classification = self._classify_event(event_data)

        triage_result = {
            "event_id": event_data.get("event_id", "unknown"),
            "priority": priority_score,
            "classification": classification,
            "recommended_action": self._get_recommended_action(classification, priority_score),
            "requires_investigation": priority_score >= 70,
            "auto_remediation_possible": priority_score < 30,
        }

        self._analyzed_events.append({
            "event_id": event_data.get("event_id"),
            "triage_result": triage_result,
            "timestamp": asyncio.get_event_loop().time(),
        })

        return triage_result

    async def _investigate_incident(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Investigate security incident.

        Args:
            input_data: Incident investigation data
            correlation_context: Correlation tracking

        Returns:
            Investigation results
        """
        incident_id = input_data.get("incident_id", f"inc_{hash(str(input_data))}")
        related_events = input_data.get("related_events", [])

        timeline = self._build_timeline(related_events)
        affected_resources = self._identify_affected_resources(related_events)
        iocs = self._extract_iocs(related_events)

        root_cause = await self._determine_root_cause(timeline, affected_resources)

        incident = Incident(
            incident_id=incident_id,
            title=input_data.get("title", "Security Incident"),
            severity=input_data.get("severity", "MEDIUM"),
            affected_resources=affected_resources,
            indicators=iocs,
            timeline=timeline,
            root_cause=root_cause,
            remediation_steps=self._generate_remediation(root_cause, iocs),
        )

        self._incidents[incident_id] = incident

        return {
            "incident_id": incident_id,
            "status": "investigated",
            "severity": incident.severity,
            "affected_resources": affected_resources,
            "iocs": iocs,
            "root_cause": root_cause,
            "remediation_steps": incident.remediation_steps,
            "timeline_events": len(timeline),
        }

    async def _correlate_threats(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Correlate threats across events.

        Args:
            input_data: Events for correlation
            correlation_context: Correlation tracking

        Returns:
            Correlation results
        """
        events = input_data.get("events", [])
        time_window = input_data.get("time_window_hours", 24)

        correlations = []

        ip_correlation = self._correlate_by_ip(events)
        if ip_correlation:
            correlations.append({
                "type": "ip_address",
                "related_events": ip_correlation,
                "confidence": 0.85,
            })

        pattern_correlation = self._correlate_by_pattern(events)
        if pattern_correlation:
            correlations.append({
                "type": "attack_pattern",
                "related_events": pattern_correlation,
                "confidence": 0.75,
            })

        return {
            "correlations_found": len(correlations),
            "correlations": correlations,
            "related_event_count": sum(len(c["related_events"]) for c in correlations),
            "threat_assessment": self._assess_threat_level(correlations),
        }

    async def _enrich_intelligence(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Enrich with threat intelligence.

        Args:
            input_data: IOCs for enrichment
            correlation_context: Correlation tracking

        Returns:
            Enriched intelligence
        """
        iocs = input_data.get("iocs", [])
        indicators = input_data.get("indicators", [])

        enriched = []

        for ioc in iocs:
            intel = await self._lookup_intelligence(ioc)
            if intel:
                enriched.append({
                    "ioc": ioc,
                    "intelligence": intel,
                })

        return {
            "iocs_enriched": len(enriched),
            "enrichment_results": enriched,
            "threat_actors_identified": list(set(
                e["intelligence"].get("threat_actor", "")
                for e in enriched if e["intelligence"].get("threat_actor")
            )),
        }

    async def _comprehensive_analysis(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Perform comprehensive security analysis.

        Args:
            input_data: Analysis data
            correlation_context: Correlation tracking

        Returns:
            Comprehensive analysis results
        """
        triage = await self._triage_event(input_data, correlation_context)
        correlation = await self._correlate_threats(input_data, correlation_context)

        analysis = {
            "analysis_type": "comprehensive",
            "triage": triage,
            "correlation": correlation,
            "overall_risk": self._calculate_overall_risk(triage, correlation),
            "recommended_actions": self._generate_action_plan(triage, correlation),
            "executive_summary": self._generate_executive_summary(triage, correlation),
        }

        return analysis

    def _calculate_priority(self, event_data: dict[str, Any]) -> int:
        """Calculate event priority score."""
        score = 50

        severity = event_data.get("severity", "MEDIUM")
        if severity == "CRITICAL":
            score += 40
        elif severity == "HIGH":
            score += 25
        elif severity == "LOW":
            score -= 20

        event_type = event_data.get("event_type", "")
        if "THREAT" in str(event_type):
            score += 15
        if "VULNERABILITY" in str(event_type):
            score += 10

        return min(score, 100)

    def _classify_event(self, event_data: dict[str, Any]) -> str:
        """Classify event type."""
        event_type = event_data.get("event_type", "")

        classifications = {
            "THREAT_DETECTED": "active_threat",
            "VULNERABILITY_FOUND": "vulnerability",
            "POLICY_VIOLATION": "compliance",
            "ANOMALY_DETECTED": "anomaly",
            "SECURITY_ALERT": "alert",
        }

        return classifications.get(event_type, "unknown")

    def _get_recommended_action(self, classification: str, priority: int) -> str:
        """Get recommended action based on classification."""
        if priority >= 80:
            return "immediate_investigation"
        elif priority >= 60:
            return "priority_investigation"
        elif priority >= 40:
            return "scheduled_review"
        else:
            return "log_and_monitor"

    def _build_timeline(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build incident timeline from events."""
        timeline = []

        for event in sorted(events, key=lambda e: e.get("timestamp", 0)):
            timeline.append({
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "description": event.get("description", ""),
                "severity": event.get("severity"),
            })

        return timeline

    def _identify_affected_resources(self, events: list[dict[str, Any]]) -> list[str]:
        """Identify affected resources from events."""
        resources = set()

        for event in events:
            resource_id = event.get("resource_id")
            if resource_id:
                resources.add(resource_id)
            payload = event.get("payload", {})
            if "resource" in payload:
                resources.add(str(payload["resource"]))

        return list(resources)

    def _extract_iocs(self, events: list[dict[str, Any]]) -> list[str]:
        """Extract indicators of compromise."""
        iocs = set()

        for event in events:
            payload = event.get("payload", {})
            if "indicators" in payload:
                iocs.update(payload["indicators"])
            if "ip_address" in payload:
                iocs.add(payload["ip_address"])
            if "hash" in payload:
                iocs.add(payload["hash"])

        return list(iocs)

    async def _determine_root_cause(
        self,
        timeline: list[dict[str, Any]],
        resources: list[str],
    ) -> str:
        """Determine root cause from timeline."""
        if not timeline:
            return "Unable to determine root cause - insufficient data"

        first_event = timeline[0]
        event_type = first_event.get("event_type", "")

        cause_mapping = {
            "THREAT_DETECTED": "External threat actor activity detected",
            "VULNERABILITY_FOUND": "Unpatched vulnerability exploited",
            "POLICY_VIOLATION": "Security policy not enforced or followed",
            "ANOMALY_DETECTED": "Unusual behavior pattern detected",
        }

        return cause_mapping.get(event_type, "Security incident requiring investigation")

    def _generate_remediation(
        self,
        root_cause: str,
        iocs: list[str],
    ) -> list[str]:
        """Generate remediation steps."""
        steps = [
            "Contain affected systems",
            "Preserve evidence for forensics",
            "Reset compromised credentials",
            "Apply necessary patches",
            "Monitor for recurrence",
            "Update detection rules",
        ]

        if "vulnerability" in root_cause.lower():
            steps.insert(2, "Patch vulnerable systems immediately")

        if len(iocs) > 0:
            steps.append("Block identified IOCs at perimeter")

        return steps

    def _correlate_by_ip(self, events: list[dict[str, Any]]) -> list[str]:
        """Correlate events by IP address."""
        ip_events = {}

        for event in events:
            payload = event.get("payload", {})
            ip = payload.get("ip_address") or payload.get("source_ip")
            if ip:
                if ip not in ip_events:
                    ip_events[ip] = []
                ip_events[ip].append(event.get("event_id", "unknown"))

        return [event_ids for ip, event_ids in ip_events.items() if len(event_ids) > 1]

    def _correlate_by_pattern(self, events: list[dict[str, Any]]) -> list[str]:
        """Correlate events by attack pattern."""
        pattern_events = {}

        for event in events:
            event_type = event.get("event_type", "unknown")
            if event_type not in pattern_events:
                pattern_events[event_type] = []
            pattern_events[event_type].append(event.get("event_id", "unknown"))

        return [event_ids for event_type, event_ids in pattern_events.items() if len(event_ids) > 1]

    def _assess_threat_level(self, correlations: list[dict[str, Any]]) -> str:
        """Assess overall threat level."""
        if not correlations:
            return "low"

        high_confidence = sum(1 for c in correlations if c.get("confidence", 0) > 0.8)

        if high_confidence >= 3:
            return "critical"
        elif high_confidence >= 2:
            return "high"
        elif len(correlations) >= 2:
            return "medium"
        else:
            return "low"

    async def _lookup_intelligence(self, ioc: str) -> Optional[ThreatIntelligence]:
        """Lookup threat intelligence for IOC."""
        if ioc in self._threat_intel:
            return self._threat_intel[ioc]

        mock_intel = ThreatIntelligence(
            threat_actor="Unknown",
            ttps=["reconnaissance", "initial_access"],
            iocs=[ioc],
            confidence=0.6,
            source="internal_analysis",
        )

        self._threat_intel[ioc] = mock_intel
        return mock_intel

    def _calculate_overall_risk(
        self,
        triage: dict[str, Any],
        correlation: dict[str, Any],
    ) -> dict[str, Any]:
        """Calculate overall risk assessment."""
        priority = triage.get("priority", 50)
        correlations = correlation.get("correlations_found", 0)
        threat_assessment = correlation.get("threat_assessment", "low")

        risk_scores = {"low": 0, "medium": 25, "high": 50, "critical": 75}

        total_risk = priority + (correlations * 10) + risk_scores.get(threat_assessment, 0)

        if total_risk >= 80:
            level = "critical"
        elif total_risk >= 60:
            level = "high"
        elif total_risk >= 40:
            level = "medium"
        else:
            level = "low"

        return {
            "level": level,
            "score": min(total_risk, 100),
            "factors": {
                "event_priority": priority,
                "correlation_count": correlations,
                "threat_assessment": threat_assessment,
            },
        }

    def _generate_action_plan(
        self,
        triage: dict[str, Any],
        correlation: dict[str, Any],
    ) -> list[str]:
        """Generate action plan."""
        actions = []

        if triage.get("requires_investigation"):
            actions.append("Initiate detailed investigation")

        if correlation.get("correlations_found", 0) > 0:
            actions.append("Review correlated events")
            actions.append("Assess scope of potential attack")

        actions.extend([
            "Document findings",
            "Update incident ticket",
            "Notify relevant stakeholders",
        ])

        return actions

    def _generate_executive_summary(
        self,
        triage: dict[str, Any],
        correlation: dict[str, Any],
    ) -> str:
        """Generate executive summary."""
        risk = self._calculate_overall_risk(triage, correlation)

        return (
            f"Security analysis complete. Overall risk level: {risk['level'].upper()}. "
            f"Priority score: {triage.get('priority', 0)}. "
            f"Correlated events: {correlation.get('correlations_found', 0)}. "
            f"Recommended action: {triage.get('recommended_action', 'review')}."
        )

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID."""
        return self._incidents.get(incident_id)

    def get_all_incidents(self) -> list[dict[str, Any]]:
        """Get all incidents."""
        return [
            {
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "affected_resources": inc.affected_resources,
            }
            for inc in self._incidents.values()
        ]
