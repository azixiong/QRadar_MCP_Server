"""
Analysis Engine Module

This module provides intelligent analysis capabilities for QRadar security events.
It performs root cause analysis, timeline reconstruction, indicator extraction,
and generates actionable investigation recommendations.
"""

import logging
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum

from qradar_client import QRadarClient, Offense, LogEntry

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AttackIndicator:
    """Represents a security indicator extracted from logs."""
    indicator_type: str  # IP, DOMAIN, HASH, USERNAME, etc.
    value: str
    threat_level: ThreatLevel
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrence_count: int = 0
    context: str = ""  # Additional context about the indicator


@dataclass
class TimelineEvent:
    """Represents an event in the attack timeline."""
    timestamp: datetime
    event_type: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    severity: Optional[int] = None
    log_entry: Optional[LogEntry] = None


@dataclass
class InvestigationRecommendation:
    """Represents an actionable investigation recommendation."""
    priority: str  # HIGH, MEDIUM, LOW
    action_type: str  # EDR_QUERY, NETWORK_ISOLATION, USER_INVESTIGATION, THREAT_INTEL, etc.
    title: str
    description: str
    indicators: List[str] = field(default_factory=list)
    rationale: str = ""


class AnalysisEngine:
    """
    Intelligent analysis engine for QRadar security events.
    
    This engine performs automated root cause analysis, extracts security indicators,
    reconstructs attack timelines, and generates actionable recommendations.
    """
    
    def __init__(self, qradar_client: QRadarClient):
        """
        Initialize the analysis engine.
        
        Args:
            qradar_client: An instance of QRadarClient for data retrieval
        """
        self.qradar = qradar_client
        self.known_malicious_ips: Set[str] = set()  # Could be loaded from threat intel
        self.known_malicious_domains: Set[str] = set()  # Could be loaded from threat intel
    
    async def analyze_offense(
        self,
        offense_id: int
    ) -> Dict[str, Any]:
        """
        Perform comprehensive root cause analysis on a QRadar offense.
        
        This method:
        1. Retrieves offense details and all associated logs
        2. Extracts security indicators (IPs, domains, hashes, usernames)
        3. Reconstructs the attack timeline
        4. Identifies attack patterns and relationships
        5. Generates a structured investigation report
        
        Args:
            offense_id: The ID of the offense to analyze
            
        Returns:
            Dictionary containing the complete analysis report
        """
        try:
            # Step 1: Get offense details
            offense = await self.qradar.get_offense_details(offense_id)
            logger.info(f"Analyzing offense {offense_id}: {offense.description}")
            
            # Step 2: Get all associated logs
            logs = await self.qradar.get_offense_logs(offense_id, limit=5000)
            logger.info(f"Retrieved {len(logs)} log entries for offense {offense_id}")
            
            if not logs:
                return {
                    "offense_id": offense_id,
                    "status": "NO_LOGS",
                    "message": "No log entries found for this offense",
                    "offense_details": offense.dict()
                }
            
            # Step 3: Extract indicators
            indicators = self._extract_indicators(logs, offense)
            
            # Step 4: Build timeline
            timeline = self._build_timeline(logs, offense)
            
            # Step 5: Identify attack patterns
            patterns = self._identify_attack_patterns(logs, indicators)
            
            # Step 6: Generate summary
            summary = self._generate_summary(offense, indicators, timeline, patterns)
            
            # Step 7: Compile report
            report = {
                "offense_id": offense_id,
                "analysis_timestamp": datetime.now().isoformat(),
                "offense_details": offense.dict(),
                "summary": summary,
                "indicators": [
                    {
                        "type": ind.indicator_type,
                        "value": ind.value,
                        "threat_level": ind.threat_level.value,
                        "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
                        "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
                        "occurrence_count": ind.occurrence_count,
                        "context": ind.context
                    }
                    for ind in indicators
                ],
                "timeline": [
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "event_type": event.event_type,
                        "description": event.description,
                        "source_ip": event.source_ip,
                        "destination_ip": event.destination_ip,
                        "username": event.username,
                        "severity": event.severity
                    }
                    for event in sorted(timeline, key=lambda x: x.timestamp)
                ],
                "attack_patterns": patterns,
                "statistics": {
                    "total_logs": len(logs),
                    "unique_source_ips": len(set(log.source_ip for log in logs if log.source_ip)),
                    "unique_destination_ips": len(set(log.destination_ip for log in logs if log.destination_ip)),
                    "unique_usernames": len(set(log.username for log in logs if log.username)),
                    "time_span_minutes": self._calculate_timespan(logs),
                    "indicator_count": len(indicators)
                }
            }
            
            return report
        
        except Exception as e:
            logger.error(f"Error analyzing offense {offense_id}: {str(e)}")
            raise ValueError(f"Failed to analyze offense {offense_id}: {str(e)}")
    
    def _extract_indicators(
        self,
        logs: List[LogEntry],
        offense: Offense
    ) -> List[AttackIndicator]:
        """
        Extract security indicators from log entries.
        
        Args:
            logs: List of log entries
            offense: The offense object
            
        Returns:
            List of extracted AttackIndicator objects
        """
        indicators: Dict[str, AttackIndicator] = {}
        
        # Extract source IPs
        source_ips = Counter()
        source_ip_times: Dict[str, List[datetime]] = defaultdict(list)
        
        for log in logs:
            if log.source_ip:
                source_ips[log.source_ip] += 1
                if log.start_time:
                    source_ip_times[log.source_ip].append(
                        datetime.fromtimestamp(log.start_time / 1000)
                    )
        
        for ip, count in source_ips.items():
            times = source_ip_times[ip]
            threat_level = ThreatLevel.CRITICAL if ip in self.known_malicious_ips else ThreatLevel.HIGH
            indicators[f"IP:{ip}"] = AttackIndicator(
                indicator_type="SOURCE_IP",
                value=ip,
                threat_level=threat_level,
                first_seen=min(times) if times else None,
                last_seen=max(times) if times else None,
                occurrence_count=count,
                context=f"Appears in {count} log entries as source"
            )
        
        # Extract destination IPs
        dest_ips = Counter()
        dest_ip_times: Dict[str, List[datetime]] = defaultdict(list)
        
        for log in logs:
            if log.destination_ip:
                dest_ips[log.destination_ip] += 1
                if log.start_time:
                    dest_ip_times[log.destination_ip].append(
                        datetime.fromtimestamp(log.start_time / 1000)
                    )
        
        for ip, count in dest_ips.items():
            times = dest_ip_times[ip]
            threat_level = ThreatLevel.CRITICAL if ip in self.known_malicious_domains else ThreatLevel.MEDIUM
            indicators[f"DEST_IP:{ip}"] = AttackIndicator(
                indicator_type="DESTINATION_IP",
                value=ip,
                threat_level=threat_level,
                first_seen=min(times) if times else None,
                last_seen=max(times) if times else None,
                occurrence_count=count,
                context=f"Appears in {count} log entries as destination"
            )
        
        # Extract usernames
        usernames = Counter()
        username_times: Dict[str, List[datetime]] = defaultdict(list)
        
        for log in logs:
            if log.username:
                usernames[log.username] += 1
                if log.start_time:
                    username_times[log.username].append(
                        datetime.fromtimestamp(log.start_time / 1000)
                    )
        
        for username, count in usernames.items():
            times = username_times[username]
            indicators[f"USER:{username}"] = AttackIndicator(
                indicator_type="USERNAME",
                value=username,
                threat_level=ThreatLevel.MEDIUM if count > 10 else ThreatLevel.LOW,
                first_seen=min(times) if times else None,
                last_seen=max(times) if times else None,
                occurrence_count=count,
                context=f"Appears in {count} log entries"
            )
        
        # Extract domains from payloads (basic pattern matching)
        domains = Counter()
        for log in logs:
            if log.payload:
                # Simple domain extraction (can be enhanced with regex)
                import re
                domain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
                found_domains = re.findall(domain_pattern, log.payload)
                for domain_tuple in found_domains:
                    domain = domain_tuple[0] if isinstance(domain_tuple, tuple) else domain_tuple
                    if domain and len(domain) > 3:
                        domains[domain] += 1
        
        for domain, count in domains.items():
            if count >= 3:  # Only include domains that appear multiple times
                threat_level = ThreatLevel.CRITICAL if domain in self.known_malicious_domains else ThreatLevel.HIGH
                indicators[f"DOMAIN:{domain}"] = AttackIndicator(
                    indicator_type="DOMAIN",
                    value=domain,
                    threat_level=threat_level,
                    occurrence_count=count,
                    context=f"Extracted from {count} log payloads"
                )
        
        return list(indicators.values())
    
    def _build_timeline(
        self,
        logs: List[LogEntry],
        offense: Offense
    ) -> List[TimelineEvent]:
        """
        Reconstruct the attack timeline from log entries.
        
        Args:
            logs: List of log entries
            offense: The offense object
            
        Returns:
            List of TimelineEvent objects sorted by timestamp
        """
        timeline: List[TimelineEvent] = []
        
        # Add offense creation event
        if offense.start_time:
            timeline.append(TimelineEvent(
                timestamp=datetime.fromtimestamp(offense.start_time / 1000),
                event_type="OFFENSE_CREATED",
                description=f"Offense {offense.id} created: {offense.description}",
                severity=offense.severity
            ))
        
        # Process log entries
        for log in logs:
            if not log.start_time:
                continue
            
            timestamp = datetime.fromtimestamp(log.start_time / 1000)
            
            # Determine event type based on log characteristics
            event_type = "NETWORK_ACTIVITY"
            description = f"Network activity from {log.source_ip or 'unknown'} to {log.destination_ip or 'unknown'}"
            
            if log.username:
                event_type = "AUTHENTICATION"
                description = f"Authentication event for user {log.username} from {log.source_ip or 'unknown'}"
            
            if log.protocol:
                description += f" via {log.protocol}"
            
            if log.category:
                description += f" (Category: {log.category})"
            
            timeline.append(TimelineEvent(
                timestamp=timestamp,
                event_type=event_type,
                description=description,
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                username=log.username,
                log_entry=log
            ))
        
        return timeline
    
    def _identify_attack_patterns(
        self,
        logs: List[LogEntry],
        indicators: List[AttackIndicator]
    ) -> List[Dict[str, Any]]:
        """
        Identify attack patterns and behaviors.
        
        Args:
            logs: List of log entries
            indicators: List of extracted indicators
            
        Returns:
            List of identified attack patterns
        """
        patterns = []
        
        # Pattern: Rapid scanning (many connections from single IP)
        source_ip_counts = Counter(log.source_ip for log in logs if log.source_ip)
        for ip, count in source_ip_counts.items():
            if count > 100:
                patterns.append({
                    "pattern_type": "RAPID_SCANNING",
                    "description": f"Source IP {ip} made {count} connections, indicating potential scanning activity",
                    "severity": "HIGH",
                    "indicators": [ip]
                })
        
        # Pattern: Lateral movement (same user from multiple IPs)
        user_ip_map: Dict[str, Set[str]] = defaultdict(set)
        for log in logs:
            if log.username and log.source_ip:
                user_ip_map[log.username].add(log.source_ip)
        
        for username, ips in user_ip_map.items():
            if len(ips) > 5:
                patterns.append({
                    "pattern_type": "LATERAL_MOVEMENT",
                    "description": f"User {username} accessed from {len(ips)} different IP addresses",
                    "severity": "MEDIUM",
                    "indicators": [username] + list(ips)
                })
        
        # Pattern: Unusual port activity
        port_counts = Counter(log.destination_port for log in logs if log.destination_port)
        unusual_ports = [port for port, count in port_counts.items() if port in [4444, 5555, 6666, 8080, 9999]]
        if unusual_ports:
            patterns.append({
                "pattern_type": "UNUSUAL_PORTS",
                "description": f"Activity detected on unusual ports: {unusual_ports}",
                "severity": "MEDIUM",
                "indicators": [str(port) for port in unusual_ports]
            })
        
        # Pattern: Known malicious indicators
        critical_indicators = [ind for ind in indicators if ind.threat_level == ThreatLevel.CRITICAL]
        if critical_indicators:
            patterns.append({
                "pattern_type": "KNOWN_MALICIOUS_INDICATORS",
                "description": f"Found {len(critical_indicators)} indicators matching known malicious entities",
                "severity": "CRITICAL",
                "indicators": [ind.value for ind in critical_indicators]
            })
        
        return patterns
    
    def _generate_summary(
        self,
        offense: Offense,
        indicators: List[AttackIndicator],
        timeline: List[TimelineEvent],
        patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a human-readable summary of the analysis.
        
        Args:
            offense: The offense object
            indicators: List of extracted indicators
            timeline: List of timeline events
            patterns: List of identified patterns
            
        Returns:
            Dictionary containing summary information
        """
        critical_indicators = [ind for ind in indicators if ind.threat_level == ThreatLevel.CRITICAL]
        high_indicators = [ind for ind in indicators if ind.threat_level == ThreatLevel.HIGH]
        
        summary = {
            "overview": f"Analysis of offense {offense.id}: {offense.description or 'No description'}",
            "severity": offense.severity or 0,
            "status": offense.status or "UNKNOWN",
            "key_findings": [
                f"Extracted {len(indicators)} security indicators",
                f"Identified {len(patterns)} attack patterns",
                f"Timeline spans {len(timeline)} events"
            ],
            "critical_indicators_count": len(critical_indicators),
            "high_indicators_count": len(high_indicators),
            "attack_patterns_count": len(patterns)
        }
        
        if critical_indicators:
            summary["critical_indicators"] = [ind.value for ind in critical_indicators[:5]]
        
        return summary
    
    def _calculate_timespan(self, logs: List[LogEntry]) -> Optional[float]:
        """Calculate the time span of logs in minutes."""
        timestamps = [log.start_time for log in logs if log.start_time]
        if len(timestamps) < 2:
            return None
        
        min_time = min(timestamps)
        max_time = max(timestamps)
        return (max_time - min_time) / 1000 / 60  # Convert to minutes
    
    async def recommend_investigation_actions(
        self,
        offense_id: Optional[int] = None,
        indicators: Optional[List[str]] = None
    ) -> List[InvestigationRecommendation]:
        """
        Generate actionable investigation recommendations.
        
        Args:
            offense_id: Optional offense ID to analyze
            indicators: Optional list of indicators (IPs, usernames, etc.)
            
        Returns:
            List of InvestigationRecommendation objects
        """
        recommendations: List[InvestigationRecommendation] = []
        
        # If offense_id provided, get analysis first
        if offense_id:
            try:
                analysis = await self.analyze_offense(offense_id)
                indicators_from_analysis = [
                    ind["value"] for ind in analysis.get("indicators", [])
                    if ind["threat_level"] in ["CRITICAL", "HIGH"]
                ]
                if indicators:
                    indicators.extend(indicators_from_analysis)
                else:
                    indicators = indicators_from_analysis
                
                # Add recommendations based on patterns
                patterns = analysis.get("attack_patterns", [])
                for pattern in patterns:
                    if pattern.get("pattern_type") == "RAPID_SCANNING":
                        recommendations.append(InvestigationRecommendation(
                            priority="HIGH",
                            action_type="NETWORK_ISOLATION",
                            title=f"Isolate scanning source IP",
                            description=f"Source IP {pattern['indicators'][0]} shows scanning behavior. Consider network isolation.",
                            indicators=pattern["indicators"],
                            rationale=pattern["description"]
                        ))
                
            except Exception as e:
                logger.warning(f"Could not analyze offense {offense_id} for recommendations: {str(e)}")
        
        if not indicators:
            return recommendations
        
        # Generate recommendations based on indicators
        for indicator in indicators:
            # IP-based recommendations
            if self._is_ip_address(indicator):
                recommendations.append(InvestigationRecommendation(
                    priority="HIGH",
                    action_type="EDR_QUERY",
                    title=f"Query EDR for IP address {indicator}",
                    description=f"Search endpoint detection and response (EDR) systems for all activity from IP {indicator}",
                    indicators=[indicator],
                    rationale="IP address is a key indicator for endpoint investigation"
                ))
                
                recommendations.append(InvestigationRecommendation(
                    priority="MEDIUM",
                    action_type="THREAT_INTEL",
                    title=f"Check threat intelligence for IP {indicator}",
                    description=f"Query threat intelligence feeds to determine if {indicator} is known malicious",
                    indicators=[indicator],
                    rationale="Threat intelligence can provide context on indicator reputation"
                ))
            
            # Username-based recommendations
            elif self._is_username(indicator):
                recommendations.append(InvestigationRecommendation(
                    priority="HIGH",
                    action_type="USER_INVESTIGATION",
                    title=f"Investigate user account: {indicator}",
                    description=f"Review all authentication and access logs for user {indicator}. Check for privilege escalation, unusual access patterns, and data exfiltration.",
                    indicators=[indicator],
                    rationale="User account investigation is critical for insider threat and compromised account scenarios"
                ))
                
                recommendations.append(InvestigationRecommendation(
                    priority="MEDIUM",
                    action_type="IAM_REVIEW",
                    title=f"Review IAM permissions for user {indicator}",
                    description=f"Audit Identity and Access Management (IAM) permissions for user {indicator}. Verify if current permissions are appropriate.",
                    indicators=[indicator],
                    rationale="Unauthorized permissions may indicate privilege escalation"
                ))
            
            # Domain-based recommendations
            elif self._is_domain(indicator):
                recommendations.append(InvestigationRecommendation(
                    priority="HIGH",
                    action_type="NETWORK_ISOLATION",
                    title=f"Block communication to domain {indicator}",
                    description=f"Immediately block outbound communication to domain {indicator} at firewall/proxy level",
                    indicators=[indicator],
                    rationale="Malicious domains should be blocked to prevent data exfiltration and C2 communication"
                ))
                
                recommendations.append(InvestigationRecommendation(
                    priority="MEDIUM",
                    action_type="THREAT_INTEL",
                    title=f"Check threat intelligence for domain {indicator}",
                    description=f"Query threat intelligence feeds for domain {indicator} to determine reputation and associated threats",
                    indicators=[indicator],
                    rationale="Domain reputation can indicate C2 infrastructure or malicious hosting"
                ))
        
        # Remove duplicates based on title
        seen_titles = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec.title not in seen_titles:
                seen_titles.add(rec.title)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if a string is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _is_username(self, value: str) -> bool:
        """Heuristic to determine if a value might be a username."""
        # Simple heuristic: usernames typically don't contain dots and are shorter
        if "." in value or len(value) > 50:
            return False
        return not self._is_ip_address(value) and not self._is_domain(value)
    
    def _is_domain(self, value: str) -> bool:
        """Check if a string is a domain name."""
        import re
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, value))

