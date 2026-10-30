"""
Business Intelligence & Executive Reporting
===========================================

Executive-level security intelligence with:
- Security posture score tracking
- Risk trend analysis
- Executive summary reports

All features are:
- Read-only
- Derived from existing data
- Lightweight and fast
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class SecurityPostureScoreCalculator:
    """
    Calculates security posture score based on scan results.
    Score: 0-100 (higher is better)
    """
    
    @staticmethod
    def calculate(scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate security posture score
        
        Args:
            scan_results: Recent scan results
            
        Returns:
            Score and breakdown
        """
        
        findings = scan_results.get('findings', [])
        
        if not findings:
            return {
                'score': 100,
                'grade': 'A',
                'status': 'excellent',
                'message': 'No security issues detected'
            }
        
        # Severity weights
        severity_weights = {
            'critical': -25,
            'high': -15,
            'medium': -7,
            'low': -3,
            'info': -1
        }
        
        # Start with perfect score
        score = 100
        
        # Deduct points for each finding
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            weight = severity_weights.get(severity, -5)
            score += weight
        
        # Floor at 0
        score = max(0, score)
        
        # Calculate grade
        if score >= 90:
            grade = 'A'
            status = 'excellent'
        elif score >= 80:
            grade = 'B'
            status = 'good'
        elif score >= 70:
            grade = 'C'
            status = 'fair'
        elif score >= 60:
            grade = 'D'
            status = 'poor'
        else:
            grade = 'F'
            status = 'critical'
        
        # Severity breakdown
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            severity_counts[severity] += 1
        
        return {
            'score': score,
            'grade': grade,
            'status': status,
            'total_findings': len(findings),
            'severity_breakdown': dict(severity_counts),
            'message': SecurityPostureScoreCalculator._get_message(score, severity_counts)
        }
    
    @staticmethod
    def _get_message(score: int, severity_counts: Dict[str, int]) -> str:
        """Get contextual message based on score"""
        
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        
        if score >= 90:
            return "Your security posture is excellent. Continue regular monitoring."
        elif score >= 80:
            return "Your security posture is good with minor issues to address."
        elif critical > 0:
            return f"URGENT: {critical} critical vulnerabilities require immediate attention."
        elif high > 0:
            return f"WARNING: {high} high-severity issues need prompt remediation."
        else:
            return "Your security posture needs improvement. Review all findings."


class RiskTrendAnalyzer:
    """Analyzes security risk trends over time"""
    
    @staticmethod
    def analyze(scan_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze risk trends from scan history
        
        Args:
            scan_history: List of historical scans (most recent first)
            
        Returns:
            Trend analysis with insights
        """
        
        if len(scan_history) < 2:
            return {
                'trend': 'insufficient_data',
                'message': 'Need at least 2 scans for trend analysis'
            }
        
        # Calculate scores for each scan
        scores = []
        dates = []
        
        for scan in scan_history:
            posture = SecurityPostureScoreCalculator.calculate(scan)
            scores.append(posture['score'])
            dates.append(scan.get('created_at', datetime.utcnow().isoformat()))
        
        # Determine trend
        recent_score = scores[0]
        previous_score = scores[1]
        score_change = recent_score - previous_score
        
        if score_change > 10:
            trend = 'improving'
            trend_emoji = '📈'
        elif score_change > 0:
            trend = 'slightly_improving'
            trend_emoji = '↗️'
        elif score_change < -10:
            trend = 'degrading'
            trend_emoji = '📉'
        elif score_change < 0:
            trend = 'slightly_degrading'
            trend_emoji = '↘️'
        else:
            trend = 'stable'
            trend_emoji = '➡️'
        
        # Average score
        avg_score = sum(scores) / len(scores)
        
        # Volatility (score variance)
        variance = sum((s - avg_score) ** 2 for s in scores) / len(scores)
        volatility = 'high' if variance > 100 else 'medium' if variance > 25 else 'low'
        
        return {
            'trend': trend,
            'trend_emoji': trend_emoji,
            'current_score': recent_score,
            'previous_score': previous_score,
            'score_change': score_change,
            'average_score': round(avg_score, 2),
            'volatility': volatility,
            'data_points': len(scores),
            'scores': scores,
            'dates': dates,
            'message': RiskTrendAnalyzer._get_trend_message(trend, score_change, volatility)
        }
    
    @staticmethod
    def _get_trend_message(trend: str, score_change: float, volatility: str) -> str:
        """Generate trend message"""
        
        if trend == 'improving':
            return f"Security posture is improving (+{score_change:.1f} points). Keep up the good work!"
        elif trend == 'slightly_improving':
            return f"Security posture shows slight improvement (+{score_change:.1f} points)."
        elif trend == 'degrading':
            return f"WARNING: Security posture is degrading ({score_change:.1f} points). Immediate action needed."
        elif trend == 'slightly_degrading':
            return f"Security posture shows slight decline ({score_change:.1f} points). Monitor closely."
        else:
            return "Security posture remains stable. Continue regular assessments."


class ExecutiveReport:
    """Generates executive-level security reports"""
    
    @staticmethod
    def generate(
        current_scan: Dict[str, Any],
        scan_history: List[Dict[str, Any]],
        user_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate executive summary report
        
        Args:
            current_scan: Latest scan results
            scan_history: Historical scans
            user_info: User/organization information (optional)
            
        Returns:
            Executive report
        """
        
        # Calculate posture score
        posture = SecurityPostureScoreCalculator.calculate(current_scan)
        
        # Analyze trends
        all_scans = [current_scan] + scan_history
        trends = RiskTrendAnalyzer.analyze(all_scans)
        
        # Top risks
        findings = current_scan.get('findings', [])
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        high_findings = [f for f in findings if f.get('severity') == 'high']
        
        top_risks = (critical_findings + high_findings)[:5]
        
        # Compliance summary (if available)
        compliance_status = current_scan.get('compliance', {})
        
        # Key metrics
        metrics = {
            'total_scans_performed': len(all_scans),
            'last_scan_date': current_scan.get('created_at', datetime.utcnow().isoformat()),
            'findings_remediated': ExecutiveReport._calculate_remediated(all_scans),
            'average_resolution_time': ExecutiveReport._calculate_avg_resolution_time(all_scans)
        }
        
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'report_period': {
                'start': all_scans[-1].get('created_at') if all_scans else None,
                'end': all_scans[0].get('created_at') if all_scans else None
            },
            'organization': user_info.get('organization', 'N/A') if user_info else 'N/A',
            'executive_summary': {
                'security_posture': posture,
                'risk_trend': trends,
                'key_metrics': metrics
            },
            'top_risks': [
                {
                    'title': r.get('title', 'Unknown'),
                    'severity': r.get('severity', 'medium'),
                    'impact': r.get('description', 'No description')[:200]
                }
                for r in top_risks
            ],
            'compliance_summary': compliance_status,
            'recommendations': ExecutiveReport._generate_recommendations(posture, trends, critical_findings)
        }
        
        return report
    
    @staticmethod
    def _calculate_remediated(scans: List[Dict[str, Any]]) -> int:
        """Calculate number of findings remediated"""
        if len(scans) < 2:
            return 0
            
        old_findings = len(scans[-1].get('findings', []))
        new_findings = len(scans[0].get('findings', []))
        
        return max(0, old_findings - new_findings)
    
    @staticmethod
    def _calculate_avg_resolution_time(scans: List[Dict[str, Any]]) -> str:
        """Calculate average resolution time"""
        # Placeholder - would need tracking data
        return "Not available"
    
    @staticmethod
    def _generate_recommendations(
        posture: Dict[str, Any],
        trends: Dict[str, Any],
        critical_findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate executive recommendations"""
        
        recommendations = []
        
        if critical_findings:
            recommendations.append(
                f"PRIORITY: Address {len(critical_findings)} critical vulnerabilities immediately"
            )
        
        if posture['score'] < 70:
            recommendations.append(
                "Implement comprehensive security improvement plan"
            )
        
        if trends.get('trend') == 'degrading':
            recommendations.append(
                "Security posture is declining - conduct security review"
            )
        
        if posture['score'] >= 90:
            recommendations.append(
                "Maintain current security practices and continue regular monitoring"
            )
        else:
            recommendations.append(
                "Schedule regular security assessments (weekly recommended)"
            )
        
        recommendations.append(
            "Consider implementing continuous security monitoring"
        )
        
        return recommendations


def generate_dashboard_data(user_id: int) -> Dict[str, Any]:
    """
    Generate dashboard data for executive view
    
    Args:
        user_id: User ID
        
    Returns:
        Dashboard data
    """
    from models import Scan, User
    
    # Get recent scans
    scans = Scan.query.filter_by(user_id=user_id).order_by(
        Scan.created_at.desc()
    ).limit(10).all()
    
    if not scans:
        return {
            'message': 'No scans available',
            'posture': {'score': 0, 'grade': 'N/A'},
            'trends': {'trend': 'no_data'}
        }
    
    # Convert to dict format
    scan_dicts = [s.to_dict() for s in scans]
    
    # Generate report
    user = User.query.get(user_id)
    user_info = {'organization': user.organization if hasattr(user, 'organization') else 'N/A'}
    
    report = ExecutiveReport.generate(
        current_scan=scan_dicts[0],
        scan_history=scan_dicts[1:],
        user_info=user_info
    )
    
    return report
