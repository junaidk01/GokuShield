"""
Service module initialization
Provides service handler registry and factory
"""

from services.free_security_audit_service import FreeSecurityAuditService
from services.adaptive_authentication_service import AdaptiveAuthenticationService
from services.adaptive_learning_systems_service import AdaptiveLearningSystemsService
from services.api_security_score_service import ApiSecurityScoreService
from services.automated_security_orchestration_service import AutomatedSecurityOrchestrationService
from services.autonomous_defense_evolution_service import AutonomousDefenseEvolutionService
from services.compliance_regulations_service import ComplianceRegulationsService
from services.data_breach_prevention_service import DataBreachPreventionService
from services.evolutionary_threat_intelligence_service import EvolutionaryThreatIntelligenceService
from services.neural_network_evolution_service import NeuralNetworkEvolutionService
from services.owasp_api_security_service import OwaspApiSecurityService
from services.performance_optimization_service import PerformanceOptimizationService
from services.rate_limiting_ddos_service import RateLimitingDdosService
from services.self_learning_ai_defense_service import SelfLearningAiDefenseService
from services.zero_day_vulnerability_service import ZeroDayVulnerabilityService

# Service registry mapping service_id to handler class
SERVICE_REGISTRY = {
    'free_security_audit': FreeSecurityAuditService,
    'adaptive_authentication': AdaptiveAuthenticationService,
    'adaptive_learning_systems': AdaptiveLearningSystemsService,
    'api_security_score': ApiSecurityScoreService,
    'automated_security_orchestration': AutomatedSecurityOrchestrationService,
    'autonomous_defense_evolution': AutonomousDefenseEvolutionService,
    'compliance_regulations': ComplianceRegulationsService,
    'data_breach_prevention': DataBreachPreventionService,
    'evolutionary_threat_intelligence': EvolutionaryThreatIntelligenceService,
    'neural_network_evolution': NeuralNetworkEvolutionService,
    'owasp_api_security': OwaspApiSecurityService,
    'performance_optimization': PerformanceOptimizationService,
    'rate_limiting_ddos': RateLimitingDdosService,
    'self_learning_ai_defense': SelfLearningAiDefenseService,
    'zero_day_vulnerability': ZeroDayVulnerabilityService
}

def get_service_handler(service_id, ollama_client=None):
    """
    Get service handler instance by service_id
    
    Args:
        service_id: Service identifier
        ollama_client: Ollama client instance (required)
    
    Returns:
        Service handler instance or None if not found
    """
    handler_class = SERVICE_REGISTRY.get(service_id)
    if handler_class:
        return handler_class(ollama_client=ollama_client)
    return None

def list_available_services():
    """Get list of all available service IDs"""
    return list(SERVICE_REGISTRY.keys())

__all__ = [
    'get_service_handler',
    'list_available_services',
    'SERVICE_REGISTRY'
]
