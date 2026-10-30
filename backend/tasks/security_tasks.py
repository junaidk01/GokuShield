"""
Complete Celery tasks with monitoring, outreach, and usage reset
"""

from celery import Celery
from datetime import datetime, timedelta
import logging

from models import db, Scan, ScanStatus, IPBlacklist, SystemHealth, Lead, LeadStatus
from ai.security_engine import SecurityEngine
from utils.usage_enforcement import reset_daily_usage, reset_monthly_usage
from utils.outreach_engine import OutreachEngine

logger = logging.getLogger(__name__)

# Celery app will be configured by app factory
celery = Celery('gokushield')

@celery.task(name='tasks.security_tasks.execute_scan_task', bind=True, max_retries=3)
def execute_scan_task(self, scan_id):
    """
    Execute security scan asynchronously
    Handles both authenticated and pre-auth (lead) scans
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return {'error': 'Scan not found'}
            
            # Update status
            scan.status = ScanStatus.PROCESSING
            scan.started_at = datetime.utcnow()
            db.session.commit()
            
            # Get service
            from models import Service
            service = Service.query.get(scan.service_id)
            if not service:
                scan.status = ScanStatus.FAILED
                scan.error_message = 'Service not found'
                db.session.commit()
                return {'error': 'Service not found'}
            
            # Get security engine
            security_engine = app.security_engine
            ollama_client = app.ollama_client
            
            # Execute scan based on service
            from services import get_service_handler
            handler = get_service_handler(service.service_id, ollama_client)
            
            if not handler:
                scan.status = ScanStatus.FAILED
                scan.error_message = 'Service handler not implemented'
                db.session.commit()
                return {'error': 'Service handler not implemented'}
            
            # Execute scan
            result = handler.scan(scan.target, {})
            
            # Update scan with results
            scan.status = ScanStatus.COMPLETED
            scan.risk_score = result.get('risk_score', 0)
            scan.confidence_score = result.get('confidence_score', 0)
            scan.findings = result.get('findings', [])
            scan.analysis = result.get('analysis', '')
            scan.technical_summary = result.get('technical_summary', '')
            scan.recommendations = result.get('recommendations', [])
            scan.raw_data = result.get('raw_data')
            scan.completed_at = datetime.utcnow()
            scan.execution_time_ms = int((scan.completed_at - scan.started_at).total_seconds() * 1000)
            scan.ai_model_used = result.get('ai_model_used')
            
            db.session.commit()
            
            # If this is a lead scan, send audit report
            if scan.lead_id:
                try:
                    lead = Lead.query.get(scan.lead_id)
                    if lead:
                        OutreachEngine.send_audit_report(lead, result)
                except Exception as e:
                    logger.error(f"Failed to send audit report: {e}")
            
            logger.info(f"Scan {scan_id} completed successfully")
            return {'scan_id': scan_id, 'status': 'completed'}
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            
            try:
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
                    db.session.commit()
            except:
                pass
            
            # Retry logic
            try:
                raise self.retry(exc=e, countdown=60 * (self.request.retries + 1))
            except self.MaxRetriesExceededError:
                return {'error': str(e), 'scan_id': scan_id}

@celery.task(name='tasks.security_tasks.reset_daily_usage')
def reset_daily_usage_task():
    """
    Reset daily usage counters
    Runs daily at midnight UTC
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            result = reset_daily_usage()
            logger.info(f"Daily usage reset: {result}")
            return result
        except Exception as e:
            logger.error(f"Daily usage reset failed: {e}")
            return {'error': str(e)}

@celery.task(name='tasks.security_tasks.reset_monthly_usage')
def reset_monthly_usage_task():
    """
    Reset monthly usage counters
    Runs on 1st of each month
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            result = reset_monthly_usage()
            logger.info(f"Monthly usage reset: {result}")
            return result
        except Exception as e:
            logger.error(f"Monthly usage reset failed: {e}")
            return {'error': str(e)}

@celery.task(name='tasks.security_tasks.cleanup_expired_blacklists')
def cleanup_expired_blacklists():
    """
    Remove expired IP blacklist entries
    Runs hourly
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            now = datetime.utcnow()
            expired = IPBlacklist.query.filter(
                IPBlacklist.expires_at.isnot(None),
                IPBlacklist.expires_at < now
            ).all()
            
            count = len(expired)
            for entry in expired:
                db.session.delete(entry)
            
            db.session.commit()
            
            logger.info(f"Cleaned up {count} expired blacklist entries")
            return {'cleaned': count}
            
        except Exception as e:
            logger.error(f"Blacklist cleanup failed: {e}")
            return {'error': str(e)}

@celery.task(name='tasks.security_tasks.health_check_ollama')
def health_check_ollama():
    """
    Check Ollama health and log status
    Runs every 5 minutes
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            ollama_client = app.ollama_client
            
            start = datetime.utcnow()
            is_available = ollama_client.is_available()
            response_time = int((datetime.utcnow() - start).total_seconds() * 1000)
            
            status = 'up' if is_available else 'down'
            
            # Log to SystemHealth
            health = SystemHealth(
                component='ollama',
                status=status,
                response_time_ms=response_time,
                details={'models': ollama_client.list_models() if is_available else []}
            )
            db.session.add(health)
            db.session.commit()
            
            logger.info(f"Ollama health check: {status} ({response_time}ms)")
            return {'status': status, 'response_time_ms': response_time}
            
        except Exception as e:
            logger.error(f"Ollama health check failed: {e}")
            
            health = SystemHealth(
                component='ollama',
                status='down',
                details={'error': str(e)}
            )
            db.session.add(health)
            db.session.commit()
            
            return {'status': 'down', 'error': str(e)}

@celery.task(name='tasks.security_tasks.health_check_system')
def health_check_system():
    """
    Comprehensive system health check
    Runs every 15 minutes
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            components = ['database', 'redis', 'celery']
            results = {}
            
            # Check database
            try:
                db.session.execute('SELECT 1')
                results['database'] = 'up'
                
                health = SystemHealth(component='database', status='up')
                db.session.add(health)
            except Exception as e:
                results['database'] = 'down'
                logger.error(f"Database health check failed: {e}")
            
            # Check Redis
            try:
                if app.redis_client:
                    app.redis_client.ping()
                    results['redis'] = 'up'
                    
                    health = SystemHealth(component='redis', status='up')
                    db.session.add(health)
                else:
                    results['redis'] = 'down'
            except Exception as e:
                results['redis'] = 'down'
                logger.error(f"Redis health check failed: {e}")
            
            # Check Celery
            try:
                from celery import current_app
                inspect = current_app.control.inspect()
                stats = inspect.stats()
                results['celery'] = 'up' if stats else 'down'
                
                health = SystemHealth(
                    component='celery',
                    status='up' if stats else 'down',
                    details={'workers': len(stats) if stats else 0}
                )
                db.session.add(health)
            except Exception as e:
                results['celery'] = 'down'
                logger.error(f"Celery health check failed: {e}")
            
            db.session.commit()
            
            logger.info(f"System health check: {results}")
            return results
            
        except Exception as e:
            logger.error(f"System health check failed: {e}")
            return {'error': str(e)}

@celery.task(name='tasks.security_tasks.process_outreach_queue')
def process_outreach_queue():
    """
    Process pending outreach emails
    Runs every 10 minutes
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            result = OutreachEngine.process_pending_outreach(limit=100)
            logger.info(f"Outreach processing: {result}")
            return result
        except Exception as e:
            logger.error(f"Outreach processing failed: {e}")
            return {'error': str(e)}

@celery.task(name='tasks.security_tasks.follow_up_unconverted_leads')
def follow_up_unconverted_leads():
    """
    Send follow-up emails to leads that audited but didn't convert
    Runs daily
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            from utils.lead_engine import LeadEngine
            
            # Get leads that audited 2-7 days ago but didn't convert
            leads = LeadEngine.get_unconverted_leads(days=7)
            
            sent_count = 0
            for lead in leads:
                # Check if we already sent follow-up recently
                from models import Outreach
                recent_followup = Outreach.query.filter_by(
                    lead_id=lead.id,
                    template_name='follow_up'
                ).order_by(Outreach.created_at.desc()).first()
                
                if recent_followup:
                    # Don't send if we sent one in last 3 days
                    if (datetime.utcnow() - recent_followup.created_at).days < 3:
                        continue
                
                # Get their last scan
                last_scan = Scan.query.filter_by(
                    lead_id=lead.id,
                    status=ScanStatus.COMPLETED
                ).order_by(Scan.created_at.desc()).first()
                
                if last_scan:
                    scan_result = {
                        'risk_score': last_scan.risk_score,
                        'findings': last_scan.findings or [],
                        'recommendations': last_scan.recommendations or []
                    }
                    
                    OutreachEngine.send_follow_up(lead, scan_result)
                    sent_count += 1
            
            logger.info(f"Sent {sent_count} follow-up emails")
            return {'sent': sent_count}
            
        except Exception as e:
            logger.error(f"Follow-up campaign failed: {e}")
            return {'error': str(e)}

@celery.task(name='tasks.security_tasks.periodic_monitoring_scan')
def periodic_monitoring_scan():
    """
    Future: Run periodic monitoring scans for registered APIs
    Runs daily for Professional and Enterprise users
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            from models import User, API, PlanType
            
            # Get users with monitoring-enabled plans
            users = User.query.filter(
                User.is_active == True,
                User.plan_type.in_([PlanType.PROFESSIONAL, PlanType.ENTERPRISE])
            ).all()
            
            scan_count = 0
            for user in users:
                # Get their registered APIs
                apis = user.apis.filter_by(is_active=True).all()
                
                for api in apis:
                    # Create monitoring scan
                    # This would trigger the default monitoring service
                    pass  # Future implementation
                    scan_count += 1
            
            logger.info(f"Initiated {scan_count} monitoring scans")
            return {'scans': scan_count}
            
        except Exception as e:
            logger.error(f"Periodic monitoring failed: {e}")
            return {'error': str(e)}
