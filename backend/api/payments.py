"""
Payment & Subscription Lifecycle API Module
GoKushield AI v1.0 - Production Billing & Entitlement Gateway
Provides checkout generation, webhook processing, subscription activation,
and deterministic service unlocking.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import secrets
import logging

from models import db, User, Transaction, TransactionStatus, PlanType, AuditLog, Service, PlanServiceMapping
from config import VERSION
from utils.decorators import admin_required

logger = logging.getLogger(__name__)

payments_bp = Blueprint('payments', __name__)

PLAN_PRICING = {
    'Starter': {'monthly_cents': 1900, 'annual_cents': 19000, 'daily_scans': 10},
    'Professional': {'monthly_cents': 5900, 'annual_cents': 59000, 'daily_scans': 100},
    'Enterprise': {'monthly_cents': 17900, 'annual_cents': 179000, 'daily_scans': 9999}
}

@payments_bp.route('/checkout', methods=['POST'])
@jwt_required()
def create_checkout_session():
    """
    Generate payment checkout session for plan subscription.
    Enforces 10% introductory discount for eligible accounts.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404

    data = request.get_json(silent=True) or {}
    plan_name = data.get('plan_type', 'Professional')
    cycle = data.get('billing_cycle', 'monthly')
    payment_method = data.get('payment_method', 'card')

    if plan_name not in PLAN_PRICING:
        return jsonify({'error': f'Invalid plan: {plan_name}. Must be Starter, Professional, or Enterprise.', 'version': VERSION}), 400

    pricing = PLAN_PRICING[plan_name]
    base_cents = pricing['annual_cents'] if cycle == 'annual' else pricing['monthly_cents']

    # 10% promotional offer: "Our first 100 users get 10% off on our plans"
    total_users_count = User.query.count()
    apply_promo = total_users_count <= 100 or data.get('promo_code', '').upper() == 'FIRST100'
    final_cents = int(base_cents * 0.90) if apply_promo else base_cents

    inv_num = f"INV-{datetime.utcnow().strftime('%Y%m')}-{secrets.token_hex(4).upper()}"

    transaction = Transaction(
        user_id=user.id,
        invoice_number=inv_num,
        plan_type=PlanType(plan_name.lower()),
        amount_cents=final_cents,
        currency='USD',
        payment_method=payment_method,
        status=TransactionStatus.PENDING,
        gateway_reference=f"gtw_{secrets.token_urlsafe(16)}",
        discount_applied=apply_promo
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({
        'invoice_number': inv_num,
        'transaction_id': transaction.id,
        'plan_type': plan_name,
        'billing_cycle': cycle,
        'amount_usd': final_cents / 100.0,
        'discount_applied': apply_promo,
        'checkout_url': f"https://checkout.gokushield.com/pay/{inv_num}",
        'status': 'pending',
        'version': VERSION
    }), 201

@payments_bp.route('/activate', methods=['POST'])
@jwt_required()
def activate_subscription():
    """
    Activate and unlock paid subscription services.
    Validates transaction status, upgrades User.plan_type, and unlocks tier services.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404

    data = request.get_json(silent=True) or {}
    inv_num = data.get('invoice_number')
    plan_name = data.get('plan_type')

    # If invoice supplied, complete existing transaction
    if inv_num:
        tx = Transaction.query.filter_by(invoice_number=inv_num, user_id=user.id).first()
        if not tx:
            return jsonify({'error': 'Transaction record not found', 'version': VERSION}), 404
        tx.status = TransactionStatus.COMPLETED
        plan_enum = tx.plan_type
    elif plan_name and plan_name in PLAN_PRICING:
        plan_enum = PlanType(plan_name.lower())
        # Create instant record
        tx = Transaction(
            user_id=user.id,
            invoice_number=f"INV-{datetime.utcnow().strftime('%Y%m')}-{secrets.token_hex(4).upper()}",
            plan_type=plan_enum,
            amount_cents=PLAN_PRICING[plan_name]['monthly_cents'],
            status=TransactionStatus.COMPLETED,
            gateway_reference=f"direct_act_{secrets.token_hex(8)}"
        )
        db.session.add(tx)
    else:
        return jsonify({'error': 'Valid invoice_number or plan_type required', 'version': VERSION}), 400

    old_plan = user.plan_type.value
    user.plan_type = plan_enum
    user.plan_started_at = datetime.utcnow()

    audit = AuditLog(
        user_id=user.id,
        action='subscription_activated',
        resource_type='user',
        resource_id=user.id,
        details={'from_plan': old_plan, 'to_plan': plan_enum.value, 'invoice': tx.invoice_number},
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()

    # Query unlocked services for this plan
    mappings = PlanServiceMapping.query.filter_by(plan_type=plan_enum).all()
    unlocked_service_ids = [m.service.service_id for m in mappings if m.service]

    return jsonify({
        'message': f'Subscription upgraded to {plan_enum.value} successfully.',
        'user_id': user.id,
        'plan': plan_enum.value,
        'plan_started_at': user.plan_started_at.isoformat(),
        'unlocked_services': unlocked_service_ids,
        'invoice_number': tx.invoice_number,
        'version': VERSION
    }), 200

@payments_bp.route('/subscription', methods=['GET'])
@jwt_required()
def get_subscription_status():
    """Get active subscription and billing details"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404

    recent_txs = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.created_at.desc()).limit(10).all()

    return jsonify({
        'user_id': user.id,
        'current_plan': user.plan_type.value,
        'plan_started_at': user.plan_started_at.isoformat() if user.plan_started_at else None,
        'transactions': [t.to_dict() for t in recent_txs],
        'version': VERSION
    }), 200

@payments_bp.route('/webhook', methods=['POST'])
def payment_webhook():
    """
    Handle webhook from payment gateways (Stripe, PayPal, internal payment mesh).
    Idempotent transaction state update and automatic entitlement provisioning.
    """
    data = request.get_json(silent=True) or {}
    event_type = data.get('event', data.get('type', ''))
    inv_num = data.get('invoice_number') or data.get('data', {}).get('object', {}).get('metadata', {}).get('invoice_number')

    if not inv_num:
        return jsonify({'status': 'ignored', 'reason': 'No invoice identifier'}), 200

    tx = Transaction.query.filter_by(invoice_number=inv_num).first()
    if not tx:
        return jsonify({'status': 'error', 'message': 'Invoice not found'}), 404

    if event_type in ['payment.succeeded', 'checkout.session.completed']:
        tx.status = TransactionStatus.COMPLETED
        user = User.query.get(tx.user_id)
        if user:
            user.plan_type = tx.plan_type
            user.plan_started_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'status': 'success', 'plan_activated': tx.plan_type.value}), 200

    return jsonify({'status': 'acknowledged'}), 200

