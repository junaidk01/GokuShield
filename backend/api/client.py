from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime

from models import db, User, API, Scan, Service
from config import VERSION

client_bp = Blueprint('client', __name__)

@client_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get user profile"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404
    
    return jsonify({
        'version': VERSION,
        'profile': user.to_dict()
    }), 200

@client_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404
    
    data = request.get_json()
    
    if data.get('full_name'):
        user.full_name = data['full_name']
    if data.get('company'):
        user.company = data['company']
    
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'message': 'Profile updated successfully',
        'profile': user.to_dict()
    }), 200

@client_bp.route('/apis', methods=['GET'])
@jwt_required()
def list_apis():
    """List user's APIs"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    apis = API.query.filter_by(user_id=user.id).all()
    
    return jsonify({
        'version': VERSION,
        'apis': [api.to_dict() for api in apis]
    }), 200

@client_bp.route('/apis', methods=['POST'])
@jwt_required()
def create_api():
    """Register new API"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('base_url'):
        return jsonify({'error': 'name and base_url required', 'version': VERSION}), 400
    
    api = API(
        user_id=user.id,
        name=data['name'],
        base_url=data['base_url'],
        description=data.get('description', '')
    )
    
    db.session.add(api)
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'message': 'API registered successfully',
        'api': api.to_dict()
    }), 201

@client_bp.route('/apis/<int:api_id>', methods=['GET'])
@jwt_required()
def get_api(api_id):
    """Get API details"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    api = API.query.get(api_id)
    
    if not api or api.user_id != user.id:
        return jsonify({'error': 'API not found', 'version': VERSION}), 404
    
    return jsonify({
        'version': VERSION,
        'api': api.to_dict()
    }), 200

@client_bp.route('/apis/<int:api_id>', methods=['PUT'])
@jwt_required()
def update_api(api_id):
    """Update API"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    api = API.query.get(api_id)
    
    if not api or api.user_id != user.id:
        return jsonify({'error': 'API not found', 'version': VERSION}), 404
    
    data = request.get_json()
    
    if data.get('name'):
        api.name = data['name']
    if data.get('base_url'):
        api.base_url = data['base_url']
    if data.get('description'):
        api.description = data['description']
    if 'is_active' in data:
        api.is_active = data['is_active']
    
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'message': 'API updated successfully',
        'api': api.to_dict()
    }), 200

@client_bp.route('/apis/<int:api_id>', methods=['DELETE'])
@jwt_required()
def delete_api(api_id):
    """Delete API"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    api = API.query.get(api_id)
    
    if not api or api.user_id != user.id:
        return jsonify({'error': 'API not found', 'version': VERSION}), 404
    
    db.session.delete(api)
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'message': 'API deleted successfully'
    }), 200

@client_bp.route('/usage', methods=['GET'])
@jwt_required()
def get_usage():
    """Get user usage statistics"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    from sqlalchemy import func
    from datetime import datetime, timedelta
    
    # Today's scans
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_scans = Scan.query.filter(
        Scan.user_id == user.id,
        Scan.created_at >= today_start
    ).count()
    
    # This month's scans
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_scans = Scan.query.filter(
        Scan.user_id == user.id,
        Scan.created_at >= month_start
    ).count()
    
    # Total scans
    total_scans = Scan.query.filter_by(user_id=user.id).count()
    
    return jsonify({
        'version': VERSION,
        'usage': {
            'plan': user.plan_type.value,
            'today_scans': today_scans,
            'month_scans': month_scans,
            'total_scans': total_scans
        }
    }), 200
