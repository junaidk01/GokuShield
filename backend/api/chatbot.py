from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from datetime import datetime
import json

from models import db, User
from config import VERSION
from ai.chatbot_engine import ChatbotEngine

chatbot_bp = Blueprint('chatbot', __name__)

# Initialize chatbot engine
chatbot_engine = None

def get_chatbot_engine():
    global chatbot_engine
    if chatbot_engine is None:
        from flask import current_app
        chatbot_engine = ChatbotEngine(current_app.ollama_client)
    return chatbot_engine

@chatbot_bp.route('/chat', methods=['POST'])
def chat():
    """Chat with AI assistant (public endpoint with optional auth)"""
    
    # Optional authentication
    user_id = None
    user_context = {}
    
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            user = User.query.get(user_id)
            if user:
                user_context = {
                    'plan': user.plan_type.value,
                    'email': user.email
                }
    except:
        pass
    
    data = request.get_json()
    
    if not data or not data.get('message'):
        return jsonify({'error': 'message required', 'version': VERSION}), 400
    
    message = data['message']
    conversation_history = data.get('history', [])
    
    engine = get_chatbot_engine()
    
    try:
        response = engine.chat(
            message=message,
            history=conversation_history,
            user_context=user_context
        )
        
        return jsonify({
            'version': VERSION,
            'response': response['message'],
            'suggestions': response.get('suggestions', []),
            'requires_auth': response.get('requires_auth', False)
        }), 200
    except Exception as e:
        return jsonify({
            'version': VERSION,
            'error': 'Chat service temporarily unavailable',
            'message': 'Our AI assistant is currently offline. Please try again later.'
        }), 503

@chatbot_bp.route('/explain-scan', methods=['POST'])
@jwt_required()
def explain_scan():
    """Get AI explanation of scan results"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404
    
    data = request.get_json()
    
    if not data or not data.get('scan_id'):
        return jsonify({'error': 'scan_id required', 'version': VERSION}), 400
    
    from models import Scan
    scan = Scan.query.get(data['scan_id'])
    
    if not scan or scan.user_id != user.id:
        return jsonify({'error': 'Scan not found', 'version': VERSION}), 404
    
    engine = get_chatbot_engine()
    
    explanation = engine.explain_scan_results(scan.to_dict())
    
    return jsonify({
        'version': VERSION,
        'explanation': explanation
    }), 200

@chatbot_bp.route('/security-advice', methods=['POST'])
def security_advice():
    """Get general security advice from AI"""
    data = request.get_json()
    
    if not data or not data.get('question'):
        return jsonify({'error': 'question required', 'version': VERSION}), 400
    
    engine = get_chatbot_engine()
    
    advice = engine.get_security_advice(data['question'])
    
    return jsonify({
        'version': VERSION,
        'advice': advice
    }), 200
