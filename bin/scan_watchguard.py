import sys
import logging
import logging.handlers
import os
import socket
import json
import argparse
import requests
from datetime import datetime, timedelta
from time import time
import base64


IN_SPLUNK = False

panda_cloud = "api.deu.cloud.watchguard.com"
PATH = os.environ['SPLUNK_HOME'] + "/etc/apps/scan_watchguard"
access_token_file = PATH + "/tmp/.access_token.json"
MAX_TIME_SCAN = 3600

settings = {
    "api_token_path": "https://" + panda_cloud + "/oauth/token",
    "fmw_path": "https://" + panda_cloud + "/rest/aether-endpoint-security/aether-mgmt",
    "api_path": "/api/v1/accounts",
    "WG_access_token": ""
}


def setup_logger(level):
    global logger
    logger = logging.getLogger("scan_watchguard_alert")
    logger.propagate = False
    logger.setLevel(level)
    file_handler = logging.handlers.RotatingFileHandler(
        os.environ['SPLUNK_HOME'] + '/var/log/splunk/scan_watchguard_alert.log',
        maxBytes = 250000000,
        backupCount = 5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

logger = setup_logger(logging.INFO)



def log_message(s):
    if IN_SPLUNK:
        logger.info(s)
    else:
        print(s)



def parse_args():
    global config
    global event_result

    # for debugging
    config = {
        'WG_account_id': '',
        'WatchGuard_API_Key': '',
        'username': '',
        'password': '',
        'task_name': 'test task',
        'task_description': 'test task description',
        'scan_scope': '0',
        'specified_items_to_scan': '',
        'detect_hacking_tools': '0',
        'scan_compressed_files': '1',
        'detect_suspicious_files': '1',
        'apply_exclusions_on_scan': '0',
        'extensions_to_exclude': '',
        'files_to_exclude': '',
        'folders_to_exclude': '',
        'execution_window_expiration': '7:00:00:00'
    }
    event_result = {
        'c_ip': '198.18.0.0',
        'cs_host': 'example.com'
    }
    #log_message(config)



def parse_stdin():
    global config
    global event_result
    payload = json.loads(sys.stdin.read())
    config = payload.get("configuration")
    event_result = payload.get('result')
    #log_message(config)



def request_token():
    global token_data
    url = settings["api_token_path"]
    payload='grant_type=client_credentials'
    up_encoded = base64.b64encode((config['username'] + ":" + config['password']).encode('ascii')).decode('ascii')
    headers = {
        'Authorization': "Basic " + up_encoded,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'python-requests/2.27.1'
    }
    try:
        response = requests.post(url, headers=headers, data=payload)
        token_data = response.json()
        present = datetime.now()
        incremento = token_data['expires_in']
        expires_in = present + timedelta(seconds = incremento)
        token_data['expires_in'] = expires_in.strftime('%y/%m/%d %H:%M:%S')
        return True
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)



def obtain_token():
    global token_data
    if os.path.exists(access_token_file):
        with open(access_token_file, "r") as f:
            token_data = json.load(f)
            present = datetime.now()
            if  datetime.strptime(token_data['expires_in'], '%y/%m/%d %H:%M:%S') > present:
                return True

    if request_token():
        with open(access_token_file, "w") as f:
            json.dump(token_data, f)
        return True

    return False




def resolve_name():
    tmp = ""
    try:
        tmp = socket.gethostbyaddr(event_result["c_ip"])
        tmp = tmp[0].split('.')[0]
    except socket.herror:
        tmp = event_result["c_ip"]
    return tmp



def search_computer():
    global task_name
    global device_id
    global search
    
    token_type = token_data['token_type']
    access_token = token_data['access_token']
    search = resolve_name()
    task_name = config.get('task_name') + ": " + event_result.get('cs_host') + " " + search
    url = settings['fmw_path'] + settings['api_path'] + "/" + config['WG_account_id'] + "/devices?$search=" + search
    payload={}
    headers = {
        'Watchguard-API-key': config["WatchGuard_API_Key"],
        'Authorization': token_type + " " + access_token
    }
    try:
        response = requests.request("GET", url, headers=headers, data=payload)
        response_json = response.json()
        device_id = response_json['data'][0]['device_id'] # one by one
        return True
    except IndexError:
        return False
    except KeyError:
        return False
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)



def computer_locked():
    filename = PATH + "/tmp/" + search + ".json"
    if os.path.exists(filename):
        time_mod = time() - os.path.getmtime(filename)
        if time_mod < MAX_TIME_SCAN:
            return True
    return False


def computer_lock(msg):
    filename = PATH + "/tmp/" + search + ".json"
    with open(filename, "w") as f:
        f.write(msg)
        f.close()


def scan_computer():
    log_message(task_name)
    if computer_locked():
        log_message("Recently scanned, skipping")
        return
    url = settings['fmw_path'] + settings['api_path'] + "/" + config['WG_account_id'] + "/immediatescan?device_ids=" + device_id
    time_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = json.dumps({
        "device_ids": [ device_id ],
        "task_name": time_text + " " + task_name,
        "task_description": config.get('task_description'),
        "scan_scope": config.get('scan_scope'),
        "specified_items_to_scan": config.get('specified_items_to_scan'),
        "detect_hacking_tools": config.get('detect_hacking_tools'),
        "detect_suspicious": config.get('detect_suspicious_files'),
        "scan_compressed_files": config.get('scan_compressed_files'),
        "apply_exclusions_on_scan": config.get('apply_exclusions_on_scan'),
        "extensions_to_exclude": config.get('extensions_to_exclude'),
        "files_to_exclude": config.get('files_to_exclude'),
        "folders_to_exclude": config.get('folders_to_exclude'),
        "execution_window_expiration": config.get('execution_window_expiration')
    })
    headers = {
        'Watchguard-API-key': config["WatchGuard_API_Key"],
        'Authorization': token_data['token_type'] + " " + token_data['access_token'],
        "Content-Type": "application/json"
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    log_message(response.text)
    computer_lock(response.text)




def main():
    global IN_SPLUNK
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        IN_SPLUNK = True
        parse_stdin()
    else:
        IN_SPLUNK = False
        parse_args()
        
    if obtain_token():
        if search_computer():
            scan_computer()
        else:
            log_message("Computer not found")
    else:
        log_message("Cannot obtain token")



if __name__ == "__main__":
    main()
