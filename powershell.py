import base64
import random

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