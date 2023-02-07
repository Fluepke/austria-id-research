#!/bin/env python

import requests
import random
from lxml import etree as ET
from base64 import b64decode, b64encode

SALT = b'anugBygKOMdtx9AJbhrN5b1sObQ5AyISZbKf1hxiPA73IYFc9I1QggKwgVaO48vsAM75MLkXPm75gNaZxUdDeWHI1aYYOdJxEkE55DgqjzMSv44GgvMIDk6NWy1CSHyHURSRaQjMn6NdaXpa0xdlfdrxOcQx3ajHNqqCHUPJV7BkOtHJaV2rPmhWzEOlD9yFCUWRDenT1mwumnuxbisDqOWtlPWQ293zjWZEV0Wm0eXA1oC7Cz6ZkV0c2f4QIhasWGbm3H1p0Q308J70G666JkaZ2hkmI4AQeAjcnWCuIlSIqGBg5aEQuyjs3jeb5EPtT2xXUVpVew02IIF8X9OePuO5VOyN8WIPtKN1Wxt6qYznjMkKY6qVAwHt9FsKTBo5AHbv02jARUFWzIf5WR3OWL61maEo6rNOl1OjUA0UlSNgJHDNaLwrFZD3AguMoGB7X8hBDCYfapywZ365c3hSZcieQ9QGQWdYXJYWEk9I2ZXf7729l2ZKGbqfiwnjSRNw7ofZEd8I0WAS2reVz34MLAK5oEE0LINjphBWVged2XfEXY95orEfQIIBWdrogtqjOLIhtm6wYMJR27Y8jmADlGOzbC7egGbv5frNyQ36pmgaRwqZgYlZSPAjo8mbZuKUsrRGBQACIv99odb8w4idBawvMs0RNGlH2MEcsgXxEkLf7HNyFNRjdNt6tn2cBCsrVl9YiYZfbcSciMPdor03Y0uv9mZs2nCPcTi4rp4tc4WyZB3vY9vvHRTFNqrfhC7awHmMJNZXPBz3oQmZ02ZYtZhXQ8K6AFb2oLqks8M06MVvlaYTbB9RVQbxWU4yG7N4aiyl02A5D78v6GYQuQJGf2E4ZQk9abaHujqDpWWCfBAhKjvHXnlpPa6V7Llj5fkDQJgA5DecBVk3UVn9Yn6ZAg57VUyy0JgxTHKcnUnEDEOUiBkBAHD95cRaOA4YdvOrDHEWcwBZKlutMmjWFhUW09M9wtJp9dr6CimpkBlgHzYVwKB6hCUUwh6pQyCF'
ATRUST_VERSION_NAME = "2.9.11"

def minifyXML(xml):
    return ET.tostring(ET.XML(xml, ET.XMLParser(remove_blank_text=True))).decode()

headers = {
    'Host': 'api.a-trust.at',
    'User-Agent': 'Handy-Signatur-App/2.9.11',
    'Connection': 'Keep-Alive',
}

command = """
    <Command>
      <Version>0</Version>
      <Type>0</Type>
      <FriendlyName>emulator64_x86_64_arm64</FriendlyName>
      <HostAppId>857f87de-81a6-44f4-8e70-03d7b1911cfa</HostAppId>
    </Command>"""

nonce = random.randint(0, 2**64)

data = {
    'command': minifyXML(command),
    'nonce': nonce.to_bytes(8, 'little').hex().upper(),
}

response = requests.post('https://api.a-trust.at/WebTanApp/AppAktivierungStart.ashx', headers=headers, data=data, verify='a-sign-SSL-07.pem')

resp = b64decode(ET.XML(response.text).xpath("/tanapp/b64Response/text()")[0])
data = ET.XML(resp.decode())

session_id = data.xpath("/tanapp/sessionid/text()")[0]
app_token = data.xpath("/tanapp/apptoken/text()")[0]
g = int(data.xpath("/tanapp/response/Response/G/text()")[0])
p = int(data.xpath("/tanapp/response/Response/P/text()")[0])
pubkeyA = int(data.xpath("/tanapp/response/Response/PubKeyA/text()")[0])

from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers, DHPublicNumbers

parameter_numbers = DHParameterNumbers(p=p, g=g)
params = parameter_numbers.parameters()
privkey = params.generate_private_key()
shared_secret = pow(pubkeyA, privkey.private_numbers().x, p)
shared_secret = str(shared_secret).encode()

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=25000
)

encryption_key = kdf.derive(shared_secret)

system_info_xml = f"""
<app version="1">
    <AppVersion>{ATRUST_VERSION_NAME}</AppVersion>
    <OS>Android</OS>
    <OSVersion>31</OSVersion>
</app>"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

iv = os.urandom(16)
encryptor = Cipher(algorithms.AES(encryption_key), modes.GCM(iv)).encryptor()

pubkey_b = str(privkey.public_key().public_numbers().y)
mini = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n" + minifyXML(system_info_xml.encode())

enc_init_data = b64encode(
    encryptor.update(
        mini.encode()
    ) + encryptor.finalize() + encryptor.tag
).decode()

from urllib.parse import quote_plus

command = f"""
    <Command>
      <Version>0</Version>
      <Type>1</Type>
      <PubKeyB>{ pubkey_b }</PubKeyB>
      <EncInitDataA>{ quote_plus(enc_init_data) }</EncInitDataA>
      <IV>{ quote_plus(b64encode(iv).decode()) }</IV>
    </Command>"""

nonce = random.randint(0, 2**64)
postData = f"AppToken={app_token}&Command={minifyXML(command)}&nonce={random.randbytes(8).hex().upper()}"

params = {
    'step': '1',
    'sid': session_id,
}

headers = {
    'Host': 'api.a-trust.at',
    'User-Agent': 'Handy-Signatur-App/2.9.11',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Connection': 'Keep-Alive',
    # 'Accept-Encoding': 'gzip, deflate',
    # 'Content-Length': '1074',
}

response = requests.post(
    'https://api.a-trust.at/WebTanApp/AppAktivierungCommand.ashx',
    params=params,
    headers=headers,
    data=postData,
    verify='a-sign-SSL-07.pem',
)

print(response)
print(response.headers)
print(response.text)
