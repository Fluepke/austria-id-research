#!/bin/env python

# Example code to retrieve a Binding Certificate "Bindungs-Zertifikat" for use with the eAusweise / Digitales Amt
# Usage: python3 ./demo.py
# Dependencies: cryptography
#
# Yes, the code is terrible
# I suggest you to unomment the proxies to inspect and study responses / replies with some MITM proxy (like burp) 

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from uuid import uuid4
from base64 import b64decode,b64encode,urlsafe_b64encode
import requests
import json
import time
from os.path import isfile

proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
}

verify = 'burp.pem'

digitalesAmtFiles = [
    "digitales-amt-binding-uuid.txt",
    "digitales-amt-cert.pem",
    "digitales-amt-csr.pem",
    "digitales-amt-key.pem"
]

if any([not isfile(f) for f in digitalesAmtFiles]):
    print("Need to perform initial registration!")
    headers = {
        'Host': 'eid.oesterreich.gv.at',
        'Accept': 'application/json',
        'Accept-Language': 'en-US',
        'X-Requested-With': 'Android Binding Library 2.0.14',
        'User-Agent': 'okhttp/4.9.3',
        'Connection': 'close',
    }
    
    params = {
        'os': 'android',
        'packageName': 'at.gv.oe.app',
    }
    
    sess = requests.Session()
    response = sess.get('https://eid.oesterreich.gv.at/bindingservice/params', params=params, headers=headers, proxies=proxies, verify=verify)
    s = response.text.split(".")[1]
    claims = json.loads(b64decode(s + '=' * (-len(s) % 4)).decode())
    
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )
    
    # Write our key to disk for safe keeping
    with open("digitales-amt-key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # Generate a CSR
    x509_name = x509.Name.from_rfc4514_string(claims['subject'])
    CN = x509_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    O = x509_name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    C = x509_name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    	# The order matters!
        x509.NameAttribute(NameOID.COMMON_NAME, CN),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, O),
        x509.NameAttribute(NameOID.COUNTRY_NAME, C),
    # Sign the CSR with our private key.
    ])).sign(private_key, hashes.SHA256())
    
    # Write our CSR out to disk.
    with open("digitales-amt-csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    
    previousAppId = str(uuid4())
    currentAppId = str(uuid4())
    
    json_data = {'params': response.text,
        'deviceInfo': {
            'osType': 'android',
            'packageName': 'at.gv.oe.app',
            'osVersion': '12',
            'patchLevel': '2021-12-01',
            'deviceName': 'emulator64_x86_64_arm64',
        },
        'previousAppId':  previousAppId,
        'currentAppId':  currentAppId,
        'csr': b64encode(csr.public_bytes(serialization.Encoding.DER)).decode(),
        'attestationChain': [
            # Here we fool the backend, because we're re-using a completely different attestation ;)
            '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',
        ],
    }
    
    
    bindingUuid = claims['postUrl'][len('binding/'):]
    
    headers = {
        'Host': 'eid.oesterreich.gv.at',
        'Accept': 'application/json',
        'Accept-Language': 'en-US',
        'X-Requested-With': 'Android Binding Library 2.0.14',
        'Content-Type': 'application/json; charset=utf-8',
        'User-Agent': 'okhttp/4.9.3',
        'Connection': 'close',
    }
    
    url = 'https://eid.oesterreich.gv.at/bindingservice/' + claims['postUrl']
    
    response = sess.post(url,
        headers=headers,
        json=json_data,
        verify=verify,
        proxies=proxies,
        allow_redirects=False,
    )
    
    headers = {
        'Host': 'eid.oesterreich.gv.at',
        'Accept': 'application/json',
        'Sl2clienttype': 'nativeApp',
        'X-Moa-Vda': '0',
        'Accept-Language': 'de',
        'User-Agent': 'okhttp/4.9.3',
        'Connection': 'close',
    }
    
    redirect = response.headers['location']
    response = sess.get(redirect,
        headers=headers,
        verify=verify,
        proxies=proxies,
        allow_redirects=False,
    )
    
    resp = json.loads(response.text)
    pendingid = resp['params']['pendingid']
    pendingReqID = resp['params']['pendingReqID']
    
    headers = {
        'Host': 'eid.oesterreich.gv.at',
        'Accept': 'application/json',
        'Sl2clienttype': 'nativeApp',
        'X-Moa-Vda': '0',
        'Accept-Language': 'de',
        'User-Agent': 'okhttp/4.9.3',
        'Connection': 'close',
    }
    
    data = {
        'pendingid': pendingid,
        'pendingReqID': pendingReqID,
        'useeIDAS': 'true',
    }
    
    response = sess.post(
        'https://eid.oesterreich.gv.at/authHandler/public/secure/process',
        headers=headers,
        data=data,
        verify=verify,
        proxies=proxies,
        allow_redirects=False,
    )
    
    resp = json.loads(response.text)
    pendingid = resp['params']['pendingid']
    pendingReqID = resp['params']['pendingReqID']
    
    
    print("Open https://oesterreich.gv.at/eu-login in a browser")
    print("And enter QR Code contents:")
    eidasWebSynch = input()
    print("In the browser, performing login using eIDAS")
    
    headers = {
        'Host': 'eid.oesterreich.gv.at',
        'Accept': 'application/json',
        'Sl2clienttype': 'nativeApp',
        'X-Moa-Vda': '0',
        'Accept-Language': 'de',
        'User-Agent': 'okhttp/4.9.3',
        'Connection': 'close',
    }
    
    data = {
        'pendingid': pendingid,
        'qrCodeResult': eidasWebSynch,
    }
    
    response = sess.post(
        'https://eid.oesterreich.gv.at/authHandler//public/secure/process',
        headers=headers,
        data=data,
        verify=verify,
        proxies=proxies,
        allow_redirects=False,
    )
    
    resp = json.loads(response.text)
    pendingid = resp['params']['pendingid']
    
    finished = False
    
    while not finished:
        headers = {
            'Host': 'eid.oesterreich.gv.at',
            'X-Binding-Wait_auth': pendingid,
            'Accept': 'application/json',
            'Sl2clienttype': 'nativeApp',
            'X-Moa-Vda': '0',
            'Accept-Language': 'de',
            'User-Agent': 'okhttp/4.9.3',
            'Connection': 'close',
        }
        
        response = sess.get(
            'https://eid.oesterreich.gv.at/authHandler//public/secure/binding/waiting/authfinished',
            headers=headers,
            verify=verify,
            proxies=proxies,
            allow_redirects=False,
        )
    
        finished = response.status_code != 503
        time.sleep(1)
    
    l = response.headers['location']
    
    headers = {
        'Host': 'eid.oesterreich.gv.at',
        'Accept': 'application/json',
        'Sl2clienttype': 'nativeApp',
        'X-Moa-Vda': '0',
        'Accept-Language': 'de',
        'User-Agent': 'okhttp/4.9.3',
        'Connection': 'close',
    }
    
    response = sess.get(
        l,
        headers=headers,
        verify=verify,
        proxies=proxies,
        allow_redirects=False,
    )
    
    l = response.headers['location']
    
    headers = {
        'Host': 'eid.oesterreich.gv.at',
        'Accept': 'application/json',
        'Accept-Language': 'en-US',
        'X-Requested-With': 'Android Binding Library 2.0.14',
        'Content-Type': 'application/json; charset=utf-8',
        'User-Agent': 'okhttp/4.9.3',
        'Connection': 'close',
    }
    
    response = sess.post(
        l + "/" + bindingUuid + "/" + currentAppId,
        headers=headers,
        verify=verify,
        proxies=proxies,
        allow_redirects=False,
    )
    
    d = json.loads(response.text)
    cert = x509.load_der_x509_certificate(b64decode(d['certificate']))
    
    with open("digitales-amt-cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open("digitales-amt-binding-uuid.txt", "w") as f:
        f.write(bindingUuid)    

    print("key => digitales-amt-key.pem")
    print("crt => digitales-amt-cert.pem")
    print("bindingUuid => digitales-amt-binding-uuid.txt")
    print("Digitales Amt Registration Done")

eAusweise = requests.Session()
bindingUuid = open('digitales-amt-binding-uuid.txt').read()
cert = x509.load_pem_x509_certificate(open('digitales-amt-cert.pem', 'rb').read())
key = serialization.load_pem_private_key(open('digitales-amt-key.pem', 'rb').read(), password=None)

headers = {
    'Host': 'identity.awp.oesterreich.gv.at',
    'User-Agent': 'eAusweise/1.1.0+304911 (Android 12; sdk_gphone64_x86_64)',
    'Connection': 'close',
}

response = eAusweise.get('https://identity.awp.oesterreich.gv.at/login', headers=headers, verify=verify, proxies=proxies, allow_redirects=False)
l = response.headers['location']

headers = {
    'Host': 'eid.oesterreich.gv.at',
    'Accept': 'application/json',
    'Sl2clienttype': 'nativeApp',
    'X-Binding-Token': bindingUuid,
    'X-Moa-Vda': '0',
    'Accept-Language': 'de',
    'User-Agent': 'okhttp/4.9.3',
    'Connection': 'close',
}

response = eAusweise.get(
    l,
    headers=headers,
    verify=verify,
    proxies=proxies,
    allow_redirects=True,
)
resp = json.loads(response.text)

pendingid = resp['params']['pendingid']
pendingReqID = resp['params']['pendingReqID']

# fetch challenge
headers = {
    'Host': 'eid.oesterreich.gv.at',
    'Accept': 'application/json',
    'Sl2clienttype': 'nativeApp',
    'X-Binding-Token': 'f0be51ae-5b7f-4e40-8a97-8724fb3c789a',
    'X-Moa-Vda': '0',
    'Accept-Language': 'de',
    'User-Agent': 'okhttp/4.9.3',
    'Connection': 'close',
}

data = {
    'pendingid': pendingid,
    'useBindingAuth': 'true',
    'pendingReqID': pendingReqID,
    'storeConsent': 'true',
}

response = eAusweise.post(
    'https://eid.oesterreich.gv.at/authHandler/public/secure/process',
    headers=headers,
    data=data,
    verify=verify,
    proxies=proxies,
    allow_redirects=True,
)

resp = json.loads(response.text)
challenge = resp['challenge']['challenge']
issuedAt = resp['challenge']['issuedAt']
pendingid = resp['params']['pendingid']
pendingReqID = resp['params']['pendingReqID']
response.close()

head = json.dumps({
  "x5c": [ b64encode(cert.public_bytes(serialization.Encoding.DER)).decode() ],
  "typ": "bindingAuth",
  "alg": "ES256",
}, separators=(",",":")).encode()

pay = json.dumps({
    "challenge": challenge,
    "issuedAt": issuedAt,
}, separators=(",",":")).encode()

head_b64 = urlsafe_b64encode(head).replace(b'=', b'')
pay_b64 = urlsafe_b64encode(pay).replace(b'=', b'')
sig = key.sign(head_b64 + b'.' + pay_b64, ec.ECDSA(hashes.SHA256()))
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
r,s = decode_dss_signature(sig)
sig1 = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
jwt = head_b64 + b'.' + pay_b64 + b'.' + urlsafe_b64encode(sig1).replace(b'=', b'')

headers = {
    'Host': 'eid.oesterreich.gv.at',
    'Accept': 'application/json',
    'Sl2clienttype': 'nativeApp',
    'X-Binding-Token': bindingUuid,
    'X-Moa-Vda': '0',
    'Accept-Language': 'de',
    'User-Agent': 'okhttp/4.9.3',
    'Connection': 'close',
}


data = {
    'challengeResponse': jwt.decode(),
    'pendingid': pendingid,
    'pendingReqID': pendingReqID,
}

response = eAusweise.post(
    'https://eid.oesterreich.gv.at/authHandler/public/secure/process',
    headers=headers,
    data=data,
    verify=verify,
    proxies=proxies,
    allow_redirects=False,
)

l = response.headers['location']
response.close()

# Yes, this code is horrible, I warned you!
response = eAusweise.get(
    l,
    headers=headers,
    verify=verify,
    proxies=proxies,
    allow_redirects=False,
)

l = response.headers['location']
response.close()

response = eAusweise.get(
    l,
    headers=headers,
    verify=verify,
    proxies=proxies,
    allow_redirects=False,
)

l = response.headers['location']
response.close()

response = eAusweise.get(
    "https://eid.oesterreich.gv.at" + l,
    headers=headers,
    verify=verify,
    proxies=proxies,
    allow_redirects=False,
)
response.close()

headers = {
    'Host': 'identity.awp.oesterreich.gv.at',
    'User-Agent': 'eAusweise/1.1.0+304911 (Android 12; sdk_gphone64_x86_64)',
    'Connection': 'close',
}
l = response.headers['location']
s = requests.Session()
response = eAusweise.get(
    l,
    headers=headers,
    allow_redirects=False,
)

resp = json.loads(response.text)
registrationToken = resp['registrationToken']

headers = {
    'Host': 'backend.awp.oesterreich.gv.at',
    'User-Agent': 'okhttp/4.10.0',
    'Connection': 'close',
}

url = "https://backend.awp.oesterreich.gv.at/backend/app/api/v11/registrations/" + registrationToken

response = requests.get(url,
    headers=headers,
    allow_redirects=False,
    cert=("anonymous-prod-cert.pem", "anonymous-prod-key.pem"),
)

resp = json.loads(response.text)
assert(resp['registered'] == True)
    
private_key = ec.generate_private_key(
    ec.SECP256R1()
)

# Write our key to disk for safe keeping
with open("eAusweise-key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "fuck-the.gov"),
# Sign the CSR with our private key.
])).sign(private_key, hashes.SHA256())

# Write our CSR out to disk.
with open("eAusweise-csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

json_data = {
    'csr': csr.public_bytes(serialization.Encoding.PEM).decode(),
    'device': {
        'manufacturer': 'Google',
        'name': 'sdk_gphone64_x86_64',
        'pushMessageType': 'gcm',
        'pushMessageToken': '',
    },
    'user': {},
    'password': None,
}

response = requests.post(
    url,
    headers=headers,
    json=json_data,
    cert=("anonymous-prod-cert.pem", "anonymous-prod-key.pem"),
)

resp = json.loads(response.text)

with open("eAusweise-cert.pem", "w") as f:
    f.write(resp['cert'])

print("Done eAusweise Login")
print("Usage example: curl --key eAusweise-key.pem --cert eAusweise-cert.pem https://backend.awp.oesterreich.gv.at/backend/app/api/v11/users/status")
