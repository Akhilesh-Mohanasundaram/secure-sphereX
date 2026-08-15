import logging
import os
import requests
import uvicorn
import base64
import tempfile
import ssl
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from spiffe import WorkloadApiClient
from cryptography.hazmat.primitives import serialization

# Local library imports
from pq_crypto import PQHybridEngine
from mls import MLSEngine

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecureClient")

SERVER_URL = os.getenv("SERVER_URL", "https://envoy-proxy:8443")
USER_ID = os.getenv("USER_ID", "alice")
PEER_ID = os.getenv("PEER_ID", "bob")
PORT = int(os.getenv("PORT", "3000"))

# Initialize single-user MLSEngine session
session = MLSEngine(USER_ID)

# --- Patch urllib3 globally for SPIFFE ID matching ---
import urllib3.util
import urllib3.util.ssl_

original_match_hostname = urllib3.util.ssl_match_hostname

def spiffe_match_hostname(cert, asserted_hostname):
    san = cert.get('subjectAltName', ())
    for key, value in san:
        if key == 'URI':
            # Verify the peer possesses a valid SVID matching Envoy proxy
            if value == "spiffe://securesphere.io/ns/production/sa/envoy":
                return
            if value == "spiffe://securesphere.io/ns/production/sa/backend":
                return
    # Fallback to standard DNS hostname check
    return original_match_hostname(cert, asserted_hostname)

# Apply patches
urllib3.util.ssl_match_hostname = spiffe_match_hostname
urllib3.util.ssl_.ssl_match_hostname = spiffe_match_hostname

# --- Helper: mTLS Certs & Trust Bundle from SPIRE ---
def get_mtls_certs():
    with WorkloadApiClient() as client:
        context = client.fetch_x509_context()
        svid = context.default_svid
        
        c_file = tempfile.NamedTemporaryFile(delete=False)
        k_file = tempfile.NamedTemporaryFile(delete=False)
        ca_file = tempfile.NamedTemporaryFile(delete=False)
        
        # Write SVID certificates chain and private key
        svid.save(c_file.name, k_file.name, serialization.Encoding.PEM)
        
        # Extract and write trust bundle for client's trust domain
        bundle = context.x509_bundle_set.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)
        bundle.save(ca_file.name, serialization.Encoding.PEM)
        
        c_file.close()
        k_file.close()
        ca_file.close()
        
        return (c_file.name, k_file.name, ca_file.name)

# --- Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def read_root():
    return FileResponse("templates/index.html")

@app.get("/api/config")
async def get_config():
    return {
        "user": USER_ID,
        "peer": PEER_ID,
        "mode": "separated"
    }

@app.post("/api/reset")
async def reset_state():
    global session
    session = MLSEngine(USER_ID)
    return {"status": "reset"}

@app.post("/api/publish/{user}")
async def publish_key(user: str):
    if user != USER_ID:
        return {"error": f"This client only manages session for {USER_ID}"}
        
    kp = session.create_key_package()
    certs = get_mtls_certs()
    try:
        resp = requests.post(f"{SERVER_URL}/mls/key-package", json=kp, cert=(certs[0], certs[1]), verify=certs[2])
        if resp.status_code != 200:
            return {"error": f"Backend error: {resp.status_code}"}
        pk_preview = kp['pq_pk'][:30] + "..."
        return {"status": "Published", "viz_data": {"type": "KEY_GEN", "key": pk_preview}}
    finally:
        os.remove(certs[0]); os.remove(certs[1]); os.remove(certs[2])

@app.post("/api/invite")
async def send_invite(data: dict):
    sender_name = data['sender']
    target_user = data['target']
    
    if sender_name != USER_ID:
        return {"error": f"This client only manages session for {USER_ID}"}
        
    certs = get_mtls_certs()
    try:
        # Fetch Target Keys from directory
        resp = requests.get(f"{SERVER_URL}/mls/key-package/{target_user}", cert=(certs[0], certs[1]), verify=certs[2])
        if resp.status_code != 200:
            return {"error": f"Target user '{target_user}' keys not found"}
        target_kp = resp.json()

        # Encapsulate shared secret using ML-KEM-768
        welcome_msg = session.create_welcome_message(target_kp)
        
        requests.post(f"{SERVER_URL}/mls/send", json={
            "sender": USER_ID, "target": target_user, "payload_type": "WELCOME", "payload": welcome_msg
        }, cert=(certs[0], certs[1]), verify=certs[2])
        
        return {
            "status": "Invite Sent", 
            "epoch": session.epoch,
            "viz_data": {
                "type": "ML_KEM_ENCAP",
                "shared_secret": "*** QUANTUM SECRET ***",
                "ciphertext": welcome_msg['ciphertext'][:40] + "..."
            }
        }
    finally:
        os.remove(certs[0]); os.remove(certs[1]); os.remove(certs[2])

@app.post("/api/send-msg")
async def send_chat(data: dict):
    sender_name = data['sender']
    target_user = data['target']
    
    if sender_name != USER_ID:
        return {"error": f"This client only manages session for {USER_ID}"}
        
    # 1. Encrypt locally (Client Side) and ratchet key state
    ciphertext = session.encrypt_application_message(data['message'])
    
    certs = get_mtls_certs()
    try:
        # 2. Send Encrypted Blob to backend delivery queue
        requests.post(f"{SERVER_URL}/mls/send", json={
            "sender": USER_ID, "target": target_user, "payload_type": "APPLICATION", "payload": {"ciphertext": ciphertext}
        }, cert=(certs[0], certs[1]), verify=certs[2])
        
        return {
            "status": "Sent", 
            "epoch": session.epoch,
            "viz_data": {
                "type": "MLS_RATCHET",
                "plaintext": data['message'],
                "key_epoch": session.epoch - 1,
                "ciphertext": ciphertext[:50] + "..."
            }
        }
    finally:
        os.remove(certs[0]); os.remove(certs[1]); os.remove(certs[2])

@app.post("/api/check-inbox/{user}")
async def check_inbox(user: str):
    if user != USER_ID:
        return {"error": f"This client only manages session for {USER_ID}"}
        
    certs = get_mtls_certs()
    logs = []
    
    try:
        resp = requests.get(f"{SERVER_URL}/mls/messages/{USER_ID}", cert=(certs[0], certs[1]), verify=certs[2])
        messages = resp.json()
        
        for msg in messages:
            if msg['payload_type'] == "WELCOME":
                session.process_welcome_message(msg['payload'])
                logs.append(f"🔓 Decrypted Invitation! Joined Group Epoch {session.epoch}")
            elif msg['payload_type'] == "APPLICATION":
                plaintext = session.decrypt_application_message(msg['payload']['ciphertext'])
                logs.append(f"💬 {msg['sender']}: {plaintext}")
        
        return {"logs": logs, "epoch": session.epoch}
    finally:
        os.remove(certs[0]); os.remove(certs[1]); os.remove(certs[2])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)