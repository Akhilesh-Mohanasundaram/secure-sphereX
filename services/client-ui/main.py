import logging
import os
import requests
import uvicorn
import base64
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from spiffe import WorkloadApiClient

from pq_crypto import PQHybridEngine
from mls import MLSEngine

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecureClient")

SERVER_URL = "https://envoy-proxy:8443"

# In-Memory Session
sessions = { "alice": MLSEngine("alice"), "bob": MLSEngine("bob") }

# --- Helper: mTLS Certs ---
import tempfile
def get_mtls_certs():
    with WorkloadApiClient() as client:
        svid = client.fetch_x509_svid()
        c_file = tempfile.NamedTemporaryFile(delete=False)
        k_file = tempfile.NamedTemporaryFile(delete=False)
        chain = svid.certs if hasattr(svid, 'certs') else [svid.leaf]
        for cert in chain: c_file.write(cert.public_bytes(os.sys.modules['cryptography.hazmat.primitives.serialization'].Encoding.PEM))
        k_file.write(svid.private_key.private_bytes(
            os.sys.modules['cryptography.hazmat.primitives.serialization'].Encoding.PEM,
            os.sys.modules['cryptography.hazmat.primitives.serialization'].PrivateFormat.PKCS8,
            os.sys.modules['cryptography.hazmat.primitives.serialization'].NoEncryption()
        ))
        c_file.flush(); k_file.flush()
        return (c_file.name, k_file.name)

# --- Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def read_root():
    return FileResponse("templates/index.html")

@app.post("/api/reset")
async def reset_state():
    global sessions
    sessions = { "alice": MLSEngine("alice"), "bob": MLSEngine("bob") }
    return {"status": "reset"}

@app.post("/api/publish/{user}")
async def publish_key(user: str):
    engine = sessions[user]
    kp = engine.create_key_package() # Generates Kyber Keys
    
    certs = get_mtls_certs()
    try:
        requests.post(f"{SERVER_URL}/mls/key-package", json=kp, cert=certs, verify=False)
        # VISUALIZATION DATA: Return the Public Key snippet
        pk_preview = kp['pq_pk'][:30] + "..."
        return {"status": "Published", "viz_data": {"type": "KEY_GEN", "key": pk_preview}}
    finally:
        os.remove(certs[0]); os.remove(certs[1])

@app.post("/api/invite")
async def send_invite(data: dict):
    sender = sessions[data['sender']]
    target_user = data['target']
    
    certs = get_mtls_certs()
    try:
        # Fetch Target Keys
        resp = requests.get(f"{SERVER_URL}/mls/key-package/{target_user}", cert=certs, verify=False)
        if resp.status_code != 200: return {"error": "Target not found"}
        target_kp = resp.json()

        # Encapsulate (Kyber)
        welcome_msg = sender.create_welcome_message(target_kp)
        
        requests.post(f"{SERVER_URL}/mls/send", json={
            "sender": data['sender'], "target": target_user, "payload_type": "WELCOME", "payload": welcome_msg
        }, cert=certs, verify=False)
        
        # VISUALIZATION DATA: Show the Encapsulated Secret
        return {
            "status": "Invite Sent", 
            "epoch": sender.epoch,
            "viz_data": {
                "type": "KYBER_ENCAP",
                "shared_secret": "*** QUANTUM SECRET ***",
                "ciphertext": welcome_msg['ciphertext'][:40] + "..."
            }
        }
    finally:
        os.remove(certs[0]); os.remove(certs[1])

@app.post("/api/send-msg")
async def send_chat(data: dict):
    sender = sessions[data['sender']]
    
    # 1. Encrypt locally (Client Side)
    ciphertext = sender.encrypt_application_message(data['message'])
    
    certs = get_mtls_certs()
    try:
        # 2. Send Encrypted Blob
        requests.post(f"{SERVER_URL}/mls/send", json={
            "sender": data['sender'], "target": data['target'], "payload_type": "APPLICATION", "payload": {"ciphertext": ciphertext}
        }, cert=certs, verify=False)
        
        # VISUALIZATION DATA: Return Plaintext vs Ciphertext
        return {
            "status": "Sent", 
            "epoch": sender.epoch,
            "viz_data": {
                "type": "MLS_RATCHET",
                "plaintext": data['message'],
                "key_epoch": sender.epoch - 1, # The key used was from previous step
                "ciphertext": ciphertext[:50] + "..."
            }
        }
    finally:
        os.remove(certs[0]); os.remove(certs[1])

@app.post("/api/check-inbox/{user}")
async def check_inbox(user: str):
    engine = sessions[user]
    certs = get_mtls_certs()
    logs = []
    
    try:
        resp = requests.get(f"{SERVER_URL}/mls/messages/{user}", cert=certs, verify=False)
        messages = resp.json()
        
        for msg in messages:
            if msg['payload_type'] == "WELCOME":
                engine.process_welcome_message(msg['payload'])
                logs.append(f"🔓 Decrypted Invitation! Joined Group Epoch {engine.epoch}")
            elif msg['payload_type'] == "APPLICATION":
                plaintext = engine.decrypt_application_message(msg['payload']['ciphertext'])
                logs.append(f"💬 {msg['sender']}: {plaintext}")
        
        return {"logs": logs, "epoch": engine.epoch}
    finally:
        os.remove(certs[0]); os.remove(certs[1])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)