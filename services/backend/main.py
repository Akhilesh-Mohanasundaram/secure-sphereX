import logging
import os
import sqlite3
import json
import re
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import uvicorn
from spiffe import WorkloadApiClient

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecureSphere-DS")

DB_FILE = "securesphere.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS key_packages (
            identity TEXT PRIMARY KEY,
            pq_pk TEXT NOT NULL,
            classic_pk TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            target TEXT NOT NULL,
            payload_type TEXT NOT NULL,
            payload TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# --- Authentication Helpers ---

def verify_client_identity(xfcc_header: str) -> str:
    if not xfcc_header:
        logger.warning("Authentication failed: Missing X-Forwarded-Client-Cert header")
        raise HTTPException(status_code=401, detail="Missing X-Forwarded-Client-Cert header")
    
    cert_details = xfcc_header.split(",")
    allowed_patterns = [
        r"^spiffe://securesphere\.io/ns/production/sa/client-ui$",
        r"^spiffe://securesphere\.io/ns/production/sa/client-alice$",
        r"^spiffe://securesphere\.io/ns/production/sa/client-bob$",
        r"^spiffe://securesphere\.io/ns/production/sa/backend$",
        r"^spiffe://securesphere\.io/ns/production/sa/envoy$"
    ]
    
    client_spiffe_ids = []
    
    for detail in cert_details:
        parts = detail.split(";")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                k, v = part.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"')
                if k == "URI":
                    if not v.startswith("spiffe://securesphere.io/"):
                        logger.warning(f"Authentication failed: Untrusted trust domain in SVID: {v}")
                        raise HTTPException(status_code=401, detail="Invalid client certificate trust domain")
                    if not any(re.match(pattern, v) for pattern in allowed_patterns):
                        logger.warning(f"Authorization denied: SPIFFE ID '{v}' is not in the allowed list")
                        raise HTTPException(status_code=403, detail=f"Access denied for SPIFFE ID: {v}")
                    client_spiffe_ids.append(v)
            else:
                logger.warning(f"Authentication failed: Malformed header part: {part}")
                raise HTTPException(status_code=401, detail="Invalid client certificate SPIFFE ID")
                
    if not client_spiffe_ids:
        logger.warning("Authentication failed: No URI SAN found in XFCC header")
        raise HTTPException(status_code=401, detail="Invalid client certificate SPIFFE ID")
        
    return client_spiffe_ids[0]

def authenticate_request(x_forwarded_client_cert: Optional[str] = Header(None)) -> str:
    if os.getenv("DISABLE_AUTH_FOR_TESTS") == "true":
        return "test-workload"
    return verify_client_identity(x_forwarded_client_cert)

class KeyPackageModel(BaseModel):
    identity: str
    pq_pk: str
    classic_pk: str

class MessageModel(BaseModel):
    sender: str
    target: str
    payload_type: str  # "WELCOME" or "APPLICATION"
    payload: dict

@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("🚀 MLS Delivery Service Started (SQLite DB Initialized)")
    if os.getenv("DISABLE_AUTH_FOR_TESTS") != "true":
        try:
            with WorkloadApiClient() as client:
                svid = client.fetch_x509_svid()
                logger.info(f"Verified Backend Workload SVID: {svid.spiffe_id}")
        except Exception as e:
            logger.warning(f"Could not fetch self-attested SVID on startup: {e}")

# --- MLS ENDPOINTS ---

@app.post("/mls/key-package")
def publish_key_package(kp: KeyPackageModel, client_id: str = Depends(authenticate_request)):
    """User publishes their PQ Identity keys"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO key_packages (identity, pq_pk, classic_pk) VALUES (?, ?, ?)",
        (kp.identity, kp.pq_pk, kp.classic_pk)
    )
    conn.commit()
    conn.close()
    
    logger.info(f"📦 KeyPackage stored for {kp.identity} (Authenticated as {client_id})")
    return {"status": "published"}

@app.get("/mls/key-package/{identity}")
def get_key_package(identity: str, client_id: str = Depends(authenticate_request)):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT identity, pq_pk, classic_pk FROM key_packages WHERE identity = ?", (identity,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(404, "User not found")
        
    logger.info(f"🔑 KeyPackage fetched for {identity} (Authenticated as {client_id})")
    return {"identity": row[0], "pq_pk": row[1], "classic_pk": row[2]}

@app.post("/mls/send")
def send_message(msg: MessageModel, client_id: str = Depends(authenticate_request)):
    """Route encrypted messages between users"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO messages (sender, target, payload_type, payload) VALUES (?, ?, ?, ?)",
        (msg.sender, msg.target, msg.payload_type, json.dumps(msg.payload))
    )
    conn.commit()
    conn.close()
    
    logger.info(f"📨 Message routed: {msg.sender} -> {msg.target} [{msg.payload_type}] (Authenticated as {client_id})")
    return {"status": "queued"}

@app.get("/mls/messages/{identity}")
def fetch_messages(identity: str, client_id: str = Depends(authenticate_request)):
    """User fetches their inbox"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, sender, target, payload_type, payload FROM messages WHERE target = ?", (identity,))
    rows = c.fetchall()
    
    # Delete fetched messages (Pop)
    c.execute("DELETE FROM messages WHERE target = ?", (identity,))
    conn.commit()
    conn.close()
    
    messages = []
    for row in rows:
        messages.append({
            "sender": row[1],
            "target": row[2],
            "payload_type": row[3],
            "payload": json.loads(row[4])
        })
        
    logger.info(f"📥 Inbox synchronized for {identity} (Authenticated as {client_id}, fetched {len(messages)} messages)")
    return messages

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)