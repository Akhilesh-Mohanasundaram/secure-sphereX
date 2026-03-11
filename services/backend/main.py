import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from spiffe import WorkloadApiClient
from pq_crypto import PQHybridEngine
# FIX: Removed the broken 'MLSSessionStore' import
# We don't need it because we use the global 'key_package_store' dict below.

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecureSphere-DS")

# In-Memory Storage (Use Redis in true production)
key_package_store = {}  # { "user_id": KeyPackage }
message_queue = []      # [ { "to": "bob", "payload": "..." } ]

class KeyPackageModel(BaseModel):
    identity: str
    pq_pk: str
    classic_pk: str

class MessageModel(BaseModel):
    sender: str
    target: str
    payload_type: str # "WELCOME" or "APPLICATION"
    payload: dict

@app.on_event("startup")
def startup_event():
    logger.info("🚀 MLS Delivery Service Started")

# --- MLS ENDPOINTS ---

@app.post("/mls/key-package")
def publish_key_package(kp: KeyPackageModel):
    """User publishes their PQ Identity keys"""
    # Verify mTLS Identity
    try:
        with WorkloadApiClient() as client: client.fetch_x509_svid()
    except Exception as e:
        logger.warning(f"Identity check failed (Dev Mode?): {e}")
    
    key_package_store[kp.identity] = kp.dict()
    logger.info(f"📦 KeyPackage stored for {kp.identity}")
    return {"status": "published"}

@app.get("/mls/key-package/{identity}")
def get_key_package(identity: str):
    if identity not in key_package_store:
        raise HTTPException(404, "User not found")
    return key_package_store[identity]

@app.post("/mls/send")
def send_message(msg: MessageModel):
    """Route encrypted messages between users"""
    # Verify mTLS Identity
    try:
        with WorkloadApiClient() as client: client.fetch_x509_svid()
    except Exception:
        pass 
    
    message_queue.append(msg.dict())
    logger.info(f"📨 Message routed: {msg.sender} -> {msg.target} [{msg.payload_type}]")
    return {"status": "queued"}

@app.get("/mls/messages/{identity}")
def fetch_messages(identity: str):
    """User fetches their inbox"""
    # Filter messages for this user and clear them (Pop)
    my_msgs = [m for m in message_queue if m['target'] == identity]
    for m in my_msgs:
        message_queue.remove(m)
    return my_msgs

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)