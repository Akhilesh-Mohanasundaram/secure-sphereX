# SecureSphere-X: System Design & Architecture

SecureSphere-X is a zero-trust, post-quantum secure communication platform. The architecture is heavily decoupled, separating network security (identity and transport) from application-layer cryptography (message encryption and ratcheting). 
## 1. Technology Stack
### Application Layer (Cryptography & Business Logic)
* **Backend Framework:** FastAPI (Python 3.9)
* **Frontend UI:** Vue.js 3, TailwindCSS, HTML5 (Served via FastAPI Static/Template engine)
* **Post-Quantum KEM:** `liboqs-python` (Implementing CRYSTALS-Kyber-768)
* **Symmetric Encryption:** `cryptography` (AES-256-GCM)
* **State Management:** Custom MLS-inspired Ephemeral Ratchet (`mls.py`)

### Network & Infrastructure Layer (Zero-Trust)
* **Identity Provider (Control Plane):** SPIRE (SPIFFE Runtime Environment)
* **Transport Security (Data Plane):** Envoy Proxy
* **Containerization:** Docker & Docker Compose
* **mTLS Certificates:** X.509 SVIDs (SPIFFE Verifiable Identity Documents)

## 2. System Components
1.  **SPIRE Server & Agent:** Forms the trusted control plane. The agent attests the backend workload and mints short-lived (1-hour) X.509 SVIDs.
2.  **Envoy Proxy:** Acts as the network gatekeeper. It terminates mTLS connections, verifying the SPIFFE identity of incoming requests before routing traffic to the internal FastAPI backend.
3.  **Backend Service:** Handles cryptographic key generation, decapsulation, message routing, and continuous epoch ratcheting.
4.  **Client UI Container:** Serves the interactive Vue.js dashboard to visualize the mathematical processes occurring within the backend.