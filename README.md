# 🛡️ SecureSphere-X

> **Post-Quantum Secure Communication System with Zero-Trust Architecture**

SecureSphere-X is a production-grade communication platform designed to protect sensitive data against both contemporary cyber threats and future quantum computing attacks. It combines Mutual TLS (mTLS) identity enforcement, Lattice-based cryptography (Kyber-768), and continuous MLS-style key ratcheting into a single, interactive architecture.

## ✨ Features
* **Post-Quantum Key Exchange:** Utilizes CRYSTALS-Kyber-768 (NIST standard) for quantum-resistant secret encapsulation.
* **Perfect Forward Secrecy:** Custom Epoch ratcheting ensures keys are destroyed and rotated after every single message.
* **Zero-Trust Networking:** Integrates SPIFFE/SPIRE for ephemeral workload identity and Envoy Proxy for strict mTLS enforcement.
* **Interactive Visualization:** A dynamic Vue.js frontend that intercepts and explains the mathematical transformations (plaintext ➔ lattice puzzle ➔ ciphertext) in real-time.

## 📖 Documentation
* [System Design & Tech Stack](SYSTEM_DESIGN.md)
* [Cryptographic Process Flow](CRYPTOGRAPHIC_FLOW.md)

---

## 🚀 Quick Start Guide

Due to the strict identity verification requirements of the Zero-Trust SPIRE architecture, the infrastructure must be initialized sequentially. Follow these steps exactly to deploy the environment.

### Prerequisites
* Docker & Docker Compose V2
* WSL (Windows Subsystem for Linux) or a standard Linux/macOS terminal

### Phase 1: Environment Reset
Navigate to the project root and ensure a clean slate by removing old containers and volumes.

```bash
cd secure-sphere-x/
docker-compose down -v
```

### Phase 2: SPIRE Control Plane Setup

Boot the SPIRE Server, extract the trust bundle, and manually join the SPIRE Agent.

```bash
# Start the SPIRE Server
docker-compose up -d spire-server

# Extract the bootstrap certificate bundle for the Agent
docker-compose exec -T spire-server bin/spire-server bundle show > infrastructure/spire/conf/agent/bootstrap.crt

# Generate a one-time join token for the Agent node
docker-compose exec spire-server bin/spire-server token generate -spiffeID spiffe://securesphere.io/host/node1
```

**⚠️ IMPORTANT:** Copy the token output from the previous command and paste it into the `TOKEN=` variable below to start the Agent.

```bash
# Replace 'xxxxx...' with your generated token
TOKEN=xxxxx-xxxxx-xxxxx-xxxxx docker-compose up -d spire-agent

# Verify the agent connected successfully (Press Ctrl+C to exit logs)
docker-compose logs spire-agent
```

### Phase 3: Workload Registration & Routing

Register the internal services with the SPIRE Server so they can receive mTLS identities.

```bash
# Register Backend Service
docker-compose exec spire-server bin/spire-server entry create -parentID spiffe://securesphere.io/host/node1 -spiffeID spiffe://securesphere.io/ns/production/sa/backend -selector unix:uid:0

# Register Envoy Proxy (UID)
docker-compose exec spire-server bin/spire-server entry create -parentID spiffe://securesphere.io/host/node1 -spiffeID spiffe://securesphere.io/ns/production/sa/envoy -selector unix:uid:101

# Register Envoy Proxy (Docker Label)
docker-compose exec spire-server bin/spire-server entry create -parentID spiffe://securesphere.io/host/node1 -spiffeID spiffe://securesphere.io/ns/production/sa/envoy -selector docker:label:com.docker.compose.service=envoy-proxy

# Start the Envoy Proxy
docker-compose up -d envoy-proxy
```

### Phase 4: Backend Initialization

Build and boot the cryptography backend.

```bash
# Build and start the FastAPI Backend
docker-compose up -d --build backend-service

# Verify backend booted and fetched its identity (Press Ctrl+C to exit logs)
docker-compose logs -f backend-service
```

### Phase 5: Client UI Registration & Launch

Register the Client UI with SPIRE and start the visualization dashboard.

```bash
# Register the Client UI with SPIRE
docker-compose exec spire-server bin/spire-server entry create -parentID spiffe://securesphere.io/host/node1 -spiffeID spiffe://securesphere.io/ns/production/sa/client-ui -selector docker:label:com.docker.compose.service=client-ui

# Start the Client UI
docker-compose up -d client-ui

# Verify UI booted successfully (Press Ctrl+C to exit logs)
docker-compose logs -f client-ui
```

### Phase 6: Access the Interface

Open your web browser and navigate to the visualization dashboard:

```
http://localhost:3000
```

---

## 🛑 Teardown

To safely stop the containers and remove the isolated networks when you are finished:

```bash
docker-compose down
```