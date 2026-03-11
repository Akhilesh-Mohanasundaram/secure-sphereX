# SecureSphere-X: Cryptographic Lifecycle & Process Flow

This document details the exact cryptographic and network operations executed during a SecureSphere-X communication lifecycle.

## Phase 1: Zero-Trust Bootstrapping
1.  **Workload Attestation:** The SPIRE Agent verifies the backend container's signature/PID.
2.  **SVID Issuance:** SPIRE issues an ephemeral X.509 certificate (`spiffe://securesphere.io/ns/production/sa/backend`).
3.  **Envoy Configuration:** Envoy consumes this certificate to establish an mTLS listener on port 8443, dropping any unauthenticated TCP connections.

## Phase 2: Post-Quantum Handshake (Key Encapsulation)
1.  **Key Generation:** The recipient (Bob) generates a CRYSTALS-Kyber-768 keypair and publishes the Public Key to the directory.
2.  **Encapsulation:** The sender (Alice) retrieves the Public Key and executes the Kyber `encap` function, generating a **Shared Secret** and a **Ciphertext** (quantum puzzle). 3.  **Decapsulation:** Alice transmits the Ciphertext. Bob utilizes his Kyber Private Key to run the `decap` function, deriving the exact same Shared Secret. Both parties initialize their state at **Epoch 0**.

## Phase 3: Authenticated Encryption & Forward Secrecy
1.  **Message Encryption:** When a message is sent, the AES-256-GCM engine generates a unique Initialization Vector (IV). The plaintext is encrypted using the current Epoch key, appending an Authentication Tag.
2.  **Transmission:** The encrypted payload traverses the Envoy mTLS tunnel.
3.  **Decryption:** The receiver validates the Auth Tag and decrypts the payload.
4.  **Continuous Ratcheting:** Immediately following successful encryption/decryption, both nodes pass the current Epoch key through a one-way Key Derivation Function (KDF) to generate the $N+1$ Epoch key. The previous key is securely deleted from memory, guaranteeing **Perfect Forward Secrecy (PFS)**.