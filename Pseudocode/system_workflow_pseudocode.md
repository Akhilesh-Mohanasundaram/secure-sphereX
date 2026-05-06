# Secure-SphereX: End-to-End System Workflow Pseudocode

This document represents the Secure-SphereX architecture as a unified, single-model workflow. It illustrates the sequence of operations from zero-trust initialization and cryptographic bootstrapping through secure messaging, mapping out how the distinct services interact as one complete system.

---

## 1. Zero-Trust System Initialization
**Context:** Establishing a secure, authenticated environment before any application data moves.

```text
PROCEDURE Initialize_Environment():
    START SPIRE Server (Control Plane)
    START Envoy Proxy (Data Plane Gatekeeper)
    START Backend Delivery Service
    
    // Workload Attestation
    Delivery_Service -> SPIRE_Agent: Request Identity
    SPIRE_Agent -> SPIRE_Server: Verify Process Signature / PID
    SPIRE_Server -> SPIRE_Agent: Issue X.509 SVID (spiffe://securesphere.io/ns/production/sa/backend)
    
    // Network Configuration
    Envoy_Proxy configures mTLS Listener on Port 8443
    Envoy_Proxy Requires Valid SPIFFE Certificate for all TCP connections
    
    Delivery_Service -> Memory: Initialize KeyPackage_Store and Message_Queue
END PROCEDURE
```

## 2. User Identity Publication (Bob Onboards)
**Context:** Bob registers his public keys so others can establish a secure session with him.

```text
PROCEDURE Publish_Identity(User="Bob"):
    Client_UI -> SPIRE_Agent: Fetch Client X.509 SVID Certs
    
    // Key Generation
    Bob_PQ_Keys = Kyber768_GenerateKeyPair()
    Bob_Classic_Keys = X25519_GenerateKeyPair()
    Bob_Key_Package = {
        Identity: "Bob",
        PQ_Public_Key: Bob_PQ_Keys.Public,
        Classic_Public_Key: Bob_Classic_Keys.Public
    }
    
    // Secure Transmission
    Client_UI -> Envoy_Proxy: POST /mls/key-package (Payload: Bob_Key_Package, mTLS: Client_SVID)
    Envoy_Proxy -> Envoy_Proxy: Validate Client_SVID
    Envoy_Proxy -> Delivery_Service: Forward Request
    
    Delivery_Service -> Memory: Insert Bob_Key_Package into KeyPackage_Store
    Delivery_Service -> Client_UI: Return 200 OK
END PROCEDURE
```

## 3. Creating & Inviting to a Secure Group (Alice Invites Bob)
**Context:** Alice wants to start a secure chat with Bob using hybrid post-quantum encryption.

```text
PROCEDURE Invite_User(Sender="Alice", Target="Bob"):
    Client_UI -> SPIRE_Agent: Fetch Client X.509 SVID Certs
    
    // Fetch Target Keys
    Client_UI -> Delivery_Service: GET /mls/key-package/Bob (via mTLS)
    Delivery_Service -> Client_UI: Return Bob_Key_Package
    
    // 1. Generate Group Secret
    Initial_Group_Secret = GenerateRandomBytes(32)
    
    // 2. Quantum Encapsulation (Kyber)
    Ciphertext, PQ_Shared_Secret = Kyber768_Encapsulate(Bob_Key_Package.PQ_Public_Key)
    
    // 3. Classical Key Exchange (X25519)
    Alice_Temp_Keys = X25519_GenerateKeyPair()
    Classic_Shared_Secret = X25519_DiffieHellman(Alice_Temp_Keys.Private, Bob_Key_Package.Classic_Public_Key)
    
    // 4. Hybridize & Encrypt Secret
    Temporary_Session_Key = HKDF_SHA256(Concatenate(PQ_Shared_Secret, Classic_Shared_Secret))
    Encrypted_Group_Secret = AES_GCM_Encrypt(Key=Temporary_Session_Key, Plaintext=Initial_Group_Secret)
    
    // 5. Setup Local State
    Alice_State.App_Secret, Alice_State.Epoch_Secret = HKDF_SHA256_Derive(Initial_Group_Secret)
    Alice_State.Epoch = 0
    
    // 6. Transmit Invitation
    Welcome_Message = {
        Sender: "Alice", Target: "Bob", Type: "WELCOME",
        Payload: { Ciphertext, Alice_Temp_Classic_Public_Key, Encrypted_Group_Secret, Epoch: 0 }
    }
    Client_UI -> Delivery_Service: POST /mls/send (Payload: Welcome_Message, via mTLS)
    Delivery_Service -> Memory: Append Welcome_Message to Message_Queue
END PROCEDURE
```

## 4. Processing the Invitation (Bob Joins)
**Context:** Bob receives the invitation and derives the same Group Secret.

```text
PROCEDURE Process_Inbox(User="Bob"):
    Client_UI -> Delivery_Service: GET /mls/messages/Bob (via mTLS)
    Delivery_Service -> Memory: Extract and Remove messages where Target == "Bob"
    Delivery_Service -> Client_UI: Return [Welcome_Message]
    
    // 1. Quantum Decapsulation
    PQ_Shared_Secret = Kyber768_Decapsulate(Bob_PQ_Keys.Private, Welcome_Message.Ciphertext)
    
    // 2. Classical Key Exchange
    Classic_Shared_Secret = X25519_DiffieHellman(Bob_Classic_Keys.Private, Welcome_Message.Alice_Temp_Classic_Public_Key)
    
    // 3. Derive Temporary Key & Decrypt Secret
    Temporary_Session_Key = HKDF_SHA256(Concatenate(PQ_Shared_Secret, Classic_Shared_Secret))
    Initial_Group_Secret = AES_GCM_Decrypt(Key=Temporary_Session_Key, Ciphertext=Welcome_Message.Encrypted_Group_Secret)
    
    // 4. Setup Local State
    Bob_State.App_Secret, Bob_State.Epoch_Secret = HKDF_SHA256_Derive(Initial_Group_Secret)
    Bob_State.Epoch = 0
END PROCEDURE
```

## 5. Secure Forward-Secrecy Messaging (Alice -> Bob)
**Context:** Sending application messages and ratcheting the keys forward.

```text
PROCEDURE Send_Encrypted_Message(Sender="Alice", Target="Bob", Message="Hello"):
    // 1. Encrypt with Current Epoch Key
    Message_Ciphertext = AES_GCM_Encrypt(Key=Alice_State.App_Secret, Plaintext=Message)
    
    // 2. Ratchet Forward (Perfect Forward Secrecy)
    Alice_State.App_Secret, Alice_State.Epoch_Secret = HKDF_SHA256_Derive(Alice_State.Epoch_Secret)
    Alice_State.Epoch += 1
    DESTROY_OLD_KEYS(Memory)
    
    // 3. Transmit
    App_Message = { Sender: "Alice", Target: "Bob", Type: "APPLICATION", Payload: Message_Ciphertext }
    Client_UI -> Delivery_Service: POST /mls/send (Payload: App_Message, via mTLS)
    Delivery_Service -> Memory: Append App_Message to Message_Queue
END PROCEDURE

PROCEDURE Receive_Encrypted_Message(User="Bob"):
    Client_UI -> Delivery_Service: GET /mls/messages/Bob (via mTLS)
    Delivery_Service -> Client_UI: Return [App_Message]
    
    // 1. Decrypt with Current Epoch Key
    Message_Plaintext = AES_GCM_Decrypt(Key=Bob_State.App_Secret, Ciphertext=App_Message.Payload)
    PRINT("Alice says:", Message_Plaintext)
    
    // 2. Ratchet Forward (Matches Sender's State)
    Bob_State.App_Secret, Bob_State.Epoch_Secret = HKDF_SHA256_Derive(Bob_State.Epoch_Secret)
    Bob_State.Epoch += 1
    DESTROY_OLD_KEYS(Memory)
END PROCEDURE
```
