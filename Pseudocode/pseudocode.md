# Secure-SphereX: Module-Wise Pseudocode Document

This document provides a high-level algorithmic representation of the components in the Secure-SphereX project, detailing post-quantum hybrid cryptography, MLS-inspired ratcheting, and API workflows.

---

## 1. Post-Quantum Hybrid Cryptography Engine (`pq_crypto.py`)

**Class** `PQHybridEngine`
**Properties:**
- `kem_alg`: Configured to use ML-KEM-768

**Method** `generate_server_keys()`
1. Generate Post-Quantum keypair (PQ_Public_Key, PQ_Private_Key) using ML-KEM-768.
2. Generate Classical keypair (Classic_Public_Key, Classic_Private_Key) using X25519.
3. Save private keys securely in instance state.
4. **Return** Base64 encoded structure containing `pq_pk` and `classic_pk`.

**Method** `client_encapsulate(server_keys)`
1. Decode server's PQ and Classical public keys.
2. Perform PQ encapsulation using server's ML-KEM-768 public key:
   - Output: `ciphertext`, `pq_shared_secret`
3. Generate new Classical keypair (X25519) for the client.
4. Perform Classical Diffie-Hellman exchange using server's X25519 public key and client's X25519 private key:
   - Output: `classic_shared_secret`
5. `final_session_key` = `_derive_session_key(pq_shared_secret, classic_shared_secret)`
6. **Return** (Client Encapsulation Payload, `final_session_key`)

**Method** `server_decapsulate(client_data)`
1. Decode client's `ciphertext` and `client_classic_pk`.
2. Perform PQ decapsulation on `ciphertext` using server's ML-KEM-768 private key:
   - Output: `pq_shared_secret`
3. Perform Classical Diffie-Hellman exchange using client's X25519 public key and server's X25519 private key:
   - Output: `classic_shared_secret`
4. **Return** `_derive_session_key(pq_shared_secret, classic_shared_secret)`

**Method** `_derive_session_key(pq_secret, classic_secret)`
1. `combined_secret` = Concatenate(`pq_secret`, `classic_secret`)
2. Pass `combined_secret` through HKDF (HMAC-based Key Derivation Function) using SHA-256 to output a 32-byte key.
3. **Return** Derived Key.

**Method** `encrypt_data(key, plaintext)`
1. Initialize AES-GCM cipher with `key`.
2. Generate a random 12-byte Nonce.
3. `ciphertext` = AES-GCM Encrypt `plaintext` using `nonce`.
4. **Return** Base64 encoded Concatenate(`nonce`, `ciphertext`).

**Method** `decrypt_data(key, payload)`
1. Decode Base64 `payload` into bytes.
2. Extract first 12 bytes as `nonce` and remainder as `ciphertext`.
3. Initialize AES-GCM cipher with `key`.
4. `plaintext` = AES-GCM Decrypt `ciphertext` using `nonce`.
5. **Return** `plaintext` string.

---

## 2. Message Layer Security (MLS) Engine (`mls.py`)

**Class** `MLSEngine`
**Properties:**
- `identity`: User's string identifier
- `pq_engine`: Instance of `PQHybridEngine`
- `epoch`: Current state epoch counter (Integer)
- `app_secret`, `epoch_secret`: Ephemeral cryptographic keys

**Method** `create_key_package()`
1. `keys` = `pq_engine.generate_server_keys()`
2. **Return** Dictionary containing `identity`, `pq_pk`, and `classic_pk`.

**Method** `create_welcome_message(target_key_package)`
1. Generate random 32-byte `initial_group_secret`.
2. Encapsulate `target_key_package` to generate `encap_data` and temporary `shared_key`.
3. `encrypted_group_secret` = Encrypt `initial_group_secret` using `shared_key`.
4. Call `_derive_epoch_keys(initial_group_secret)` to initialize sender's epoch state.
5. **Return** Welcome Payload (`ciphertext`, `client_classic_pk`, `encrypted_group_secret`, `epoch`).

**Method** `process_welcome_message(welcome_msg)`
1. Extract encapsulation payload from `welcome_msg`.
2. `transport_key` = `pq_engine.server_decapsulate(encap_data)`
3. `initial_group_secret` = Decrypt `encrypted_group_secret` using `transport_key`.
4. Call `_derive_epoch_keys(initial_group_secret)` to initialize recipient's epoch state.
5. `epoch` = `welcome_msg.epoch`

**Method** `encrypt_application_message(plaintext)`
1. If `app_secret` is null, Throw Error ("Group not initialized").
2. Encrypt `plaintext` using AES-GCM and `app_secret` with a random nonce.
3. Call `_ratchet_step()` to advance the state and ensure forward secrecy.
4. **Return** Encoded ciphertext including the nonce.

**Method** `decrypt_application_message(ciphertext)`
1. If `app_secret` is null, Throw Error ("Group not initialized").
2. Decrypt `ciphertext` using AES-GCM and `app_secret` with the extracted nonce.
3. Call `_ratchet_step()` to advance the state matching the sender.
4. **Return** Decrypted `plaintext`.

**Method** `_derive_epoch_keys(input_secret)`
1. Use HKDF-SHA256 to expand `input_secret` into 64 bytes.
2. `app_secret` = First 32 bytes (used for message encryption).
3. `epoch_secret` = Last 32 bytes (used to derive next epoch).

**Method** `_ratchet_step()`
1. Call `_derive_epoch_keys(epoch_secret)` to cycle the keys securely.
2. Increment `epoch` by 1.

---

## 3. Backend Delivery Service (`services/backend/main.py`)

**State:**
- Persistent tables (`key_packages` and `messages`) in SQLite database (`securesphere.db`).

**Endpoint** `POST /mls/key-package`
1. Parse client certificate details from the `X-Forwarded-Client-Cert` (XFCC) header.
2. Verify that the client's SPIFFE ID is authorized (e.g. `client-alice` or `client-bob`). Reject with HTTP 401/403 if invalid.
3. Insert or update the public keys (`pq_pk` and `classic_pk`) in the `key_packages` database table.
4. **Return** Success Status.

**Endpoint** `GET /mls/key-package/{identity}`
1. Verify caller's SPIFFE ID in XFCC header.
2. Query `key_packages` table for the target `identity`. Return HTTP 404 if absent.
3. **Return** Stored Key Package.

**Endpoint** `POST /mls/send`
1. Verify caller's SPIFFE ID in XFCC header.
2. Insert message payload, sender, target, and payload type into the `messages` database table.
3. **Return** Success Status.

**Endpoint** `GET /mls/messages/{identity}`
1. Verify caller's SPIFFE ID in XFCC header.
2. Query `messages` table for target `identity`.
3. Delete the matching records from the database table (Pop messages).
4. **Return** Fetched message list.

---

## 4. Client-UI Backend API (`services/client-ui/main.py`)

**State:**
- `session`: Isolated client session `MLSEngine` running for a single identity (`USER_ID`).

**Helper Function** `get_mtls_certs()`
1. Call SPIFFE Workload API `fetch_x509_context()`.
2. Extract client SVID and write SVID cert chain and private key to temp files.
3. Extract local trust domain's root bundle and write to a temp CA file.
4. **Return** Tuple of file paths (cert, key, ca).

**Endpoint** `POST /api/publish/{user}`
1. Verify `user` matches active `USER_ID`.
2. `kp` = Generate ML-KEM-768 Key Package via session.
3. Fetch cert, key, and ca file paths.
4. HTTP POST `kp` to Backend Service (`/mls/key-package`) with client certs and `verify=ca`, validating Envoy's peer SPIFFE ID.
5. Cleanup temporary files.
6. **Return** Success Status and Visualization Data.

**Endpoint** `POST /api/invite`
1. Fetch cert, key, and ca file paths.
2. HTTP GET Target's Key Package from Backend Service with client certs and `verify=ca`, validating Envoy's peer SPIFFE ID.
3. `welcome_msg` = `session.create_welcome_message(target_key_package)`.
4. HTTP POST `welcome_msg` to Backend Service (`/mls/send`) with client certs and `verify=ca`.
5. Cleanup temporary files.
6. **Return** Success and Encap Visualization Data.

**Endpoint** `POST /api/send-msg`
1. `ciphertext` = `session.encrypt_application_message(message)`.
2. HTTP POST `ciphertext` payload to Backend Service (`/mls/send`) with client certs and `verify=ca`.
3. Cleanup temporary files.
4. **Return** Success and Ratchet Visualization Data.

**Endpoint** `POST /api/check-inbox/{user}`
1. HTTP GET messages from Backend Service (`/mls/messages/{USER_ID}`) with client certs and `verify=ca`.
2. For each message:
   - If type is "WELCOME": `session.process_welcome_message(payload)`
   - If type is "APPLICATION": `session.decrypt_application_message(payload)`
3. Cleanup temporary files.
4. **Return** Decrypted message logs and current Epoch state.
