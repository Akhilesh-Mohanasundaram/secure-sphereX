import oqs # The Quantum Library
import os
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PQHybridEngine:
    def __init__(self):
        # We use Kyber768 (NIST ML-KEM Level 3)
        self.kem_alg = "Kyber768"
    
    def generate_server_keys(self):
        """Server Step 1: Generate Kyber + X25519 Public Keys"""
        # 1. Post-Quantum KeyGen
        self.server_kem = oqs.KeyEncapsulation(self.kem_alg)
        pq_public_key = self.server_kem.generate_keypair()
        
        # 2. Classical KeyGen (X25519)
        self.server_x25519_private = x25519.X25519PrivateKey.generate()
        self.server_x25519_public = self.server_x25519_private.public_key()
        
        return {
            "pq_pk": base64.b64encode(pq_public_key).decode(),
            "classic_pk": base64.b64encode(
                self.server_x25519_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).decode()
        }

    def client_encapsulate(self, server_keys_b64):
        """Client Step 2: Create Shared Secret"""
        # Decode Server Keys
        server_pq_pk = base64.b64decode(server_keys_b64['pq_pk'])
        server_classic_pk_bytes = base64.b64decode(server_keys_b64['classic_pk'])
        server_classic_pk = x25519.X25519PublicKey.from_public_bytes(server_classic_pk_bytes)

        # 1. PQ Encapsulation (Kyber)
        with oqs.KeyEncapsulation(self.kem_alg) as client_kem:
            ciphertext, pq_shared_secret = client_kem.encap_secret(server_pq_pk)

        # 2. Classical Diffie-Hellman (X25519)
        client_x25519_private = x25519.X25519PrivateKey.generate()
        client_x25519_public = client_x25519_private.public_key()
        classic_shared_secret = client_x25519_private.exchange(server_classic_pk)

        # 3. Hybridize (Combine Secrets)
        final_session_key = self._derive_session_key(pq_shared_secret, classic_shared_secret)

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "client_classic_pk": base64.b64encode(
                client_x25519_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).decode()
        }, final_session_key

    def server_decapsulate(self, client_data):
        """Server Step 3: Recover Shared Secret"""
        ciphertext = base64.b64decode(client_data['ciphertext'])
        client_classic_pk_bytes = base64.b64decode(client_data['client_classic_pk'])
        client_classic_pk = x25519.X25519PublicKey.from_public_bytes(client_classic_pk_bytes)

        # 1. PQ Decapsulation
        pq_shared_secret = self.server_kem.decap_secret(ciphertext)
        
        # 2. Classical Diffie-Hellman
        classic_shared_secret = self.server_x25519_private.exchange(client_classic_pk)

        # 3. Hybridize
        return self._derive_session_key(pq_shared_secret, classic_shared_secret)

    def _derive_session_key(self, pq_secret, classic_secret):
        """Mixes both secrets using HKDF to create one AES-256 Key"""
        combined_secret = pq_secret + classic_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 32 bytes = 256 bits (for AES-256)
            salt=None,
            info=b'SecureSphere-X Hybrid Handshake'
        )
        return hkdf.derive(combined_secret)

    @staticmethod
    def encrypt_data(key, plaintext):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()

    @staticmethod
    def decrypt_data(key, payload_b64):
        data = base64.b64decode(payload_b64)
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()