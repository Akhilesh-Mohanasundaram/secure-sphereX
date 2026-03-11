import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pq_crypto import PQHybridEngine

class MLSEngine:
    def __init__(self, identity, pq_engine=None):
        self.identity = identity
        self.pq_engine = pq_engine if pq_engine else PQHybridEngine()
        self.epoch_secret = None
        self.app_secret = None
        self.epoch = 0

    def create_key_package(self):
        """Step 1: Publish Identity & Public Keys"""
        keys = self.pq_engine.generate_server_keys() # Reusing Phase 3 Logic
        return {
            "identity": self.identity,
            "pq_pk": keys['pq_pk'],
            "classic_pk": keys['classic_pk']
        }

    def create_welcome_message(self, target_key_package):
        """Step 2: Create Group & Invite User (Alice -> Bob)"""
        # 1. Generate the initial 'Group Secret' (Random 32 bytes)
        initial_group_secret = os.urandom(32)
        
        # 2. Encapsulate it for the Target (Using Phase 3 Hybrid Encryption)
        # We pretend the group secret is the "session key" for the invite
        encap_data, shared_key = self.pq_engine.client_encapsulate(target_key_package)
        
        # 3. Encrypt the Group Secret with this temporary shared key
        encrypted_group_secret = self.pq_engine.encrypt_data(shared_key, base64.b64encode(initial_group_secret).decode())

        # 4. Initialize Self
        self._derive_epoch_keys(initial_group_secret)

        return {
            "ciphertext": encap_data['ciphertext'],
            "client_classic_pk": encap_data['client_classic_pk'],
            "encrypted_group_secret": encrypted_group_secret,
            "epoch": 0
        }

    def process_welcome_message(self, welcome_msg):
        """Step 3: Join Group (Bob receives Invite)"""
        # 1. Reconstruct the encapsulation payload
        encap_data = {
            "ciphertext": welcome_msg['ciphertext'],
            "client_classic_pk": welcome_msg['client_classic_pk']
        }
        
        # 2. Decapsulate to get the shared transport key
        transport_key = self.pq_engine.server_decapsulate(encap_data)
        
        # 3. Decrypt the Group Secret
        group_secret_b64 = self.pq_engine.decrypt_data(transport_key, welcome_msg['encrypted_group_secret'])
        initial_group_secret = base64.b64decode(group_secret_b64)
        
        # 4. Initialize Self
        self._derive_epoch_keys(initial_group_secret)
        self.epoch = welcome_msg['epoch']

    def encrypt_application_message(self, plaintext):
        """Step 4: Send Message (Ratchet Forward)"""
        if not self.app_secret: raise Exception("Group not initialized")

        # 1. Encrypt with CURRENT Application Secret
        aesgcm = AESGCM(self.app_secret)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        
        # 2. RATCHET FORWARD (Forward Secrecy)
        # Old keys are overwritten in memory!
        self._ratchet_step()

        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt_application_message(self, ciphertext_b64):
        """Step 5: Receive Message (Ratchet Forward)"""
        if not self.app_secret: raise Exception("Group not initialized")

        # 1. Decrypt
        data = base64.b64decode(ciphertext_b64)
        nonce = data[:12]
        payload = data[12:]
        aesgcm = AESGCM(self.app_secret)
        plaintext = aesgcm.decrypt(nonce, payload, None).decode()

        # 2. RATCHET FORWARD (Must match sender's ratchet)
        self._ratchet_step()

        return plaintext

    def _derive_epoch_keys(self, input_secret):
        """Derives App Secret and Next Epoch Secret from Input"""
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'MLS_EPOCH_DERIVATION')
        derived = hkdf.derive(input_secret)
        self.app_secret = derived[:32]    # Used to encrypt messages
        self.epoch_secret = derived[32:]  # Used to generate NEXT epoch

    def _ratchet_step(self):
        """The 'Ratchet': Advances the state so old keys are gone forever"""
        # Feed the current Epoch Secret back into HKDF to get the next one
        self._derive_epoch_keys(self.epoch_secret)
        self.epoch += 1