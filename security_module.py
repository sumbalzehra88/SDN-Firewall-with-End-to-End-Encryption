from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os
import json
import time

class SecureHost:
    """
    Security module for network hosts
    Implements:
    - Fernet encryption for data
    - RSA authentication for Zero Trust
    - Key management
    """
    
    def __init__(self, host_name):
        self.name = host_name
        self.key_dir = "keys"
        
        # Create keys directory if it doesn't exist
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir)
        
        # Load or generate RSA keys (for Zero Trust)
        self._setup_rsa_keys()
        
        # Generate Fernet key for session (for data encryption)
        self.fernet_key = Fernet.generate_key()
        self.cipher = Fernet(self.fernet_key)
        
        # Track verified hosts (Zero Trust registry)
        self.verified_hosts = {}
        
        print(f"[{self.name}] Security module initialized")
    
    def _setup_rsa_keys(self):
        """Generate or load RSA key pair"""
        private_key_path = f"{self.key_dir}/{self.name}_private.pem"
        public_key_path = f"{self.key_dir}/{self.name}_public.pem"
        
        if os.path.exists(private_key_path):
            # Load existing keys
            self._load_rsa_keys(private_key_path, public_key_path)
            print(f"[{self.name}] Loaded existing RSA keys")
        else:
            # Generate new keys
            self._generate_rsa_keys()
            self._save_rsa_keys(private_key_path, public_key_path)
            print(f"[{self.name}] Generated new RSA keys")
    
    def _generate_rsa_keys(self):
        """Generate new RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def _save_rsa_keys(self, private_path, public_path):
        """Save RSA keys to files"""
        # Save private key
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_path, 'wb') as f:
            f.write(pem)
        
        # Save public key
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_path, 'wb') as f:
            f.write(pem)
    
    def _load_rsa_keys(self, private_path, public_path):
        """Load RSA keys from files"""
        # Load private key
        with open(private_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        # Load public key
        with open(public_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())
    
    def get_public_key_bytes(self):
        """Export public key as bytes (for sharing)"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def load_public_key_from_bytes(self, public_key_bytes):
        """Import public key from bytes"""
        return serialization.load_pem_public_key(public_key_bytes)
    
    # ========== DATA ENCRYPTION (FERNET) ==========
    
    def encrypt_data(self, data):
        """
        Encrypt data using Fernet (symmetric encryption)
        Used for encrypting network packets
        """
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = self.cipher.encrypt(data)
        print(f"[{self.name}] Encrypted data: {len(data)} bytes -> {len(encrypted)} bytes")
        return encrypted
    
    def decrypt_data(self, encrypted_data):
        """
        Decrypt data using Fernet
        Used for decrypting received packets
        """
        try:
            decrypted = self.cipher.decrypt(encrypted_data)
            print(f"[{self.name}] Decrypted data successfully")
            return decrypted
        except Exception as e:
            print(f"[{self.name}] ❌ Decryption failed: {e}")
            return None
    
    # ========== SESSION KEY EXCHANGE (RSA) ==========
    
    def encrypt_session_key(self, other_host_public_key):
        """
        Encrypt Fernet session key with another host's public key
        Used to securely share encryption keys
        """
        encrypted_key = other_host_public_key.encrypt(
            self.fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"[{self.name}] Encrypted session key for secure exchange")
        return encrypted_key
    
    def decrypt_session_key(self, encrypted_session_key):
        """
        Decrypt received session key with our private key
        """
        try:
            session_key = self.private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"[{self.name}] Decrypted session key")
            return session_key
        except Exception as e:
            print(f"[{self.name}] ❌ Session key decryption failed: {e}")
            return None
    
    # ========== ZERO TRUST AUTHENTICATION ==========
    
    def sign_identity(self):
        """
        Sign identity with private key (proves who we are)
        Used for Zero Trust verification
        """
        timestamp = str(int(time.time()))
        message = f"I am {self.name} at {timestamp}".encode()
        
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print(f"[{self.name}] Signed identity")
        return {
            'host_name': self.name,
            'message': message,
            'signature': signature,
            'timestamp': timestamp
        }
    
    def verify_host(self, other_host_public_key, identity_packet):
        """
        Verify another host's identity (Zero Trust check)
        Returns True if host is verified, False otherwise
        """
        try:
            other_host_public_key.verify(
                identity_packet['signature'],
                identity_packet['message'],
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            host_name = identity_packet['host_name']
            self.verified_hosts[host_name] = {
                'public_key': other_host_public_key,
                'verified_at': time.time()
            }
            
            print(f"[{self.name}] ✅ Verified host: {host_name}")
            return True
            
        except Exception as e:
            print(f"[{self.name}] ❌ Verification FAILED: {e}")
            return False
    
    def is_host_verified(self, host_name):
        """Check if a host is in verified registry"""
        return host_name in self.verified_hosts
    
    # ========== UTILITY FUNCTIONS ==========
    
    def get_verified_hosts(self):
        """Return list of verified hosts"""
        return list(self.verified_hosts.keys())
    
    def revoke_host(self, host_name):
        """Remove host from verified registry (revoke trust)"""
        if host_name in self.verified_hosts:
            del self.verified_hosts[host_name]
            print(f"[{self.name}] ⚠️ Revoked trust for: {host_name}")


# ========== STANDALONE TESTING ==========
if __name__ == "__main__":
    print("=" * 60)
    print("TESTING SECURITY MODULE")
    print("=" * 60)
    
    # Create two hosts
    print("\n1. Creating hosts...")
    hostA = SecureHost("HostA")
    hostB = SecureHost("HostB")
    
    # Test 1: Data Encryption
    print("\n2. Testing data encryption...")
    original_data = "This is secret network traffic from HostA to HostB"
    print(f"Original: {original_data}")
    
    encrypted = hostA.encrypt_data(original_data)
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = hostA.decrypt_data(encrypted)
    print(f"Decrypted: {decrypted.decode()}")
    
    # Test 2: Zero Trust Authentication
    print("\n3. Testing Zero Trust authentication...")
    
    # HostA signs identity
    identity_proof = hostA.sign_identity()
    
    # HostB verifies HostA
    hostA_public_key = hostA.public_key
    verification_result = hostB.verify_host(hostA_public_key, identity_proof)
    
    if verification_result:
        print("✅ Zero Trust verification successful!")
    else:
        print("❌ Zero Trust verification failed!")
    
    # Test 3: Check verified hosts
    print("\n4. Verified hosts registry...")
    print(f"HostB's verified hosts: {hostB.get_verified_hosts()}")
    
    # Test 4: Session Key Exchange
    print("\n5. Testing session key exchange...")
    
    # HostA encrypts its session key with HostB's public key
    encrypted_session_key = hostA.encrypt_session_key(hostB.public_key)
    print(f"Encrypted session key size: {len(encrypted_session_key)} bytes")
    
    # HostB decrypts the session key
    received_session_key = hostB.decrypt_session_key(encrypted_session_key)
    
    if received_session_key == hostA.fernet_key:
        print("✅ Session key exchange successful!")
    else:
        print("❌ Session key exchange failed!")
    
    # Test 5: Cross-host encryption
    print("\n6. Testing cross-host encrypted communication...")
    
    # HostA encrypts data
    message = "Secret message from A to B"
    encrypted_msg = hostA.encrypt_data(message)
    
    # HostB needs HostA's session key to decrypt
    # (In real scenario, this would be exchanged securely via RSA)
    hostB.fernet_key = hostA.fernet_key
    hostB.cipher = Fernet(hostB.fernet_key)
    
    decrypted_msg = hostB.decrypt_data(encrypted_msg)
    print(f"HostB received: {decrypted_msg.decode()}")
    
    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETED")
    print("=" * 60)