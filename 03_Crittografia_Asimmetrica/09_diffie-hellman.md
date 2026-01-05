# Capitolo 9 - Diffie-Hellman Key Exchange

> **Corso**: Sistemi e Reti 3  
> **Parte**: 3 - Crittografia Asimmetrica  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

**Diffie-Hellman (DH)** è il primo protocollo di scambio chiavi pubblico, che permette a due parti di generare un segreto condiviso su un canale insicuro **senza mai trasmetterlo**.

### Storia

- **1976**: Whitfield Diffie e Martin Hellman pubblicano "New Directions in Cryptography"
- **Rivoluzione**: Primo sistema a chiave pubblica
- **NSA**: Scoperta parallela classificata (Malcolm Williamson, 1974)
- **Oggi**: Base di TLS, SSH, VPN

### Il Problema Risolto

```
Prima di DH:
Alice ──[Come scambiare chiave?]──► Bob
      (Canale insicuro - Eve ascolta!)

Con DH:
Alice e Bob generano segreto condiviso
SENZA trasmetterlo!
```

---

## Matematica

### Problema del Logaritmo Discreto

**Facile**: Calcolare $y = g^x \mod p$  
**Difficile**: Dato $y$, $g$, $p$, trovare $x$

Esempio:
```python
g, p = 5, 23
x = 6

y = pow(g, x, p)  # Facile: y = 8

# Trovare x da y, g, p → Difficile! (per p grandi)
```

### Parametri DH

- $p$ = **numero primo grande** (2048+ bit)
- $g$ = **generatore** del gruppo $(Z_p^*)$
- $a$ = chiave privata Alice (random)
- $b$ = chiave privata Bob (random)
- $A = g^a \mod p$ = chiave pubblica Alice
- $B = g^b \mod p$ = chiave pubblica Bob

### Segreto Condiviso

$$K = B^a \mod p = (g^b)^a = g^{ab} \mod p$$
$$K = A^b \mod p = (g^a)^b = g^{ab} \mod p$$

**Stesso segreto!** Ma Eve conosce solo $g$, $p$, $A$, $B$.

---

## Protocollo Classico

### Schema Completo

```
Parametri pubblici: p (primo), g (generatore)

Alice                                    Bob
-----                                    -----
Sceglie a ∈ [2, p-2] (segreto)          Sceglie b ∈ [2, p-2] (segreto)
Calcola A = g^a mod p                    Calcola B = g^b mod p

         A = g^a mod p
    ──────────────────────►
    
         B = g^b mod p
    ◄──────────────────────

Calcola K = B^a mod p                    Calcola K = A^b mod p
K = (g^b)^a = g^(ab) mod p              K = (g^a)^b = g^(ab) mod p

✅ Stesso segreto condiviso K = g^(ab) mod p

Eve vede: g, p, A, B
Eve NON può calcolare K (problema logaritmo discreto)
```

### Implementazione da Zero

```python
import random

def generate_prime(bits):
    """Genera primo (semplificato)"""
    import sympy
    while True:
        p = random.getrandbits(bits) | 1
        if sympy.isprime(p):
            return p

def is_generator(g, p):
    """Verifica se g è generatore di Z_p*"""
    # g è generatore se ordine(g) = p-1
    # Per semplicità assumiamo g=2 o g=5 (Sophie Germain prime)
    return True

def diffie_hellman_demo(bits=512):
    """DH da zero (didattico)"""
    
    # Parametri pubblici
    p = generate_prime(bits)
    g = 2  # Generatore comune
    
    print(f"=== Parametri Pubblici ===")
    print(f"p = {p}")
    print(f"g = {g}")
    
    # Alice
    a = random.randint(2, p-2)
    A = pow(g, a, p)
    print(f"\n=== Alice ===")
    print(f"Chiave privata a: (segreto)")
    print(f"Chiave pubblica A: {A}")
    
    # Bob
    b = random.randint(2, p-2)
    B = pow(g, b, p)
    print(f"\n=== Bob ===")
    print(f"Chiave privata b: (segreto)")
    print(f"Chiave pubblica B: {B}")
    
    # Segreto condiviso
    K_alice = pow(B, a, p)
    K_bob = pow(A, b, p)
    
    print(f"\n=== Segreto Condiviso ===")
    print(f"K_alice = B^a mod p = {K_alice}")
    print(f"K_bob   = A^b mod p = {K_bob}")
    print(f"✅ Match: {K_alice == K_bob}")
    
    return K_alice

# Test
shared_secret = diffie_hellman_demo(256)
```

### Con Libreria Cryptography

```python
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# 1. Genera parametri DH (di solito pre-condivisi)
parameters = dh.generate_parameters(
    generator=2,
    key_size=2048
)

# Serializza parametri (per condividerli)
pem_params = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)

print("=== Parametri DH ===")
print(pem_params.decode())

# 2. Alice genera chiavi
alice_private = parameters.generate_private_key()
alice_public = alice_private.public_key()

# 3. Bob genera chiavi
bob_private = parameters.generate_private_key()
bob_public = bob_private.public_key()

# 4. Scambio chiavi pubbliche (su rete)
alice_public_bytes = alice_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
bob_public_bytes = bob_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 5. Calcolo segreto condiviso
alice_shared = alice_private.exchange(bob_public)
bob_shared = bob_private.exchange(alice_public)

print(f"\n=== Segreto Condiviso ===")
print(f"Alice: {alice_shared.hex()[:64]}...")
print(f"Bob:   {bob_shared.hex()[:64]}...")
print(f"✅ Match: {alice_shared == bob_shared}")
```

---

## Derivazione Chiave (KDF)

Il segreto condiviso NON deve essere usato direttamente! Serve **Key Derivation Function**.

### Perché KDF?

❌ Segreto DH ha struttura matematica  
❌ Non uniforme  
✅ KDF produce chiave sicura

### HKDF (HMAC-based KDF)

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

def derive_keys(shared_secret, salt=None, info=b""):
    """Deriva chiavi da segreto DH"""
    
    if salt is None:
        salt = os.urandom(16)
    
    # HKDF per derivare 32 byte (AES-256)
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    
    key = kdf.derive(shared_secret)
    return key, salt

# Usa segreto DH
alice_key, salt = derive_keys(alice_shared, info=b"TLS handshake")
bob_key, _ = derive_keys(bob_shared, salt=salt, info=b"TLS handshake")

print(f"\n=== Chiavi Derivate ===")
print(f"Alice key: {alice_key.hex()}")
print(f"Bob key:   {bob_key.hex()}")
print(f"✅ Match: {alice_key == bob_key}")

# Ora usabile per AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aesgcm = AESGCM(alice_key)
nonce = os.urandom(12)

# Alice cifra
plaintext = b"Messaggio cifrato con chiave DH"
ciphertext = aesgcm.encrypt(nonce, plaintext, b"")

# Bob decifra
decrypted = AESGCM(bob_key).decrypt(nonce, ciphertext, b"")
print(f"\n✅ Decrypted: {decrypted}")
```

---

## ECDH (Elliptic Curve Diffie-Hellman)

Versione moderna su **curve ellittiche**: stessa sicurezza con chiavi più corte!

### Vantaggi

✅ **Chiavi corte**: 256 bit vs 2048 bit  
✅ **Veloce**: Operazioni più rapide  
✅ **Moderno**: Standard TLS 1.3

### Implementazione ECDH

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Alice - genera chiave su P-256
alice_private = ec.generate_private_key(ec.SECP256R1())
alice_public = alice_private.public_key()

# Bob - genera chiave su P-256
bob_private = ec.generate_private_key(ec.SECP256R1())
bob_public = bob_private.public_key()

# Scambio chiavi pubbliche
alice_public_bytes = alice_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
bob_public_bytes = bob_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("=== ECDH su P-256 ===")
print(f"Alice public key:\n{alice_public_bytes.decode()}")

# Segreto condiviso (32 byte per P-256)
alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
bob_shared = bob_private.exchange(ec.ECDH(), alice_public)

print(f"Alice shared: {alice_shared.hex()}")
print(f"Bob shared:   {bob_shared.hex()}")
print(f"✅ Match: {alice_shared == bob_shared}")
```

### X25519 (Curve25519)

Curva moderna ottimizzata di Daniel Bernstein.

```python
from cryptography.hazmat.primitives.asymmetric import x25519

# Alice
alice_private = x25519.X25519PrivateKey.generate()
alice_public = alice_private.public_key()

# Bob
bob_private = x25519.X25519PrivateKey.generate()
bob_public = bob_private.public_key()

# Segreto condiviso (sempre 32 byte)
alice_shared = alice_private.exchange(bob_public)
bob_shared = bob_private.exchange(alice_public)

print(f"\n=== X25519 ===")
print(f"Alice: {alice_shared.hex()}")
print(f"Bob:   {bob_shared.hex()}")
print(f"✅ Match: {alice_shared == bob_shared}")

# Vantaggi X25519:
# - Veloce
# - Constant-time (no timing attacks)
# - Usato in WireGuard, Signal, TLS 1.3
```

---

## Attacchi su Diffie-Hellman

### 1. Man-in-the-Middle (MITM)

**Problema principale** di DH base: no autenticazione!

```
Scenario attacco:

Alice                Eve                    Bob
-----                ---                    -----
A = g^a          A' = g^e₁              B = g^b
   ────────►        │ ────────►
                 B' = g^e₂
   ◄────────        │ ◄────────

Alice cifra con K₁ = (B')^a = g^(ae₁)
Eve decifra con K₁ = (A)^e₁ = g^(ae₁)

Eve cifra con K₂ = (B)^e₂ = g^(be₂)
Bob decifra con K₂ = (A')^b = g^(be₂)

❌ Eve vede tutto!
```

### Mitigazioni MITM

#### 1. Static DH Keys (certificati)

```python
# Chiavi DH firmate con RSA/ECDSA
# Bob pubblica chiave DH pubblica firmata

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Bob: firma chiave DH pubblica
bob_signing_key = rsa.generate_private_key(65537, 2048)

bob_dh_public_bytes = bob_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

signature = bob_signing_key.sign(
    bob_dh_public_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Alice verifica firma prima di usare
try:
    bob_signing_key.public_key().verify(
        signature,
        bob_dh_public_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Chiave DH di Bob autentica")
except:
    print("❌ Chiave DH NON autentica - MITM!")
```

#### 2. DHE (Ephemeral DH)

Chiavi DH temporanee per ogni sessione.

```python
def dhe_handshake():
    """DHE: Nuove chiavi ogni sessione"""
    
    # Ogni connessione genera nuove chiavi
    alice_private = parameters.generate_private_key()
    bob_private = parameters.generate_private_key()
    
    # Perfect Forward Secrecy:
    # Se chiave compromessa → solo quella sessione
    
    return alice_private, bob_private
```

### 2. Small Subgroup Attack

Se $g$ ha ordine piccolo → segreto predicibile!

```python
# ❌ Vulnerabile
p = 23
g = 4  # Ordine solo 11 (non p-1)

# Attaccante può limitare ricerca a sottogruppo piccolo
```

**Mitigazione**: Usa gruppi standard (RFC 3526) o curve sicure.

### 3. Logjam Attack (2015)

Attacco export-grade DH (512 bit).

**Mitigazione**: Minimo 2048 bit per DH classico!

---

## Perfect Forward Secrecy (PFS)

DH ephemeral fornisce **Perfect Forward Secrecy**.

### Concetto

```
Compromissione chiave oggi
NON compromette sessioni passate!
```

### Implementazione PFS

```python
class DHESession:
    """Sessione DH Ephemeral con PFS"""
    
    def __init__(self, parameters):
        self.parameters = parameters
        self.sessions = []
    
    def new_session(self):
        """Crea nuova sessione con chiavi fresche"""
        
        # Genera chiavi NUOVE per ogni sessione
        alice_private = self.parameters.generate_private_key()
        bob_private = self.parameters.generate_private_key()
        
        # Segreto condiviso per QUESTA sessione
        shared = alice_private.exchange(bob_private.public_key())
        
        # Deriva chiave di sessione
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        import os
        
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b"session key"
        )
        session_key = kdf.derive(shared)
        
        self.sessions.append({
            'alice_private': alice_private,
            'bob_private': bob_private,
            'session_key': session_key
        })
        
        # Distruggi chiavi private dopo uso
        # (in pratica vanno zero-izzate)
        
        return session_key
    
    def demonstrate_pfs(self):
        """Dimostra PFS"""
        
        # 3 sessioni con chiavi diverse
        key1 = self.new_session()
        key2 = self.new_session()
        key3 = self.new_session()
        
        print("=== Perfect Forward Secrecy ===")
        print(f"Session 1: {key1.hex()[:32]}...")
        print(f"Session 2: {key2.hex()[:32]}...")
        print(f"Session 3: {key3.hex()[:32]}...")
        print("\n✅ Chiavi diverse per ogni sessione")
        print("✅ Compromissione key3 NON compromette key1, key2")

# Test PFS
parameters = dh.generate_parameters(generator=2, key_size=2048)
dhe = DHESession(parameters)
dhe.demonstrate_pfs()
```

---

## Gruppi DH Standard

### RFC 3526: Moduli Standard

```python
# Gruppo DH da RFC 3526 (2048 bit)
RFC3526_MODP_2048 = """
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb
IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft
awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT
mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh
fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq
5RXSJhiY+gUQFXKOWoqsqmj//////////wIBAg==
-----END DH PARAMETERS-----
"""

# Carica parametri standard
from cryptography.hazmat.primitives.serialization import load_pem_parameters

params = load_pem_parameters(RFC3526_MODP_2048.encode())

# Usa parametri pre-calcolati (veloce!)
alice_key = params.generate_private_key()
```

### Gruppi Raccomandati

| Gruppo | Bit | RFC | Uso |
|--------|-----|-----|-----|
| modp2048 | 2048 | 3526 | Minimo accettabile |
| modp3072 | 3072 | 3526 | Raccomandato |
| modp4096 | 4096 | 3526 | Alta sicurezza |
| modp6144 | 6144 | 3526 | Molto alta |
| modp8192 | 8192 | 3526 | Paranoia |

---

## Confronto: DH vs ECDH vs X25519

```python
import time

def benchmark_dh_variants():
    """Confronta DH, ECDH, X25519"""
    
    print("=== Benchmark Key Exchange ===\n")
    
    # 1. DH classico (2048 bit)
    start = time.time()
    dh_params = dh.generate_parameters(generator=2, key_size=2048)
    dh_alice = dh_params.generate_private_key()
    dh_bob = dh_params.generate_private_key()
    dh_shared = dh_alice.exchange(dh_bob.public_key())
    dh_time = time.time() - start
    
    print(f"DH-2048:")
    print(f"  Time: {dh_time*1000:.2f}ms")
    print(f"  Shared secret: {len(dh_shared)} byte")
    print(f"  Public key: {len(dh_bob.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))} byte")
    
    # 2. ECDH P-256
    start = time.time()
    ecdh_alice = ec.generate_private_key(ec.SECP256R1())
    ecdh_bob = ec.generate_private_key(ec.SECP256R1())
    ecdh_shared = ecdh_alice.exchange(ec.ECDH(), ecdh_bob.public_key())
    ecdh_time = time.time() - start
    
    print(f"\nECDH P-256:")
    print(f"  Time: {ecdh_time*1000:.2f}ms")
    print(f"  Shared secret: {len(ecdh_shared)} byte")
    print(f"  Public key: {len(ecdh_bob.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))} byte")
    
    # 3. X25519
    start = time.time()
    x_alice = x25519.X25519PrivateKey.generate()
    x_bob = x25519.X25519PrivateKey.generate()
    x_shared = x_alice.exchange(x_bob.public_key())
    x_time = time.time() - start
    
    print(f"\nX25519:")
    print(f"  Time: {x_time*1000:.2f}ms")
    print(f"  Shared secret: {len(x_shared)} byte")
    print(f"  Public key: {len(x_bob.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))} byte")
    
    print(f"\n=== Speedup ===")
    print(f"ECDH vs DH: {dh_time/ecdh_time:.1f}x faster")
    print(f"X25519 vs DH: {dh_time/x_time:.1f}x faster")
    print(f"X25519 vs ECDH: {ecdh_time/x_time:.1f}x faster")

benchmark_dh_variants()
```

### Risultati Tipici

| Algoritmo | Tempo | Key Size | Shared Size |
|-----------|-------|----------|-------------|
| DH-2048 | ~50ms | 256 byte | 256 byte |
| ECDH P-256 | ~5ms | 65 byte | 32 byte |
| X25519 | ~1ms | 32 byte | 32 byte |

---

## Esempio Completo: Chat Sicura

```python
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

class SecureChat:
    """Chat end-to-end cifrata con X25519 + ChaCha20"""
    
    def __init__(self, name):
        self.name = name
        # Genera chiave X25519
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.shared_secret = None
        self.cipher = None
        self.send_counter = 0
        self.recv_counter = 0
    
    def get_public_key(self):
        """Ottieni chiave pubblica da condividere"""
        from cryptography.hazmat.primitives import serialization
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def establish_session(self, peer_public_key_bytes):
        """Stabilisci sessione con peer"""
        from cryptography.hazmat.primitives import serialization
        
        # Carica chiave pubblica peer
        peer_public = x25519.X25519PublicKey.from_public_bytes(
            peer_public_key_bytes
        )
        
        # Calcola segreto condiviso
        self.shared_secret = self.private_key.exchange(peer_public)
        
        # Deriva chiave ChaCha20
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"chat session"
        )
        session_key = kdf.derive(self.shared_secret)
        
        # Inizializza cipher
        self.cipher = ChaCha20Poly1305(session_key)
        
        print(f"{self.name}: Sessione stabilita!")
    
    def send_message(self, plaintext):
        """Invia messaggio cifrato"""
        if not self.cipher:
            raise RuntimeError("Sessione non stabilita")
        
        # Nonce = counter (12 byte)
        nonce = self.send_counter.to_bytes(12, 'big')
        self.send_counter += 1
        
        # Cifra con AEAD
        ciphertext = self.cipher.encrypt(
            nonce,
            plaintext.encode(),
            b""
        )
        
        return {
            'nonce': nonce,
            'ciphertext': ciphertext
        }
    
    def receive_message(self, encrypted_msg):
        """Ricevi messaggio cifrato"""
        if not self.cipher:
            raise RuntimeError("Sessione non stabilita")
        
        # Verifica counter (anti-replay)
        nonce = encrypted_msg['nonce']
        counter = int.from_bytes(nonce, 'big')
        
        if counter != self.recv_counter:
            raise ValueError("Messaggio duplicato o fuori ordine")
        
        self.recv_counter += 1
        
        # Decifra e verifica MAC
        plaintext = self.cipher.decrypt(
            nonce,
            encrypted_msg['ciphertext'],
            b""
        )
        
        return plaintext.decode()

# Simulazione chat
print("=== Secure Chat Demo ===\n")

# Alice e Bob creano istanze chat
alice = SecureChat("Alice")
bob = SecureChat("Bob")

# Scambio chiavi pubbliche (canale insicuro OK!)
alice_pubkey = alice.get_public_key()
bob_pubkey = bob.get_public_key()

print(f"Alice pubkey: {alice_pubkey.hex()}")
print(f"Bob pubkey:   {bob_pubkey.hex()}\n")

# Stabiliscono sessioni
alice.establish_session(bob_pubkey)
bob.establish_session(alice_pubkey)

# Chat cifrata
messages = [
    ("Alice", alice, bob, "Ciao Bob!"),
    ("Bob", bob, alice, "Ciao Alice!"),
    ("Alice", alice, bob, "Come stai?"),
    ("Bob", bob, alice, "Bene grazie!"),
]

for sender_name, sender, receiver, text in messages:
    # Invia
    encrypted = sender.send_message(text)
    print(f"{sender_name} → {text}")
    print(f"  Encrypted: {encrypted['ciphertext'][:16].hex()}...")
    
    # Ricevi
    decrypted = receiver.receive_message(encrypted)
    print(f"  Decrypted: {decrypted}\n")
```

---

## Best Practices

### ✅ Raccomandazioni

1. **ECDH/X25519**: Preferisci curve ellittiche
2. **Key size**: Minimo 2048 bit per DH classico
3. **Ephemeral**: Usa DHE per Perfect Forward Secrecy
4. **KDF**: Sempre deriva chiavi con HKDF
5. **Autenticazione**: Combina con firme digitali (anti-MITM)
6. **Gruppi standard**: Usa RFC 3526 o curve NIST/Curve25519

### ❌ Da Evitare

1. **DH < 2048 bit**: Vulnerabile (Logjam)
2. **Static DH senza auth**: MITM attack
3. **Riuso nonce**: Con cifrari stream
4. **Custom groups**: Usa standard testati
5. **Segreto diretto**: Sempre usa KDF

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 8 - RSA](08_rsa_rivest-shamir-adleman.md)
- **Successivo**: [Capitolo 10 - ECC](10_crittografia_a_curva_ellittica_ecc.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 2631: Diffie-Hellman Key Agreement
- RFC 3526: More Modular Exponential (MODP) Groups
- RFC 7748: Elliptic Curves (X25519, X448)
- "New Directions in Cryptography" (Diffie-Hellman, 1976)

**Nota**: DH è la base di TLS/SSL! Quasi tutto il web usa varianti di DH.
