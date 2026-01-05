# Capitolo 10 - Crittografia a Curva Ellittica (ECC)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 3 - Crittografia Asimmetrica  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

**ECC** (Elliptic Curve Cryptography) offre la stessa sicurezza di RSA/DH con chiavi **molto più corte**, risultando più veloce ed efficiente.

### Storia

- **1985**: Neal Koblitz e Victor Miller propongono ECC
- **2005**: NSA raccomanda ECC per classificati
- **2013**: Edward Snowden leak - dubbi su curve NIST
- **Oggi**: Standard per mobile, IoT, web moderno

### Vantaggi ECC

✅ **Chiavi corte**: 256 bit ECC ≈ 3072 bit RSA  
✅ **Veloce**: Operazioni più rapide  
✅ **Efficiente**: Meno banda, CPU, memoria  
✅ **Mobile-friendly**: Ideale per dispositivi limitati  
✅ **Quantum-resistant**: Più resistente di RSA (ma non immune)

---

## Confronto Sicurezza

| ECC (bit) | RSA/DH (bit) | Sicurezza (bit) | AES equivalente |
|-----------|--------------|-----------------|-----------------|
| 160 | 1024 | 80 | AES-128 (debole) |
| 224 | 2048 | 112 | AES-128 |
| 256 | 3072 | 128 | AES-128 |
| 384 | 7680 | 192 | AES-192 |
| 521 | 15360 | 256 | AES-256 |

### Dimensioni Pratiche

```python
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# RSA-2048
rsa_key = rsa.generate_private_key(65537, 2048)
rsa_public = rsa_key.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

# ECC P-256 (sicurezza equivalente RSA-3072)
ecc_key = ec.generate_private_key(ec.SECP256R1())
ecc_public = ecc_key.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

print(f"RSA-2048 public key: {len(rsa_public)} byte")
print(f"ECC P-256 public key: {len(ecc_public)} byte")
print(f"Rapporto: {len(rsa_public) / len(ecc_public):.1f}x più piccolo")
```

---

## Matematica delle Curve Ellittiche

### Equazione di Weierstrass

$$y^2 = x^3 + ax + b$$

Dove $4a^3 + 27b^2 \neq 0$ (curva non singolare).

### Esempi Curve

```python
import matplotlib.pyplot as plt
import numpy as np

def plot_elliptic_curve(a, b, title):
    """Visualizza curva ellittica"""
    y, x = np.ogrid[-5:5:100j, -5:5:100j]
    
    # y^2 = x^3 + ax + b
    plt.figure(figsize=(8, 6))
    plt.contour(x.ravel(), y.ravel(), 
                y**2 - x**3 - a*x - b, 
                [0], colors='blue', linewidths=2)
    
    plt.grid(True, alpha=0.3)
    plt.axhline(y=0, color='k', linewidth=0.5)
    plt.axvline(x=0, color='k', linewidth=0.5)
    plt.title(title)
    plt.xlabel('x')
    plt.ylabel('y')
    plt.axis('equal')

# Esempi
# plot_elliptic_curve(a=-1, b=1, "y² = x³ - x + 1")
# plot_elliptic_curve(a=0, b=7, "y² = x³ + 7 (secp256k1 - Bitcoin)")
```

### Operazioni: Addizione di Punti

#### Regole Geometriche

```
P + Q = R

1. Traccia linea da P a Q
2. Trova terzo punto di intersezione con curva
3. Rifletti rispetto asse x → R
```

#### Formule Algebriche

**Caso P ≠ Q** (addizione):

$$\lambda = \frac{y_Q - y_P}{x_Q - x_P}$$

$$x_R = \lambda^2 - x_P - x_Q$$

$$y_R = \lambda(x_P - x_R) - y_P$$

**Caso P = Q** (raddoppio):

$$\lambda = \frac{3x_P^2 + a}{2y_P}$$

$$x_R = \lambda^2 - 2x_P$$

$$y_R = \lambda(x_P - x_R) - y_P$$

### Implementazione da Zero

```python
class EllipticCurve:
    """Curva ellittica su campo finito"""
    
    def __init__(self, a, b, p):
        """
        Curva: y^2 = x^3 + ax + b (mod p)
        p: primo grande
        """
        self.a = a
        self.b = b
        self.p = p
    
    def is_on_curve(self, x, y):
        """Verifica se punto è sulla curva"""
        return (y**2 - x**3 - self.a*x - self.b) % self.p == 0
    
    def add(self, P, Q):
        """Addizione punti P + Q"""
        
        # Punto all'infinito (identità)
        if P is None:
            return Q
        if Q is None:
            return P
        
        x1, y1 = P
        x2, y2 = Q
        
        # Caso P + (-P) = O
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None  # Punto all'infinito
        
        # Calcola slope λ
        if P == Q:
            # Raddoppio
            lam = (3 * x1**2 + self.a) * pow(2 * y1, -1, self.p)
        else:
            # Addizione
            lam = (y2 - y1) * pow(x2 - x1, -1, self.p)
        
        lam %= self.p
        
        # Calcola R = P + Q
        x3 = (lam**2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        
        return (x3, y3)
    
    def multiply(self, k, P):
        """Moltiplicazione scalare: k*P"""
        
        if k == 0:
            return None  # Punto infinito
        
        if k < 0:
            # k*P = -k*(-P)
            return self.multiply(-k, (P[0], -P[1] % self.p))
        
        # Double-and-add
        result = None
        addend = P
        
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        
        return result

# Test con curva piccola (didattico)
curve = EllipticCurve(a=2, b=3, p=97)

# Punto generatore
G = (3, 6)

print(f"Generatore G = {G}")
print(f"G on curve: {curve.is_on_curve(*G)}")

# Calcola multipli
for k in range(1, 6):
    P = curve.multiply(k, G)
    print(f"{k}*G = {P}")
    if P:
        print(f"  Verifica: {curve.is_on_curve(*P)}")

# ECDH mini-demo
# Alice: a = 5, A = 5*G
alice_private = 5
alice_public = curve.multiply(alice_private, G)

# Bob: b = 7, B = 7*G
bob_private = 7
bob_public = curve.multiply(bob_private, G)

# Segreti condivisi
alice_shared = curve.multiply(alice_private, bob_public)
bob_shared = curve.multiply(bob_private, alice_public)

print(f"\n=== Mini ECDH ===")
print(f"Alice public: {alice_public}")
print(f"Bob public: {bob_public}")
print(f"Alice shared: {alice_shared}")
print(f"Bob shared: {bob_shared}")
print(f"✅ Match: {alice_shared == bob_shared}")
```

---

## Curve Standard

### NIST Curves (FIPS 186-4)

#### P-256 (secp256r1)

```python
from cryptography.hazmat.primitives.asymmetric import ec

# P-256: Curva NIST più comune
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

print("=== P-256 (secp256r1) ===")
print(f"Sicurezza: 128 bit")
print(f"Chiave: 256 bit")
print(f"Uso: TLS, SSH, Bitcoin (NO)")

# Numeri chiave
private_numbers = private_key.private_numbers()
public_numbers = public_key.public_numbers()

print(f"\nPrivate key: {private_numbers.private_value}")
print(f"Public key X: {public_numbers.x}")
print(f"Public key Y: {public_numbers.y}")
```

#### Altre Curve NIST

```python
# P-384 (secp384r1) - 192 bit security
p384_key = ec.generate_private_key(ec.SECP384R1())

# P-521 (secp521r1) - 256 bit security  
p521_key = ec.generate_private_key(ec.SECP521R1())

print("\n=== Curve NIST ===")
for curve_name, key, bits in [
    ("P-256", ec.SECP256R1(), 256),
    ("P-384", ec.SECP384R1(), 384),
    ("P-521", ec.SECP521R1(), 521),
]:
    print(f"{curve_name}: {bits} bit")
```

⚠️ **Controversia**: Alcune curve NIST sospette di backdoor NSA (Dual_EC_DRBG).

### Curve25519 / Ed25519

**Curve moderne** di Daniel Bernstein (DJB).

#### Vantaggi Curve25519

✅ **Veloce**: Ottimizzata per performance  
✅ **Sicura**: Resistente a timing attacks  
✅ **Semplice**: Meno errori implementativi  
✅ **Trasparente**: Nessuna costante "magic"  
✅ **Provably secure**: Dimostrazione formale

#### X25519 (ECDH)

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

print("\n=== X25519 (Curve25519 ECDH) ===")
print(f"Alice shared: {alice_shared.hex()}")
print(f"Bob shared:   {bob_shared.hex()}")
print(f"✅ Match: {alice_shared == bob_shared}")

# Usato in: WireGuard, Signal, TLS 1.3, SSH
```

#### Ed25519 (Firma Digitale)

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

# Genera chiavi
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Firma
messaggio = b"Documento da firmare con Ed25519"
signature = private_key.sign(messaggio)

print("\n=== Ed25519 (EdDSA) ===")
print(f"Messaggio: {messaggio}")
print(f"Firma: {signature.hex()}")

# Verifica
try:
    public_key.verify(signature, messaggio)
    print("✅ Firma VALIDA")
except:
    print("❌ Firma NON VALIDA")

# Vantaggi:
# - Firma: 64 byte
# - Chiave pubblica: 32 byte
# - Veloce: 50x più veloce di RSA
# - Deterministico: Stesso msg+key → stessa firma
```

---

## ECDH: Scambio Chiavi

### Protocollo

```
Alice                                Bob
-----                                -----
Sceglie a (privato)                  Sceglie b (privato)
Calcola A = a*G                      Calcola B = b*G

         A = a*G
    ──────────────────►
    
         B = b*G
    ◄──────────────────

Calcola K = a*B = a*(b*G)            Calcola K = b*A = b*(a*G)
K = (ab)*G                           K = (ab)*G

✅ Stesso segreto condiviso!
```

### Implementazione Completa

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import os

class ECDH_Session:
    """Sessione ECDH completa"""
    
    def __init__(self, curve=ec.SECP256R1()):
        self.private_key = ec.generate_private_key(curve)
        self.public_key = self.private_key.public_key()
        self.shared_secret = None
    
    def get_public_key_bytes(self):
        """Ottieni chiave pubblica serializzata"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def establish_session(self, peer_public_key_pem):
        """Stabilisci sessione con peer"""
        # Carica chiave pubblica peer
        peer_public = serialization.load_pem_public_key(
            peer_public_key_pem
        )
        
        # Calcola segreto condiviso
        self.shared_secret = self.private_key.exchange(
            ec.ECDH(),
            peer_public
        )
        
        return self.shared_secret
    
    def derive_keys(self, info=b"session keys"):
        """Deriva chiavi da segreto condiviso"""
        if not self.shared_secret:
            raise RuntimeError("Sessione non stabilita")
        
        # Deriva 64 byte (2 chiavi da 32)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=info
        )
        
        key_material = kdf.derive(self.shared_secret)
        
        # Split in 2 chiavi (Alice→Bob, Bob→Alice)
        return {
            'send_key': key_material[:32],
            'recv_key': key_material[32:64]
        }

# Test
print("=== ECDH Session ===\n")

alice = ECDH_Session(ec.SECP256R1())
bob = ECDH_Session(ec.SECP256R1())

# Scambio chiavi pubbliche
alice_pub = alice.get_public_key_bytes()
bob_pub = bob.get_public_key_bytes()

print(f"Alice public key:\n{alice_pub.decode()}")

# Stabiliscono sessioni
alice_shared = alice.establish_session(bob_pub)
bob_shared = bob.establish_session(alice_pub)

print(f"Alice shared: {alice_shared.hex()}")
print(f"Bob shared:   {bob_shared.hex()}")
print(f"✅ Match: {alice_shared == bob_shared}\n")

# Derivano chiavi di sessione
alice_keys = alice.derive_keys()
bob_keys = bob.derive_keys()

print("=== Derived Keys ===")
print(f"Alice send key: {alice_keys['send_key'].hex()[:32]}...")
print(f"Bob recv key:   {bob_keys['recv_key'].hex()[:32]}...")
print(f"✅ Match: {alice_keys['send_key'] == bob_keys['recv_key']}")
```

---

## ECDSA: Firma Digitale

### Algoritmo

**Firma**:
1. Calcola $e = H(m)$ (hash messaggio)
2. Sceglie $k$ random
3. Calcola $(x, y) = k \cdot G$
4. $r = x \mod n$
5. $s = k^{-1}(e + rd) \mod n$
6. Firma = $(r, s)$

**Verifica**:
1. Calcola $e = H(m)$
2. $w = s^{-1} \mod n$
3. $u_1 = ew \mod n$, $u_2 = rw \mod n$
4. $(x, y) = u_1 \cdot G + u_2 \cdot Q$
5. Verifica: $r \stackrel{?}{=} x \mod n$

### Implementazione

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature
)

class ECDSA_Signer:
    """ECDSA firma/verifica"""
    
    def __init__(self, curve=ec.SECP256R1()):
        self.private_key = ec.generate_private_key(curve)
        self.public_key = self.private_key.public_key()
    
    def sign(self, message):
        """Firma messaggio"""
        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Decodifica (r, s)
        r, s = decode_dss_signature(signature)
        
        return signature, (r, s)
    
    def verify(self, message, signature):
        """Verifica firma"""
        try:
            self.public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False

# Test ECDSA
print("\n=== ECDSA ===\n")

signer = ECDSA_Signer(ec.SECP256R1())

# Firma documento
doc = b"Contratto importante da firmare"
signature, (r, s) = signer.sign(doc)

print(f"Documento: {doc}")
print(f"Firma r: {r}")
print(f"Firma s: {s}")

# Verifica
valid = signer.verify(doc, signature)
print(f"✅ Firma valida: {valid}")

# Test con documento modificato
doc_fake = b"Contratto MODIFICATO da firmare"
valid_fake = signer.verify(doc_fake, signature)
print(f"❌ Documento fake valido: {valid_fake}")
```

### Vulnerabilità ECDSA

#### Riuso k

⚠️ **CRITICO**: Se $k$ riusato → chiave privata recuperabile!

```python
# ❌ MAI FARE QUESTO!

# Due firme con stesso k:
# s1 = k^(-1)(e1 + rd) mod n
# s2 = k^(-1)(e2 + rd) mod n
#
# s1 - s2 = k^(-1)(e1 - e2) mod n
# k = (e1 - e2) / (s1 - s2) mod n
#
# Con k noto → d = (s*k - e) / r mod n

# Esempio storico: PlayStation 3 hack (2010)
# Sony riusò k → chiave privata compromessa!
```

**Soluzione**: **RFC 6979** - ECDSA deterministico (k da H(m, d))

---

## Confronto Curve

### Performance Benchmark

```python
import time
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519

def benchmark_ecc():
    """Confronta performance curve"""
    
    curves = [
        ("P-256", ec.SECP256R1()),
        ("P-384", ec.SECP384R1()),
        ("P-521", ec.SECP521R1()),
    ]
    
    print("=== Benchmark Curve ECC ===\n")
    
    for name, curve in curves:
        # Keygen
        start = time.time()
        for _ in range(100):
            _ = ec.generate_private_key(curve)
        keygen_time = (time.time() - start) / 100
        
        # ECDH
        alice = ec.generate_private_key(curve)
        bob = ec.generate_private_key(curve)
        
        start = time.time()
        for _ in range(100):
            _ = alice.exchange(ec.ECDH(), bob.public_key())
        ecdh_time = (time.time() - start) / 100
        
        # ECDSA
        message = b"Test message"
        start = time.time()
        for _ in range(100):
            _ = alice.sign(message, ec.ECDSA(hashes.SHA256()))
        sign_time = (time.time() - start) / 100
        
        print(f"{name}:")
        print(f"  Keygen: {keygen_time*1000:.2f}ms")
        print(f"  ECDH:   {ecdh_time*1000:.2f}ms")
        print(f"  Sign:   {sign_time*1000:.2f}ms\n")
    
    # X25519
    start = time.time()
    for _ in range(100):
        alice_x = x25519.X25519PrivateKey.generate()
        bob_x = x25519.X25519PrivateKey.generate()
        _ = alice_x.exchange(bob_x.public_key())
    x25519_time = (time.time() - start) / 100
    
    print(f"X25519: {x25519_time*1000:.2f}ms")
    
    # Ed25519
    start = time.time()
    for _ in range(100):
        key = ed25519.Ed25519PrivateKey.generate()
        _ = key.sign(message)
    ed25519_time = (time.time() - start) / 100
    
    print(f"Ed25519: {ed25519_time*1000:.2f}ms")

benchmark_ecc()
```

### Tabella Comparativa

| Curva | Keygen | ECDH | Sign | Verify | Security |
|-------|--------|------|------|--------|----------|
| P-256 | 5ms | 5ms | 5ms | 10ms | 128 bit |
| P-384 | 10ms | 10ms | 10ms | 20ms | 192 bit |
| P-521 | 20ms | 20ms | 20ms | 40ms | 256 bit |
| X25519 | 1ms | 1ms | - | - | 128 bit |
| Ed25519 | 1ms | - | 0.5ms | 1ms | 128 bit |

---

## Attacchi ECC

### 1. Invalid Curve Attack

Attaccante invia punto su curva diversa (più debole).

**Mitigazione**: Sempre verifica punto su curva corretta!

```python
def verify_point_on_curve(x, y, curve):
    """Verifica punto su curva"""
    # y^2 = x^3 + ax + b (mod p)
    a, b, p = curve.a, curve.b, curve.p
    
    lhs = (y**2) % p
    rhs = (x**3 + a*x + b) % p
    
    if lhs != rhs:
        raise ValueError("Punto NON su curva - possible attack!")
    
    return True
```

### 2. Weak Curves

Alcune curve hanno proprietà speciali che facilitano attacchi.

**Mitigazione**: Usa **solo curve standard** (NIST, Curve25519)!

### 3. Side-Channel Attacks

Timing, power analysis possono rivelare chiave privata.

**Mitigazione**:
- Constant-time implementations
- Blinding techniques
- Usa Curve25519 (design sicuro)

---

## Best Practices

### ✅ Raccomandazioni

1. **Curve moderne**: P-256, P-384, X25519, Ed25519
2. **No custom curves**: Usa standard testati
3. **Validate points**: Sempre verifica punti su curva
4. **RFC 6979**: ECDSA deterministico (no riuso k)
5. **Constant-time**: Usa implementazioni sicure
6. **Key rotation**: Cambia chiavi periodicamente

### ❌ Da Evitare

1. **Curve non standard**: Rischio backdoor
2. **Weak curves**: P-192, secp160k1
3. **Riuso k in ECDSA**: Disastroso!
4. **Custom implementations**: Usa librerie testate
5. **No point validation**: Invalid curve attack

### Quando Usare Quale Curva

```
Uso Generale: P-256 (NIST)
├─ Standard consolidato
├─ Supporto hardware diffuso
└─ TLS, SSH, certificati

Performance: X25519 + Ed25519
├─ Veloce
├─ Constant-time
└─ WireGuard, Signal, moderno

Alta Sicurezza: P-384
├─ 192 bit security
├─ Governo, militare
└─ Dati classificati

Massima Sicurezza: P-521
├─ 256 bit security
├─ Paranoia
└─ Long-term secrets

Bitcoin/Crypto: secp256k1
└─ Solo per blockchain!
```

---

## Codice Completo: Sistema ECC

```python
from cryptography.hazmat.primitives.asymmetric import ec, x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

class ECCSystem:
    """Sistema completo ECC (ECDH + EdDSA + Encrypt)"""
    
    def __init__(self):
        # X25519 per ECDH
        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        
        # Ed25519 per firma
        self.sign_private = ed25519.Ed25519PrivateKey.generate()
        self.sign_public = self.sign_private.public_key()
        
        self.session_key = None
    
    def get_public_keys(self):
        """Ottieni chiavi pubbliche"""
        return {
            'dh': self.dh_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            'sign': self.sign_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        }
    
    def establish_session(self, peer_dh_public_bytes):
        """ECDH per chiave di sessione"""
        peer_dh_public = x25519.X25519PublicKey.from_public_bytes(
            peer_dh_public_bytes
        )
        
        shared = self.dh_private.exchange(peer_dh_public)
        
        # Deriva chiave ChaCha20
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ecc session"
        )
        self.session_key = kdf.derive(shared)
        
        return self.session_key
    
    def encrypt(self, plaintext):
        """Cifra con ChaCha20-Poly1305"""
        if not self.session_key:
            raise RuntimeError("Sessione non stabilita")
        
        cipher = ChaCha20Poly1305(self.session_key)
        nonce = os.urandom(12)
        
        ciphertext = cipher.encrypt(nonce, plaintext, b"")
        
        return nonce + ciphertext
    
    def decrypt(self, encrypted):
        """Decifra"""
        if not self.session_key:
            raise RuntimeError("Sessione non stabilita")
        
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        
        cipher = ChaCha20Poly1305(self.session_key)
        plaintext = cipher.decrypt(nonce, ciphertext, b"")
        
        return plaintext
    
    def sign(self, message):
        """Firma con Ed25519"""
        return self.sign_private.sign(message)
    
    def verify(self, message, signature, peer_sign_public_bytes):
        """Verifica firma"""
        try:
            peer_sign_public = ed25519.Ed25519PublicKey.from_public_bytes(
                peer_sign_public_bytes
            )
            peer_sign_public.verify(signature, message)
            return True
        except:
            return False

# Test completo
print("\n=== ECC System Test ===\n")

# Alice e Bob
alice = ECCSystem()
bob = ECCSystem()

# Scambio chiavi pubbliche
alice_keys = alice.get_public_keys()
bob_keys = bob.get_public_keys()

print("✅ Chiavi pubbliche scambiate")

# Stabiliscono sessione ECDH
alice.establish_session(bob_keys['dh'])
bob.establish_session(alice_keys['dh'])

print("✅ Sessione ECDH stabilita")

# Alice invia messaggio cifrato e firmato
msg = b"Messaggio segreto e autentico"

encrypted = alice.encrypt(msg)
signature = alice.sign(msg)

print(f"✅ Alice: cifrato e firmato")

# Bob riceve, decifra e verifica
decrypted = bob.decrypt(encrypted)
valid = bob.verify(decrypted, signature, alice_keys['sign'])

print(f"✅ Bob: decifrato e verificato")
print(f"\nMessaggio: {decrypted}")
print(f"Firma valida: {valid}")
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 9 - Diffie-Hellman](09_diffie-hellman.md)
- **Successivo**: [Capitolo 11 - Altri Algoritmi Asimmetrici](11_altri_algoritmi_asimmetrici.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- NIST FIPS 186-4: Digital Signature Standard (ECDSA)
- RFC 7748: Elliptic Curves (X25519, X448)
- RFC 8032: Edwards-Curve Digital Signature (EdDSA)
- Bernstein: "Curve25519: new Diffie-Hellman speed records"

**Nota**: ECC è il futuro! Più efficiente di RSA, ma ancora quantum-vulnerable.
