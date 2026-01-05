# Capitolo 8 - RSA (Rivest-Shamir-Adleman)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 3 - Crittografia Asimmetrica  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

**RSA** è l'algoritmo di crittografia asimmetrica più diffuso al mondo, inventato nel 1977 da Ronald Rivest, Adi Shamir e Leonard Adleman al MIT.

### Storia

- **1977**: Pubblicazione algoritmo RSA
- **1983**: MIT brevetta RSA (scaduto 2000)
- **1994**: RSA 129 fattorizzato (dopo 17 anni)
- **Oggi**: Standard de facto per firma digitale e key exchange

### Applicazioni

✅ **SSL/TLS**: Handshake HTTPS  
✅ **SSH**: Autenticazione chiave pubblica  
✅ **PGP/GPG**: Email cifrata  
✅ **JWT**: Firma JSON Web Tokens  
✅ **Certificati X.509**: PKI

## Matematica di Base

### Sicurezza: Fattorizzazione

RSA si basa sulla difficoltà di **fattorizzare** numeri grandi:

$$n = p \times q$$

Dove $p$ e $q$ sono primi grandi (1024 bit ciascuno).

**Facile**: Moltiplicare $p \times q = n$  
**Difficile**: Dato $n$, trovare $p$ e $q$

### Teorema di Eulero

$$a^{\phi(n)} \equiv 1 \pmod{n}$$

Dove $\phi(n)$ è la funzione di Eulero.

Per $n = p \times q$:

$$\phi(n) = (p-1)(q-1)$$

### Inverso Modulare

Dato $e$ e $\phi(n)$, trova $d$ tale che:

$$e \times d \equiv 1 \pmod{\phi(n)}$$

Usando **Extended Euclidean Algorithm**.

---

## Generazione Chiavi RSA

### Algoritmo Completo

1. **Scegli primi**: $p$ e $q$ (1024+ bit ciascuno)
2. **Calcola modulo**: $n = p \times q$
3. **Calcola totiente**: $\phi(n) = (p-1)(q-1)$
4. **Scegli esponente pubblico**: $e$ tale che $\gcd(e, \phi(n)) = 1$
   - Tipicamente $e = 65537 = 2^{16} + 1$ (primo di Fermat)
5. **Calcola esponente privato**: $d \equiv e^{-1} \pmod{\phi(n)}$

**Chiave pubblica**: $(n, e)$  
**Chiave privata**: $(n, d)$ (o $(p, q, d)$ per CRT)

### Implementazione da Zero

```python
import random
from math import gcd

def is_prime(n, k=5):
    """Test primalità Miller-Rabin"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # n - 1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Test k volte
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generate_prime(bits):
    """Genera primo di lunghezza bits"""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Assicura bits giusti e dispari
        if is_prime(p):
            return p

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(e, phi):
    """Calcola inverso modulare"""
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Inverso non esiste")
    return x % phi

def generate_keypair(bits=2048):
    """Genera coppia chiavi RSA"""
    
    # Genera due primi
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    # Assicura p != q
    while p == q:
        q = generate_prime(bits // 2)
    
    # Calcola n e phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Scegli e (65537 è standard)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)
    
    # Calcola d
    d = mod_inverse(e, phi)
    
    # Chiavi
    public_key = (n, e)
    private_key = (n, d, p, q)
    
    return public_key, private_key

# Test generazione (bit ridotti per demo)
public, private = generate_keypair(512)
n, e = public
_, d, p, q = private

print(f"p = {p}")
print(f"q = {q}")
print(f"n = {n}")
print(f"e = {e}")
print(f"d = {d}")
print(f"\nVerifica: (e * d) mod φ(n) = {(e * d) % ((p-1)*(q-1))}")
```

### Con Libreria Cryptography

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Genera chiavi RSA-2048
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Ottieni numeri
private_numbers = private_key.private_numbers()
public_numbers = public_key.public_numbers()

print(f"n = {public_numbers.n}")
print(f"e = {public_numbers.e}")
print(f"d = {private_numbers.d}")
print(f"p = {private_numbers.p}")
print(f"q = {private_numbers.q}")

# Esporta chiavi PEM
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'password')
)

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("\n=== Chiave Pubblica ===")
print(pem_public.decode())

# Salva su file
with open('rsa_private.pem', 'wb') as f:
    f.write(pem_private)
with open('rsa_public.pem', 'wb') as f:
    f.write(pem_public)
```

---

## Cifratura e Decifratura

### Formule Matematiche

**Cifratura** (con chiave pubblica):
$$C = M^e \mod n$$

**Decifratura** (con chiave privata):
$$M = C^d \mod n$$

### Dimostrazione Correttezza

$$M = C^d = (M^e)^d = M^{ed} \pmod{n}$$

Per Teorema di Eulero: $ed \equiv 1 \pmod{\phi(n)}$

Quindi: $ed = 1 + k\phi(n)$

$$M^{ed} = M^{1+k\phi(n)} = M \cdot (M^{\phi(n)})^k \equiv M \cdot 1^k = M \pmod{n}$$

### Implementazione Base (INSICURA!)

```python
def rsa_encrypt(message_int, public_key):
    """Cifratura RSA base (NO padding!)"""
    n, e = public_key
    return pow(message_int, e, n)

def rsa_decrypt(ciphertext_int, private_key):
    """Decifratura RSA base"""
    n, d, _, _ = private_key
    return pow(ciphertext_int, d, n)

# Test (SOLO DIDATTICO!)
public, private = generate_keypair(512)

message = 42
ciphertext = rsa_encrypt(message, public[:2])
plaintext = rsa_decrypt(ciphertext, private)

print(f"Message: {message}")
print(f"Ciphertext: {ciphertext}")
print(f"Plaintext: {plaintext}")
print(f"✅ Match: {message == plaintext}")
```

⚠️ **ATTENZIONE**: RSA textbook è INSICURO! Serve padding!

---

## Padding Schemes

### Perché Serve Padding?

❌ **Textbook RSA** vulnerabile a:
- **Determinismo**: Stesso plaintext → stesso ciphertext
- **Malleabilità**: $C_1 \times C_2 = (M_1 \times M_2)^e$
- **Small exponent**: Se $M^e < n$ → $C = M^e$ (niente modulo!)

### PKCS#1 v1.5 (DEPRECATO)

```
EM = 0x00 || 0x02 || PS || 0x00 || M
```

⚠️ Vulnerabile a **Bleichenbacher attack** (1998)

### OAEP (Optimal Asymmetric Encryption Padding)

**Standard moderno** (RFC 8017).

```
EM = 0x00 || maskedDB || maskedSeed

maskedDB = DB ⊕ MGF(seed)
maskedSeed = seed ⊕ MGF(maskedDB)

DB = Hash(L) || PS || 0x01 || M
```

#### Implementazione

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Genera chiavi
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Messaggio
messaggio = b"RSA con OAEP padding sicuro!"

# Cifratura con OAEP
ciphertext = public_key.encrypt(
    messaggio,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Plaintext: {messaggio}")
print(f"Ciphertext: {ciphertext.hex()[:64]}...")

# Decifratura
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Decrypted: {plaintext}")
print(f"✅ Match: {plaintext == messaggio}")

# Verifica: Stesso plaintext → ciphertext diverso!
ciphertext2 = public_key.encrypt(messaggio, padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
))

print(f"\nSame plaintext, different ciphertext:")
print(f"C1[:32] = {ciphertext[:32].hex()}")
print(f"C2[:32] = {ciphertext2[:32].hex()}")
print(f"✅ Different: {ciphertext != ciphertext2}")
```

---

## Firma Digitale RSA

### Schema

**Firma** (con chiave privata):
$$S = H(M)^d \mod n$$

**Verifica** (con chiave pubblica):
$$H(M) \stackrel{?}{=} S^e \mod n$$

### PSS Padding (Probabilistic Signature Scheme)

Standard moderno per firme RSA.

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Messaggio da firmare
documento = b"Contratto importante da firmare digitalmente"

# Firma con PSS
signature = private_key.sign(
    documento,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(f"Documento: {documento}")
print(f"Firma: {signature.hex()[:64]}...")

# Verifica firma
try:
    public_key.verify(
        signature,
        documento,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Firma VALIDA - documento autentico")
except Exception as e:
    print("❌ Firma NON VALIDA - documento modificato")

# Test con documento modificato
documento_fake = b"Contratto MODIFICATO da firmare digitalmente"

try:
    public_key.verify(
        signature,
        documento_fake,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Firma valida")
except:
    print("❌ Firma NON VALIDA - documento è stato modificato!")
```

---

## Hybrid Encryption

RSA per dati grandi è **lento**. Soluzione: **hybrid encryption**.

```
RSA (cifra chiave AES) + AES (cifra dati)
```

### Implementazione

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

class HybridEncryption:
    """RSA + AES Hybrid Encryption"""
    
    @staticmethod
    def encrypt(plaintext, recipient_public_key):
        """Cifra con hybrid scheme"""
        
        # 1. Genera chiave AES random
        aes_key = AESGCM.generate_key(bit_length=256)
        
        # 2. Cifra dati con AES-GCM
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, b"")
        
        # 3. Cifra chiave AES con RSA
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            'encrypted_key': encrypted_key,
            'nonce': nonce,
            'ciphertext': ciphertext
        }
    
    @staticmethod
    def decrypt(encrypted_data, recipient_private_key):
        """Decifra hybrid scheme"""
        
        # 1. Decifra chiave AES con RSA
        aes_key = recipient_private_key.decrypt(
            encrypted_data['encrypted_key'],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 2. Decifra dati con AES-GCM
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(
            encrypted_data['nonce'],
            encrypted_data['ciphertext'],
            b""
        )
        
        return plaintext

# Test con file grande
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Plaintext grande (10 MB)
plaintext = b"X" * (10 * 1024 * 1024)

# Cifra
import time
start = time.time()
encrypted = HybridEncryption.encrypt(plaintext, public_key)
encrypt_time = time.time() - start

print(f"Plaintext: {len(plaintext)} byte")
print(f"Encrypted key: {len(encrypted['encrypted_key'])} byte")
print(f"Ciphertext: {len(encrypted['ciphertext'])} byte")
print(f"Tempo cifratura: {encrypt_time:.3f}s")

# Decifra
start = time.time()
decrypted = HybridEncryption.decrypt(encrypted, private_key)
decrypt_time = time.time() - start

print(f"Tempo decifratura: {decrypt_time:.3f}s")
print(f"✅ Match: {decrypted == plaintext}")
```

---

## Chinese Remainder Theorem (CRT)

Ottimizzazione per decifratura/firma **4x più veloce**.

### Formula

Invece di: $M = C^d \mod n$

Calcola:
$$M_p = C^{d_p} \mod p$$
$$M_q = C^{d_q} \mod q$$

Dove:
- $d_p = d \mod (p-1)$
- $d_q = d \mod (q-1)$

Poi combina con CRT:
$$M = (M_p \cdot q \cdot q_{inv} + M_q \cdot p \cdot p_{inv}) \mod n$$

### Implementazione

```python
def rsa_decrypt_crt(ciphertext, private_key):
    """RSA decrypt con CRT (4x più veloce)"""
    n, d, p, q = private_key
    
    # Precalcola
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)  # Inverso modulare
    
    # CRT
    m1 = pow(ciphertext, dp, p)
    m2 = pow(ciphertext, dq, q)
    h = (qinv * (m1 - m2)) % p
    m = m2 + h * q
    
    return m

# Benchmark
import time

public, private = generate_keypair(2048)
message = 123456789

ciphertext = rsa_encrypt(message, public[:2])

# Metodo standard
start = time.time()
for _ in range(100):
    _ = rsa_decrypt(ciphertext, private)
std_time = time.time() - start

# Metodo CRT
start = time.time()
for _ in range(100):
    _ = rsa_decrypt_crt(ciphertext, private)
crt_time = time.time() - start

print(f"Standard: {std_time:.3f}s")
print(f"CRT:      {crt_time:.3f}s")
print(f"Speedup:  {std_time / crt_time:.1f}x")
```

---

## Attacchi RSA

### 1. Small Exponent Attack

Se $e$ piccolo e $M^e < n$:

$$C = M^e \pmod{n} = M^e$$

Basta calcolare radice e-esima!

```python
# ❌ Vulnerabile se e=3 e M piccolo
import gmpy2

e = 3
M = 1000
n = 10**100  # Grande

C = pow(M, e, n)

# Attacco: radice cubica
M_recovered = int(gmpy2.iroot(C, e)[0])
print(f"M original:  {M}")
print(f"M recovered: {M_recovered}")
```

**Mitigazione**: OAEP padding!

### 2. Common Modulus Attack

Se stesso $n$ usato con $(e_1, d_1)$ e $(e_2, d_2)$:

```python
# Alice cifra con e1: C1 = M^e1 mod n
# Bob cifra con e2:   C2 = M^e2 mod n

# Se gcd(e1, e2) = 1 → Attaccante recupera M!
# Usando: M = C1^a * C2^b mod n
# dove a*e1 + b*e2 = 1 (Bezout)
```

**Mitigazione**: Mai riusare $n$!

### 3. Bleichenbacher Attack (1998)

Attacco padding oracle su PKCS#1 v1.5.

**Mitigazione**: Usa OAEP!

### 4. Timing Attack

Misurando tempo di decifratura si può dedurre $d$.

**Mitigazione**: 
- CRT blinding
- Constant-time implementations

### 5. Wiener's Attack

Se $d < n^{0.25}$ → Attacco polinomiale!

**Mitigazione**: $d$ grande (almeno $n^{0.5}$)

---

## Dimensione Chiavi e Sicurezza

| Key Size | Sicurezza | Anno Sicuro | Uso |
|----------|-----------|-------------|-----|
| 1024 bit | ⚠️ Debole | < 2010 | Deprecato |
| 2048 bit | ✅ Sicuro | ~ 2030 | Standard attuale |
| 3072 bit | ✅ Alta | ~ 2050 | Raccomandato |
| 4096 bit | ✅ Molto alta | > 2050 | Paranoia/Governo |

### Performance vs Sicurezza

```python
import time

for key_size in [1024, 2048, 3072, 4096]:
    start = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    gen_time = time.time() - start
    
    public_key = private_key.public_key()
    msg = b"X" * 100
    
    # Benchmark cifratura
    start = time.time()
    for _ in range(100):
        _ = public_key.encrypt(msg, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    enc_time = (time.time() - start) / 100
    
    print(f"{key_size} bit: Gen={gen_time:.2f}s, Enc={enc_time*1000:.2f}ms")
```

---

## Best Practices

### ✅ Raccomandazioni

1. **Key size**: Minimo 2048 bit, raccomandato 3072+ bit
2. **Padding**: SEMPRE usa OAEP per cifratura, PSS per firme
3. **Hybrid**: Combina RSA + AES per dati grandi
4. **RNG**: Usa CSPRNG per generazione chiavi
5. **Key rotation**: Cambia chiavi periodicamente
6. **Storage**: Proteggi chiave privata con password forte

### ❌ Da Evitare

1. **Textbook RSA**: Mai cifrare senza padding!
2. **PKCS#1 v1.5**: Usa OAEP
3. **Small e con small M**: Vulnerabile
4. **Riuso n**: Mai condividere modulo
5. **Key < 2048**: Troppo debole
6. **Implementazione custom**: Usa librerie testate

---

## Codice Completo: Sistema RSA

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class RSASystem:
    """Sistema completo RSA"""
    
    def __init__(self, key_size=2048):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
    
    def save_keys(self, private_path, public_path, password=None):
        """Salva chiavi su file"""
        # Chiave privata (protetta)
        encryption = serialization.BestAvailableEncryption(password) \
            if password else serialization.NoEncryption()
        
        with open(private_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        
        # Chiave pubblica
        with open(public_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    @staticmethod
    def load_private_key(path, password=None):
        """Carica chiave privata"""
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password
            )
    
    @staticmethod
    def load_public_key(path):
        """Carica chiave pubblica"""
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read())
    
    def encrypt(self, plaintext):
        """Cifra con OAEP"""
        return self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, ciphertext):
        """Decifra"""
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def sign(self, message):
        """Firma con PSS"""
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def verify(self, message, signature):
        """Verifica firma"""
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

# Test completo
rsa_sys = RSASystem(2048)

# Salva chiavi
rsa_sys.save_keys('private.pem', 'public.pem', b'strongpassword')

# Cifra
msg = b"Messaggio segreto"
encrypted = rsa_sys.encrypt(msg)
print(f"Encrypted: {encrypted[:32].hex()}...")

# Decifra
decrypted = rsa_sys.decrypt(encrypted)
print(f"Decrypted: {decrypted}")

# Firma
signature = rsa_sys.sign(msg)
print(f"Signature: {signature[:32].hex()}...")

# Verifica
valid = rsa_sys.verify(msg, signature)
print(f"✅ Signature valid: {valid}")

# Verifica messaggio fake
fake = rsa_sys.verify(b"Fake message", signature)
print(f"❌ Fake valid: {fake}")
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 7 - Introduzione Crittografia Asimmetrica](07_introduzione_alla_crittografia_asimmetrica.md)
- **Successivo**: [Capitolo 9 - Diffie-Hellman](09_diffie-hellman.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 8017: PKCS#1 v2.2 (RSA Cryptography Standard)
- "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems" (RSA paper 1978)
- NIST SP 800-57: Key Management Recommendations

**Nota**: RSA è solido ma quantum-vulnerable! Post-quantum alternatives in arrivo.
