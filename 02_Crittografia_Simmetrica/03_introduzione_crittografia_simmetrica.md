# Capitolo 3 - Introduzione alla Crittografia Simmetrica

> **Parte 2 - CRITTOGRAFIA SIMMETRICA**

---

## 3.1 Concetti Base

### Definizione
La **crittografia simmetrica** (o a chiave segreta) utilizza la **stessa chiave** per cifrare e decifrare i dati.

```
┌─────────┐    Chiave K     ┌─────────┐    Chiave K     ┌─────────┐
│         │ ──────────────> │         │ ──────────────> │         │
│ Mittente│                 │Cifrato  │                 │Destinat.│
│         │                 │         │                 │         │
└─────────┘                 └─────────┘                 └─────────┘
   Alice     E(M, K) = C                  D(C, K) = M      Bob
```

### Caratteristiche Principali
- **Stessa chiave** per cifratura e decifratura
- **Velocità** elevata (hardware/software optimization)
- **Chiave condivisa** tra mittente e destinatario
- **Problema**: Distribuzione sicura della chiave

---

## 3.2 Vantaggi e Svantaggi

### ✅ Vantaggi

#### 1. **Velocità**
- 100-1000x più veloce della crittografia asimmetrica
- Ottimizzata per processori moderni (AES-NI instructions)

**Benchmark comparativo:**
```
AES-256-GCM:     ~1.5 GB/s
ChaCha20:        ~1.0 GB/s
RSA-2048:        ~0.5 MB/s  (3000x più lento!)
```

#### 2. **Efficienza**
- Basso consumo di CPU
- Ideale per dispositivi embedded
- Adatto per cifrare grandi volumi di dati

#### 3. **Chiavi Più Corte**
- 256 bit forniscono sicurezza eccellente
- RSA richiede ≥2048 bit per sicurezza comparabile

### ❌ Svantaggi

#### 1. **Distribuzione delle Chiavi**
**Problema**: Come condividere in modo sicuro la chiave?

**Scenario**:
- Alice e Bob vogliono comunicare in modo sicuro
- Devono prima scambiarsi la chiave segreta
- Se il canale è insicuro, la chiave può essere intercettata

**Soluzioni**:
- Scambio fisico (USB, carta)
- Key Exchange Protocols (Diffie-Hellman)
- Cifratura asimmetrica per scambiare la chiave simmetrica

#### 2. **Scalabilità**
Con **n** utenti, servono **n(n-1)/2** chiavi uniche.

```
2 utenti:    1 chiave
5 utenti:   10 chiavi
10 utenti:  45 chiavi
100 utenti: 4950 chiavi!
```

#### 3. **Gestione delle Chiavi**
- Storage sicuro
- Rotazione periodica
- Revoca
- Backup

---

## 3.3 Applicazioni Pratiche

### 1. **Cifratura di File e Disk**
```bash
# Cifrare un file con AES-256
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc

# Decifrare
openssl enc -d -aes-256-cbc -in file.enc -out file.txt
```

**Applicazioni:**
- BitLocker (Windows)
- FileVault (macOS)
- LUKS (Linux)
- VeraCrypt

### 2. **VPN**
Tunnel cifrati per comunicazioni sicure:
- IPsec
- OpenVPN
- WireGuard (ChaCha20-Poly1305)

### 3. **TLS/SSL**
HTTPS usa crittografia simmetrica per il trasferimento dati:
```
1. Handshake con RSA/ECDH (asimmetrica)
2. Scambio chiave di sessione
3. Comunicazione con AES-GCM (simmetrica) ← Bulk encryption
```

### 4. **Database Encryption**
- Transparent Data Encryption (TDE)
- Column-level encryption
- Backup encryption

### 5. **Messaggistica**
- Signal Protocol (Double Ratchet con AES)
- WhatsApp
- Telegram (Secret Chats)

---

## 3.4 Gestione delle Chiavi

### Ciclo di Vita della Chiave

```
┌──────────────┐
│  Generazione │ ← CSPRNG, lunghezza adeguata
└──────┬───────┘
       │
┌──────▼───────┐
│ Distribuzione│ ← Diffie-Hellman, cifratura asimmetrica
└──────┬───────┘
       │
┌──────▼───────┐
│   Storage    │ ← HSM, Key Vault, encrypted keystore
└──────┬───────┘
       │
┌──────▼───────┐
│    Uso       │ ← Cifratura/decifratura dati
└──────┬───────┘
       │
┌──────▼───────┐
│  Rotazione   │ ← Cambio periodico (es. ogni 90 giorni)
└──────┬───────┘
       │
┌──────▼───────┐
│ Distruzione  │ ← Secure wipe, zero-fill
└──────────────┘
```

### Best Practices

#### 1. **Generazione**
```python
import secrets

# ✅ Corretto
key = secrets.token_bytes(32)  # 256 bit per AES-256

# ❌ Errato
key = b"mypassword123456"  # Bassa entropia
```

#### 2. **Storage**
```python
# ❌ MAI fare così
SECRET_KEY = "abc123def456..."  # Hardcoded

# ✅ Usare environment variables
import os
SECRET_KEY = os.environ['SECRET_KEY']

# ✅ O un key management service
from azure.keyvault.secrets import SecretClient
secret = client.get_secret("database-encryption-key")
```

#### 3. **Rotazione**
```python
def rotate_key(old_key, new_key):
    """
    Rotazione chiave:
    1. Decifra dati con old_key
    2. Cifra dati con new_key
    """
    data = decrypt(ciphertext, old_key)
    new_ciphertext = encrypt(data, new_key)
    return new_ciphertext
```

#### 4. **Derivazione da Password**
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Deriva una chiave da password
password = b"user_password"
salt = os.urandom(16)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,  # OWASP recommendation 2023
)
key = kdf.derive(password)
```

---

## Confronto: Simmetrica vs Asimmetrica

| Caratteristica | Simmetrica | Asimmetrica |
|----------------|------------|-------------|
| **Chiavi** | Una chiave condivisa | Coppia (pubblica/privata) |
| **Velocità** | Molto veloce | Lenta |
| **Lunghezza chiave** | 128-256 bit | 2048-4096 bit |
| **Uso tipico** | Cifrare dati | Scambiare chiavi, firme |
| **Scalabilità** | O(n²) chiavi | O(n) chiavi |
| **Esempi** | AES, ChaCha20 | RSA, ECC |

---

## Esempio Pratico: Cifratura con AES

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_aes_cbc(plaintext: bytes, key: bytes) -> tuple:
    """
    Cifra dati con AES-256-CBC
    Returns: (iv, ciphertext)
    """
    # Genera IV casuale
    iv = os.urandom(16)
    
    # Crea cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Padding (PKCS#7)
    pad_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_length] * pad_length)
    
    # Cifra
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return iv, ciphertext

def decrypt_aes_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decifra dati AES-256-CBC"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decifra
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Rimuovi padding
    pad_length = plaintext[-1]
    return plaintext[:-pad_length]

# Test
key = os.urandom(32)  # 256 bit
message = b"Messaggio segreto da cifrare"

iv, ciphertext = encrypt_aes_cbc(message, key)
decrypted = decrypt_aes_cbc(iv, ciphertext, key)

print(f"Originale:  {message}")
print(f"Cifrato:    {ciphertext.hex()}")
print(f"Decifrato:  {decrypted}")
```

---

## Esercizi

### Esercizio 3.1: Confronto (★☆☆)
1. Elenca 3 vantaggi della crittografia simmetrica
2. Elenca 3 svantaggi
3. Perché TLS usa sia crittografia simmetrica che asimmetrica?

### Esercizio 3.2: Calcolo Chiavi (★★☆)
Calcola quante chiavi univoche servono per:
1. 10 utenti
2. 50 utenti
3. 1000 utenti

Formula: n(n-1)/2

### Esercizio 3.3: Cifratura File (★★☆)
1. Usa OpenSSL per cifrare un file di testo
2. Verifica che il file cifrato sia illeggibile
3. Decifra il file e confronta con l'originale

### Esercizio 3.4: Key Derivation (★★★)
Implementa in Python:
1. Derivazione chiave da password con PBKDF2
2. Salvataggio sicuro del salt
3. Verifica della password

---

## Domande di Verifica

1. Qual è la differenza principale tra crittografia simmetrica e asimmetrica?
2. Perché la distribuzione delle chiavi è un problema nella crittografia simmetrica?
3. In quali scenari è preferibile usare crittografia simmetrica?
4. Cosa significa "key rotation" e perché è importante?
5. Perché non si dovrebbe derivare una chiave direttamente da una password?

---

## Riferimenti

- [NIST SP 800-38A - Block Cipher Modes](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)

---

**Capitolo Precedente**: [02 - Principi di Sicurezza](02_principi_di_sicurezza.md)  
**Prossimo Capitolo**: [04 - Cifrari a Blocchi](04_cifrari_a_blocchi.md)
