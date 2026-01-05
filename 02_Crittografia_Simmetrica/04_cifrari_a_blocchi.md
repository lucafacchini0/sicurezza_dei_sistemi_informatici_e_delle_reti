# Capitolo 4 - Cifrari a Blocchi

> **Parte 2 - CRITTOGRAFIA SIMMETRICA**

---

## 4.1 Principi di Funzionamento

### Definizione
Un **cifrario a blocchi** (block cipher) cifra dati a blocchi di dimensione fissa, trasformando ogni blocco di plaintext in un blocco di ciphertext della stessa dimensione.

```
Plaintext:   [Blocco 1][Blocco 2][Blocco 3]...
                ↓          ↓          ↓
             E(K,·)     E(K,·)     E(K,·)
                ↓          ↓          ↓
Ciphertext:  [Cifrato1][Cifrato2][Cifrato3]...
```

### Caratteristiche
- **Dimensione blocco fissa**: tipicamente 64 o 128 bit
- **Permutazione**: Ogni blocco è trasformato in modo reversibile
- **Chiave**: Determina la trasformazione specifica
- **Determinismo**: Stesso input + chiave = stesso output

---

## 4.2 DES (Data Encryption Standard)

### Storia
- **1977**: Adottato come standard federale USA (FIPS 46)
- Basato su Lucifer (IBM)
- Controversie su lunghezza chiave e S-boxes

### Specifiche
- **Dimensione blocco**: 64 bit
- **Lunghezza chiave**: 56 bit (64 bit con 8 bit di parità)
- **Rounds**: 16
- **Struttura**: Feistel Network

### 4.2.1 Struttura di DES

```
┌──────────────────────────────────────┐
│   Plaintext (64 bit)                 │
└──────────────┬───────────────────────┘
               │
      ┌────────▼────────┐
      │ Initial Permutation (IP)        │
      └────────┬────────┘
               │
      ┌────────▼────────┐
      │  L₀ (32)  R₀ (32) │
      └────────┬────────┘
               │
          ┌───▼───┐
          │Round 1│ (K₁)
          └───┬───┘
              ⋮
          ┌───▼───┐
          │Round 16│ (K₁₆)
          └───┬───┘
               │
      ┌────────▼────────┐
      │  L₁₆      R₁₆    │
      └────────┬────────┘
               │
      ┌────────▼────────┐
      │Final Permutation (IP⁻¹)         │
      └────────┬────────┘
               │
┌──────────────▼───────────────────────┐
│   Ciphertext (64 bit)                │
└──────────────────────────────────────┘
```

### 4.2.2 Funzione di Feistel

```python
def des_round(L, R, subkey):
    """
    Un round di DES
    L, R: metà sinistra e destra (32 bit)
    subkey: sottochiave del round (48 bit)
    """
    # Espansione: 32 bit → 48 bit
    expanded_R = expansion(R)
    
    # XOR con sottochiave
    xor_result = expanded_R ^ subkey
    
    # S-boxes: 48 bit → 32 bit
    sbox_output = apply_sboxes(xor_result)
    
    # Permutazione
    permuted = permutation(sbox_output)
    
    # Nuove metà
    new_R = L ^ permuted
    new_L = R
    
    return new_L, new_R
```

### 4.2.3 Vulnerabilità di DES

#### 1. **Chiave Troppo Corta**
- 2^56 ≈ 72 quadrilioni di combinazioni
- **1998**: EFF DES Cracker rompe DES in 56 ore
- **1999**: distributed.net rompe DES in 22 ore
- Oggi: cracca bile in poche ore con hardware comune

#### 2. **Attacchi Noti**
- **Differential Cryptanalysis**: Richiede 2^47 plaintext scelti
- **Linear Cryptanalysis**: Richiede 2^43 plaintext noti
- **Weak keys**: 4 chiavi deboli, 12 semi-deboli

**Conclusione**: DES è **OBSOLETO** e non deve essere usato.

---

## 4.3 3DES (Triple DES)

### Soluzione Temporanea
Per estendere la vita di DES senza cambiare algoritmo.

### Schema EDE (Encrypt-Decrypt-Encrypt)
```
Ciphertext = E_K3(D_K2(E_K1(Plaintext)))
```

### Configurazioni

#### 1. **Keying Option 1** (3 chiavi diverse)
- K1 ≠ K2 ≠ K3
- Lunghezza chiave effettiva: 168 bit
- Sicurezza: ~112 bit (meet-in-the-middle)

#### 2. **Keying Option 2** (2 chiavi)
- K1 ≠ K2, K3 = K1
- Lunghezza chiave: 112 bit
- Più comune

#### 3. **Keying Option 3** (1 chiave)
- K1 = K2 = K3
- Equivalente a DES singolo
- **Non sicuro**

### Performance
```
DES:     ~280 MB/s
3DES:    ~90 MB/s  (3x più lento)
AES:     ~1500 MB/s
```

### Status Attuale
- **2023**: NIST depreca 3DES
- Sostituire con AES

---

## 4.4 AES (Advanced Encryption Standard)

### Storia
- **1997**: NIST lancia competizione per sostituire DES
- **2000**: Rijndael vince (Joan Daemen e Vincent Rijmen)
- **2001**: Adottato come FIPS 197

### Specifiche

| Parametro | AES-128 | AES-192 | AES-256 |
|-----------|---------|---------|---------|
| **Chiave** | 128 bit | 192 bit | 256 bit |
| **Rounds** | 10 | 12 | 14 |
| **Blocco** | 128 bit | 128 bit | 128 bit |

### 4.4.1 Architettura di AES

AES opera su una **matrice 4×4 di byte** (state):

```
┌────┬────┬────┬────┐
│ a₀ │ a₄ │ a₈ │ a₁₂│
├────┼────┼────┼────┤
│ a₁ │ a₅ │ a₉ │ a₁₃│
├────┼────┼────┼────┤
│ a₂ │ a₆ │ a₁₀│ a₁₄│
├────┼────┼────┼────┤
│ a₃ │ a₇ │ a₁₁│ a₁₅│
└────┴────┴────┴────┘
```

### 4.4.2 Operazioni di un Round

#### 1. **SubBytes**
Sostituzione non lineare usando S-box:
```
┌────┬────┬────┬────┐       ┌────┬────┬────┬────┐
│ 53 │ 89 │ 0f │ 4e │       │ ed │ 62 │ 76 │ 9b │
├────┼────┼────┼────┤ S-box ├────┼────┼────┼────┤
│ 2c │ 6e │ c1 │ 31 │ ───>  │ 37 │ bb │ c0 │ c2 │
├────┼────┼────┼────┤       ├────┼────┼────┼────┤
│ ... │ ... │ ... │ ... │       │ ... │ ... │ ... │ ... │
└────┴────┴────┴────┘       └────┴────┴────┴────┘
```

#### 2. **ShiftRows**
Rotazione ciclica delle righe:
```
┌────┬────┬────┬────┐       ┌────┬────┬────┬────┐
│ a₀ │ a₄ │ a₈ │ a₁₂│       │ a₀ │ a₄ │ a₈ │ a₁₂│  (no shift)
├────┼────┼────┼────┤       ├────┼────┼────┼────┤
│ a₁ │ a₅ │ a₉ │ a₁₃│ ───>  │ a₅ │ a₉ │ a₁₃│ a₁ │  (shift 1)
├────┼────┼────┼────┤       ├────┼────┼────┼────┤
│ a₂ │ a₆ │ a₁₀│ a₁₄│       │ a₁₀│ a₁₄│ a₂ │ a₆ │  (shift 2)
├────┼────┼────┼────┤       ├────┼────┼────┼────┤
│ a₃ │ a₇ │ a₁₁│ a₁₅│       │ a₁₅│ a₃ │ a₇ │ a₁₁│  (shift 3)
└────┴────┴────┴────┘       └────┴────┴────┴────┘
```

#### 3. **MixColumns**
Moltiplicazione matriciale in GF(2^8):
```
┌────┐   ┌──────────┐ ┌────┐
│ b₀ │   │ 02 03 01 01│ │ a₀ │
│ b₁ │ = │ 01 02 03 01│ │ a₁ │
│ b₂ │   │ 01 01 02 03│ │ a₂ │
│ b₃ │   │ 03 01 01 02│ │ a₃ │
└────┘   └──────────┘ └────┘
```

#### 4. **AddRoundKey**
XOR con la sottochiave del round:
```
State XOR RoundKey
```

### 4.4.3 Key Expansion

Genera sottochiavi per ogni round dalla chiave master:

```python
def aes_key_expansion(key):
    """
    Espansione chiave AES
    key: 16 bytes (AES-128)
    returns: 176 bytes (11 round keys)
    """
    Nk = 4  # Parole da 32 bit nella chiave
    Nr = 10  # Numero di rounds per AES-128
    
    # ... implementazione completa
    pass
```

### 4.4.4 AES-128, AES-192, AES-256

**Quale scegliere?**

| | AES-128 | AES-192 | AES-256 |
|---|---------|---------|---------|
| **Sicurezza** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Velocità** | Veloce | Media | Più lenta |
| **Uso tipico** | Standard | Raro | Alto valore |

**Raccomandazione**: AES-128 è sufficiente per la maggior parte degli usi. AES-256 per dati ultra-sensibili.

---

## 4.5 Altri Algoritmi

### 4.5.1 Blowfish
- Progettato da Bruce Schneier (1993)
- Blocco: 64 bit
- Chiave: 32-448 bit
- **Problema**: Blocco piccolo → vulnerabile a attacchi birthday

### 4.5.2 Twofish
- Finalista AES
- Blocco: 128 bit
- Chiave: 128, 192, 256 bit
- Molto sicuro ma più lento di AES

### 4.5.3 ChaCha20
- Cifrario a **stream** (non a blocchi, ma simile)
- Progettato da Daniel J. Bernstein
- Molto veloce su software (no AES-NI)
- Usato in TLS 1.3, WireGuard, Android

**Confronto velocità (senza AES-NI):**
```
ChaCha20: 100%
AES:      60%
```

**Con AES-NI hardware:**
```
AES:      100%
ChaCha20: 70%
```

---

## Esempio Pratico: AES-256

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Genera chiave di 256 bit
key = os.urandom(32)

# Genera IV casuale
iv = os.urandom(16)

# Crea cipher AES-256-CBC
cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
)

# Cifra
plaintext = b"Message to encrypt. Must be padded!"
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Decifra
decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()

print(f"Plaintext:  {plaintext}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Decrypted:  {decrypted}")
```

---

## Esercizi

### Esercizio 4.1: DES History (★☆☆)
1. Ricerca il DES Cracker della EFF
2. Calcola quanto tempo ci vorrebbe oggi con GPU moderne
3. Perché 3DES non triplica la sicurezza?

### Esercizio 4.2: AES Operations (★★☆)
1. Disegna la matrice state di AES con un messaggio a scelta
2. Applica manualmente SubBytes con la S-box
3. Applica ShiftRows

### Esercizio 4.3: Implementazione (★★★)
1. Implementa un cifrario a blocchi semplice (toy cipher)
2. Usa operazioni XOR e permutazioni
3. Testa con diversi input

### Esercizio 4.4: Performance (★★☆)
Scrivi un benchmark che confronta:
1. AES-128 vs AES-256
2. Cifratura di file di diverse dimensioni
3. Misura tempo e throughput (MB/s)

---

## Domande di Verifica

1. Qual è la differenza tra DES e 3DES?
2. Perché AES ha sostituito DES?
3. Cosa fanno le operazioni SubBytes e MixColumns in AES?
4. Quando si dovrebbe usare AES-256 invece di AES-128?
5. Cos'è un cifrario a blocchi?

---

## Riferimenti

- [FIPS 197 - AES Specification](https://csrc.nist.gov/publications/detail/fips/197/final)
- [The Design of Rijndael - Daemen & Rijmen](https://www.springer.com/gp/book/9783540425809)
- [A Stick Figure Guide to AES](http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html)

---

**Capitolo Precedente**: [03 - Introduzione alla Crittografia Simmetrica](03_introduzione_crittografia_simmetrica.md)  
**Prossimo Capitolo**: [05 - Modi di Operazione](05_modi_di_operazione.md)
