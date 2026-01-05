# Capitolo 1 - Introduzione alla Crittografia

> **Parte 1 - FONDAMENTI DI CRITTOGRAFIA**

---

## 1.1 Cos'è la Crittografia

La **crittografia** (dal greco *kryptós* = nascosto e *gráphein* = scrivere) è la scienza che studia le tecniche per proteggere le informazioni attraverso la trasformazione dei dati in una forma illeggibile per chi non possiede le chiavi corrette.

### Definizione
La crittografia è l'insieme di tecniche matematiche e informatiche utilizzate per:
- Proteggere la confidenzialità delle informazioni
- Garantire l'integrità dei dati
- Autenticare l'identità degli utenti
- Assicurare il non ripudio delle comunicazioni

### Applicazioni Quotidiane
- 🔐 Login e autenticazione sui siti web
- 💳 Transazioni bancarie online
- 📱 Messaggistica istantanea cifrata (WhatsApp, Signal)
- 🌐 Navigazione sicura (HTTPS)
- 📧 Email cifrate
- 💰 Criptovalute (Bitcoin, Ethereum)

---

## 1.2 Storia della Crittografia

### 1.2.1 Cifrari Classici

#### Cifrario di Cesare (50 a.C.)
Utilizzato da Giulio Cesare per comunicazioni militari.

**Principio**: Spostamento alfabetico di *n* posizioni.

```
Testo in chiaro:  CIAO
Shift di 3:       FLDR
```

**Esempio Python:**
```python
def cesare_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# Test
plaintext = "CIAO"
ciphertext = cesare_encrypt(plaintext, 3)
print(f"Cifrato: {ciphertext}")  # Output: FLDR
```

**Vulnerabilità**: Solo 25 possibili chiavi → attacco brute-force banale.

#### Cifrario di Vigenère (1553)
Evoluzione del cifrario di Cesare con chiave variabile.

**Principio**: Usa una parola chiave ripetuta.

```
Testo:    CIAO MONDO
Chiave:   KEYK EYKEY
Cifrato:  MSSG QSRHS
```

**Tabula recta** (Tavola di Vigenère):
```
    A B C D E F G H I ...
A | A B C D E F G H I ...
B | B C D E F G H I J ...
C | C D E F G H I J K ...
...
```

### 1.2.2 Enigma e la Seconda Guerra Mondiale

**Enigma** (1918-1945): Macchina elettromeccanica usata dalla Germania nazista.

**Caratteristiche:**
- 3-5 rotori intercambiabili
- Pannello di connessione (plugboard)
- 158 quintilioni di configurazioni possibili

**Breaking Enigma:**
- Alan Turing e il team di Bletchley Park
- Macchina Bombe per decifrare i messaggi
- Contributo decisivo alla vittoria alleata

**Lezione**: Anche sistemi complessi possono essere violati con:
- Errori umani nella procedura operativa
- Analisi matematica avanzata
- Capacità computazionale

### 1.2.3 Era Moderna e Computer

**1976**: Whitfield Diffie e Martin Hellman introducono la **crittografia a chiave pubblica**

**1977**: Ron Rivest, Adi Shamir e Leonard Adleman creano **RSA**

**2001**: **AES** diventa lo standard di cifratura simmetrica

**2008**: Satoshi Nakamoto lancia **Bitcoin** (crittografia applicata alla blockchain)

**Oggi**: Crittografia end-to-end nelle app di messaggistica, HTTPS ovunque, preoccupazioni per il quantum computing

---

## 1.3 Terminologia Fondamentale

### 1.3.1 Testo in Chiaro (Plaintext)
Il messaggio originale, leggibile e comprensibile.

**Esempio**: `"Il mio PIN è 1234"`

### 1.3.2 Testo Cifrato (Ciphertext)
Il messaggio dopo la cifratura, incomprensibile senza la chiave.

**Esempio**: `"U2FsdGVkX1+8QJKf7Vx..."`

### 1.3.3 Cifratura e Decifratura

**Cifratura (Encryption)**: Trasformazione plaintext → ciphertext
```
E(plaintext, key) = ciphertext
```

**Decifratura (Decryption)**: Trasformazione ciphertext → plaintext
```
D(ciphertext, key) = plaintext
```

**Proprietà fondamentale**:
```
D(E(plaintext, key), key) = plaintext
```

### 1.3.4 Chiave Crittografica

La **chiave** è un valore segreto usato per cifrare e decifrare.

**Tipi:**
- **Chiave simmetrica**: Stessa chiave per cifrare e decifrare
- **Chiavi asimmetriche**: Coppia di chiavi (pubblica/privata)

**Lunghezza**: Determina la sicurezza
- AES-128: 128 bit = 2^128 combinazioni possibili
- RSA-2048: 2048 bit = numero con 617 cifre decimali

---

## 1.4 Obiettivi della Crittografia

### 1.4.1 Confidenzialità
Garantire che solo i destinatari autorizzati possano leggere il messaggio.

**Esempio**: Email cifrata con PGP

**Meccanismo**: Cifratura simmetrica (AES) o asimmetrica (RSA)

### 1.4.2 Integrità
Assicurare che il messaggio non sia stato modificato durante la trasmissione.

**Esempio**: Verifica checksum SHA-256 di un file scaricato

**Meccanismo**: Funzioni hash (SHA-256, SHA-3), HMAC

### 1.4.3 Autenticazione
Verificare l'identità del mittente del messaggio.

**Esempio**: Certificato SSL/TLS che conferma l'identità del server

**Meccanismo**: Firma digitale, certificati X.509

### 1.4.4 Non Ripudio
Impedire al mittente di negare di aver inviato il messaggio.

**Esempio**: Firma digitale su un contratto elettronico

**Meccanismo**: Firma digitale con timestamp

---

## Schema Riassuntivo

```
┌─────────────────────────────────────────────────────────┐
│                    CRITTOGRAFIA                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Obiettivi:                                             │
│  • Confidenzialità    (Cifratura)                       │
│  • Integrità          (Hash/MAC)                        │
│  • Autenticazione     (Firma digitale/Certificati)      │
│  • Non Ripudio        (Firma + Timestamp)               │
│                                                         │
│  Componenti:                                            │
│  • Algoritmi crittografici                              │
│  • Chiavi segrete                                       │
│  • Protocolli di comunicazione                          │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Esercizi

### Esercizio 1.1: Cifrario di Cesare (★☆☆)
1. Cifra il messaggio "HELLO" con shift di 5
2. Decifra il messaggio "MJQQT" con shift di 5
3. Scrivi un programma che testi tutti i possibili shift (brute-force)

### Esercizio 1.2: Cifrario di Vigenère (★★☆)
1. Cifra "ATTACKATDAWN" con chiave "LEMON"
2. Implementa una funzione di cifratura/decifratura Vigenère
3. Ricerca come funziona l'attacco di Kasiski

### Esercizio 1.3: Analisi (★★☆)
1. Elenca 5 applicazioni quotidiane della crittografia
2. Per ognuna, identifica quale obiettivo crittografico viene soddisfatto
3. Ricerca un caso storico di violazione crittografica

### Esercizio 1.4: Terminologia (★☆☆)
Completa le definizioni:
1. Il _________ è il messaggio originale prima della cifratura
2. La _________ è il valore segreto usato per cifrare
3. L'_________ garantisce che il messaggio non sia stato alterato
4. Il _________ impedisce di negare l'invio di un messaggio

---

## Domande di Verifica

1. Qual è la differenza principale tra crittografia classica e moderna?
2. Perché il cifrario di Cesare è considerato insicuro?
3. Qual è stato il contributo di Alan Turing alla crittografia?
4. Cosa significa "confidenzialità" nel contesto crittografico?
5. Dai un esempio pratico di "non ripudio"

---

## Riferimenti

- [The Code Book - Simon Singh](https://simonsingh.net/books/the-code-book/)
- [Applied Cryptography - Bruce Schneier](https://www.schneier.com/books/applied-cryptography/)
- [Crypto101 - Free Cryptography Book](https://www.crypto101.io/)

---

**Prossimo Capitolo**: [02 - Principi di Sicurezza](02_principi_di_sicurezza.md)
