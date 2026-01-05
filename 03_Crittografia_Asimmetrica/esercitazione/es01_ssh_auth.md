# Autenticazione SSH con Chiave Pubblica/Privata

## Indice
1. [Introduzione](#introduzione)
2. [Teoria](#teoria)
3. [Prerequisiti](#prerequisiti)
4. [Esercitazione Pratica](#esercitazione-pratica)
5. [Verifica e Troubleshooting](#verifica-e-troubleshooting)
6. [Esercizi](#esercizi)

---

## Introduzione

SSH (Secure Shell) è un protocollo crittografico utilizzato per comunicare in modo sicuro con server remoti. In questa guida imparerai come configurare l'autenticazione basata su chiavi crittografiche, un metodo più sicuro rispetto all'autenticazione con password.

### Obiettivi della Lezione
- Comprendere il funzionamento della crittografia asimmetrica
- Generare una coppia di chiavi SSH (pubblica/privata)
- Configurare l'accesso al server senza password
- Collegare al server `cognome.nome@w4s.filippobilardo.it -p 2222`

---

## Teoria

### Cos'è SSH?

**SSH (Secure Shell)** è un protocollo di rete che permette di:
- Accedere in modo sicuro a server remoti
- Eseguire comandi su macchine remote
- Trasferire file in modo sicuro (SCP, SFTP)
- Creare tunnel crittografati

### Crittografia Asimmetrica

L'autenticazione SSH con chiavi utilizza la **crittografia asimmetrica**, che si basa su due chiavi matematicamente correlate:

#### 1. **Chiave Privata** (Private Key)
- Deve rimanere **segreta** e conservata solo sul tuo computer
- Non deve mai essere condivisa o trasmessa
- Utilizzata per **decifrare** messaggi e **firmare** digitalmente
- Generalmente memorizzata in `~/.ssh/id_rsa` o `~/.ssh/id_ed25519`

#### 2. **Chiave Pubblica** (Public Key)
- Può essere **condivisa liberamente**
- Viene copiata sul server remoto
- Utilizzata per **cifrare** messaggi destinati al possessore della chiave privata
- Generalmente memorizzata in `~/.ssh/id_rsa.pub` o `~/.ssh/id_ed25519.pub`

### Come Funziona l'Autenticazione?

```
┌─────────────┐                           ┌─────────────┐
│   CLIENT    │                           │   SERVER    │
│             │                           │             │
│  ┌────────┐ │                           │  ┌────────┐ │
│  │ Chiave │ │   1. Richiesta connessione│  │ Chiave │ │
│  │Privata │ │──────────────────────────>│  │Pubblica│ │
│  └────────┘ │                           │  └────────┘ │
│             │   2. Challenge cifrato    │             │
│             │<──────────────────────────│             │
│             │                           │             │
│  Decifrare  │   3. Risposta firmata     │  Verifica   │
│  challenge  │──────────────────────────>│  firma      │
│             │                           │             │
│             │   4. Accesso consentito   │             │
│             │<──────────────────────────│             │
└─────────────┘                           └─────────────┘
```

**Processo passo-passo:**

1. Il client invia una richiesta di connessione al server
2. Il server controlla se esiste la chiave pubblica del client in `~/.ssh/authorized_keys`
3. Il server genera un **challenge** (messaggio casuale) e lo cifra con la chiave pubblica del client
4. Il client decifra il challenge con la sua chiave privata
5. Il client firma il challenge e lo rispedisce al server
6. Il server verifica la firma con la chiave pubblica
7. Se la verifica ha successo, l'accesso viene concesso

### Vantaggi dell'Autenticazione con Chiavi

✅ **Sicurezza maggiore**: Le chiavi sono molto più lunghe e complesse delle password  
✅ **Nessuna trasmissione di credenziali**: La chiave privata non lascia mai il client  
✅ **Protezione da attacchi brute-force**: Impossibile indovinare una chiave di 2048+ bit  
✅ **Automazione**: Permette script e connessioni automatiche senza inserire password  
✅ **Gestione centralizzata**: Facile revocare l'accesso rimuovendo la chiave pubblica dal server  

### Tipi di Algoritmi per Chiavi SSH

| Algoritmo | Lunghezza | Sicurezza | Velocità | Raccomandato |
|-----------|-----------|-----------|----------|--------------|
| RSA | 2048-4096 bit | Buona | Media | ✅ Sì |
| DSA | 1024 bit | Obsoleto | - | ❌ No |
| ECDSA | 256-521 bit | Buona | Alta | ⚠️ Dipende |
| Ed25519 | 256 bit | Ottima | Molto alta | ✅ Sì (moderno) |

**Raccomandazione**: Utilizzare **Ed25519** per nuove chiavi (più veloce e sicuro), o **RSA 4096** per compatibilità con sistemi più vecchi.

---

## Prerequisiti

### Software Necessario

#### Windows
- **Git Bash** (consigliato) - installato con Git for Windows
- **PuTTY** + **PuTTYgen** (alternativa)
- **Windows Terminal** + OpenSSH (Windows 10/11)

#### Linux/macOS
- OpenSSH client (pre-installato nella maggior parte delle distribuzioni)

### Verifica Installazione

Apri un terminale e verifica che SSH sia installato:

```bash
ssh -V
```

Output atteso (esempio):
```
OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2 15 Mar 2022
```

---

## Esercitazione Pratica

### Step 1: Generare la Coppia di Chiavi

Apri un terminale (Git Bash su Windows, Terminal su Linux/macOS).

#### Opzione A: Chiave Ed25519 (Raccomandato)

```bash
ssh-keygen -t ed25519 -C "tuo.nome@esempio.it"
```

#### Opzione B: Chiave RSA (Compatibilità)

```bash
ssh-keygen -t rsa -b 4096 -C "tuo.nome@esempio.it"
```

**Parametri:**
- `-t`: tipo di algoritmo (ed25519 o rsa)
- `-b`: lunghezza della chiave in bit (solo per RSA)
- `-C`: commento (solitamente la tua email)

#### Processo Interattivo

```
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/user/.ssh/id_ed25519):
```

**Premi INVIO** per accettare il percorso predefinito.

```
Enter passphrase (empty for no passphrase):
```

**Importante**: Inserisci una **passphrase sicura** per proteggere la chiave privata.
- Usa almeno 12 caratteri
- Combina lettere, numeri e simboli
- Questa password NON viene inviata al server, protegge solo la tua chiave locale

```
Enter same passphrase again:
```

Ripeti la passphrase.

```
Your identification has been saved in /home/user/.ssh/id_ed25519
Your public key has been saved in /home/user/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx tuo.nome@esempio.it
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|    . .          |
|   . o           |
|  ...            |
|                 |
|                 |
|                 |
|                 |
|                 |
+----[SHA256]-----+
```

✅ **Chiavi generate con successo!**

### Step 2: Verificare le Chiavi Create

```bash
ls -la ~/.ssh/
```

Dovresti vedere:
```
-rw-------  1 user user  411 Dec 17 10:00 id_ed25519      # Chiave PRIVATA
-rw-r--r--  1 user user  103 Dec 17 10:00 id_ed25519.pub  # Chiave PUBBLICA
```

**Nota i permessi:**
- Chiave privata: `-rw-------` (600) - leggibile/scrivibile solo dal proprietario
- Chiave pubblica: `-rw-r--r--` (644) - leggibile da tutti

### Step 3: Visualizzare la Chiave Pubblica

```bash
cat ~/.ssh/id_ed25519.pub
```

Output esempio:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx... tuo.nome@esempio.it
```

Questa è la chiave che dovrai copiare sul server.

### Step 4: Copiare la Chiave Pubblica sul Server

#### Metodo A: Utilizzare ssh-copy-id (Linux/macOS/Git Bash)

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2222 cognome.nome@w4s.filippobilardo.it
```

**Nota:** Sostituisci `cognome.nome` con le tue credenziali.

Ti verrà chiesta la password del server (questa sarà l'ultima volta!):
```
cognome.nome@w4s.filippobilardo.it's password:
```

Output di successo:
```
Number of key(s) added: 1

Now try logging into the machine, with:   "ssh -p '2222' 'cognome.nome@w4s.filippobilardo.it'"
and check to make sure that only the key(s) you wanted were added.
```

#### Metodo B: Copia Manuale

Se `ssh-copy-id` non funziona:

1. Visualizza e copia la chiave pubblica:
```bash
cat ~/.ssh/id_ed25519.pub
```

2. Connettiti al server con password:
```bash
ssh -p 2222 cognome.nome@w4s.filippobilardo.it
```

3. Sul server, crea la directory `.ssh` se non esiste:
```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
```

4. Aggiungi la chiave al file `authorized_keys`:
```bash
echo "ssh-ed25519 AAAAC3NzaC1... tuo.nome@esempio.it" >> ~/.ssh/authorized_keys
```

5. Imposta i permessi corretti:
```bash
chmod 600 ~/.ssh/authorized_keys
```

6. Esci dal server:
```bash
exit
```

### Step 5: Testare la Connessione

Prova a connetterti senza password:

```bash
ssh -p 2222 cognome.nome@w4s.filippobilardo.it
# oppure
ssh -i ~/.ssh/id_ed25519 -p 2222 cognome.nome@w4s.filippobilardo.it
```

Se hai impostato una passphrase, ti verrà chiesta (solo la prima volta per sessione):
```
Enter passphrase for key '/home/user/.ssh/id_ed25519':
```

✅ Se riesci ad accedere senza inserire la password del server, l'autenticazione con chiavi funziona correttamente!

### Step 6: Configurare SSH per Semplificare la Connessione (Opzionale)

Crea/modifica il file `~/.ssh/config`:

```bash
nano ~/.ssh/config
```

Aggiungi questa configurazione:

```
Host w4s
    HostName w4s.filippobilardo.it
    Port 2222
    User cognome.nome
    IdentityFile ~/.ssh/id_ed25519
```

Salva (CTRL+O, INVIO, CTRL+X in nano).

Imposta i permessi corretti:
```bash
chmod 600 ~/.ssh/config
```

Ora puoi connetterti semplicemente con:
```bash
ssh w4s
```

### Step 7: Configurare l'SSH Agent (Opzionale)

Per non dover inserire la passphrase ad ogni connessione:

#### Linux/macOS:

```bash
# Avvia l'agent
eval "$(ssh-agent -s)"

# Aggiungi la chiave
ssh-add ~/.ssh/id_ed25519
```

#### Windows (Git Bash):

```bash
# Avvia l'agent automaticamente
eval $(ssh-agent -s)

# Aggiungi la chiave
ssh-add ~/.ssh/id_ed25519
```

#### Windows (PowerShell):

```powershell
# Avvia il servizio
Start-Service ssh-agent

# Aggiungi la chiave
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```

---

## Verifica e Troubleshooting

### Verificare la Connessione in Modalità Verbose

Per diagnosticare problemi:

```bash
ssh -v -p 2222 cognome.nome@w4s.filippobilardo.it
```

Per maggiori dettagli:
```bash
ssh -vvv -p 2222 cognome.nome@w4s.filippobilardo.it
```

### Problemi Comuni

#### 1. "Permission denied (publickey)"

**Causa**: La chiave pubblica non è stata copiata correttamente o i permessi sono errati.

**Soluzione:**
```bash
# Verifica i permessi sul server
ls -la ~/.ssh/
# authorized_keys deve essere 600
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

#### 2. "WARNING: UNPROTECTED PRIVATE KEY FILE!"

**Causa**: La chiave privata ha permessi troppo aperti.

**Soluzione:**
```bash
chmod 600 ~/.ssh/id_ed25519
```

#### 3. "Connection refused"

**Causa**: Porta errata o server non raggiungibile.

**Soluzione:**
```bash
# Verifica la connessione
ping w4s.filippobilardo.it

# Verifica la porta
nmap -p 2222 w4s.filippobilardo.it
```

#### 4. La passphrase viene richiesta ad ogni connessione

**Causa**: SSH agent non è configurato.

**Soluzione:** Segui lo Step 7 per configurare l'SSH agent.

### Comandi Utili per Diagnostica

```bash
# Visualizza le chiavi caricate nell'agent
ssh-add -l

# Rimuovi tutte le chiavi dall'agent
ssh-add -D

# Testa la connessione con output dettagliato
ssh -vT -p 2222 cognome.nome@w4s.filippobilardo.it
```

---

## Esercizi

### Esercizio 1: Generazione Base (★☆☆)

1. Genera una nuova coppia di chiavi SSH con algoritmo Ed25519
2. Visualizza il contenuto della chiave pubblica
3. Verifica i permessi dei file generati

**Domande:**
- Qual è la differenza tra la chiave pubblica e quella privata?
- Perché la chiave privata ha permessi 600?

### Esercizio 2: Connessione al Server (★★☆)

1. Copia la tua chiave pubblica sul server usando `ssh-copy-id`
2. Connettiti al server senza utilizzare la password
3. Verifica che il tuo file `~/.ssh/authorized_keys` sul server contenga la chiave corretta

**Domande:**
- Cosa succede se qualcuno ottiene la tua chiave pubblica?
- Cosa succede se qualcuno ottiene la tua chiave privata?

### Esercizio 3: Configurazione Avanzata (★★★)

1. Crea un file di configurazione SSH (`~/.ssh/config`)
2. Aggiungi un alias "w4s" per il server
3. Configura l'SSH agent per memorizzare la passphrase
4. Testa la connessione usando solo `ssh w4s`

**Domande:**
- Quali vantaggi offre il file config?
- Come funziona l'SSH agent?

### Esercizio 4: Sicurezza (★★★)

1. Genera una seconda coppia di chiavi con algoritmo RSA 4096
2. Rinominala in `id_rsa_backup`
3. Configura il sistema per usare chiavi diverse per server diversi
4. Documenta le differenze tra Ed25519 e RSA

**Domande:**
- Quando è preferibile usare RSA invece di Ed25519?
- Come si può revocare l'accesso di una specifica chiave?

### Esercizio 5: Troubleshooting (★★☆)

Simula questi problemi e risolvili:

1. Modifica i permessi della chiave privata a 644 e prova a connetterti
2. Rimuovi la chiave pubblica dal server e prova a connetterti
3. Usa il comando `ssh -v` per diagnosticare un problema di connessione

**Domande:**
- Cosa significa ogni livello di verbosità (-v, -vv, -vvv)?
- Come si interpreta l'output di debug?

---

## Riferimenti e Approfondimenti

### Documentazione Ufficiale
- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [RFC 4253 - SSH Protocol](https://tools.ietf.org/html/rfc4253)

### Best Practices di Sicurezza
- Usa sempre una passphrase per proteggere le chiavi private
- Non condividere mai la chiave privata
- Genera chiavi separate per dispositivi diversi
- Ruota le chiavi periodicamente (ogni 1-2 anni)
- Usa Ed25519 o RSA ≥ 2048 bit
- Mantieni aggiornato il client SSH

### Comandi di Riferimento Rapido

```bash
# Generare chiavi
ssh-keygen -t ed25519 -C "commento"
ssh-keygen -t rsa -b 4096 -C "commento"

# Copiare chiave sul server
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host -p PORT

# Connessione
ssh user@host -p PORT

# SSH Agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ssh-add -l  # Lista chiavi

# Diagnostica
ssh -v user@host
ssh -vvv user@host  # Molto verbose

# Permessi corretti
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
chmod 600 ~/.ssh/config
chmod 600 ~/.ssh/authorized_keys  # sul server
```

---

## Conclusioni

Hai imparato a:
✅ Comprendere la crittografia asimmetrica  
✅ Generare coppie di chiavi SSH  
✅ Configurare l'autenticazione senza password  
✅ Risolvere problemi comuni  
✅ Implementare best practices di sicurezza  

L'autenticazione con chiavi SSH è uno strumento fondamentale per ogni sistemista e sviluppatore. Pratica regolarmente e mantieni sempre le tue chiavi private al sicuro!

---

**Autore**: Prof. Filippo Bilardo  
**Corso**: Sistemi e Reti 3  
**Data**: Dicembre 2025