# XRPL Vanity Wallet Generator – Implementierungsanleitung

## Voraussetzungen

- Windows 11 Pro
- Visual Studio 2022 oder neuer (mit **"Desktop development with C++"** Workload)
- Internetverbindung (für die Rust-Installation und den ersten Build)

---

## Schritt 1: Rust installieren

1. Öffne im Browser: **https://rustup.rs**
2. Klicke auf **"DOWNLOAD RUSTUP-INIT.EXE (64-BIT)"**
3. Führe die heruntergeladene `rustup-init.exe` aus
4. Es öffnet sich ein Terminal-Fenster mit Optionen – tippe **1** und drücke **Enter** (Standard-Installation)
5. Warte bis die Meldung erscheint: *"Rust is installed now. Great!"*
6. Schließe das Fenster

### Installation prüfen

Öffne eine **neue** PowerShell (wichtig: nicht die alte weiterverwenden!) und tippe:

```powershell
rustc --version
cargo --version
```

Wenn beide Befehle eine Versionsnummer ausgeben, ist Rust korrekt installiert.

> Falls `rustc` nicht gefunden wird: Starte den PC einmal neu und versuche es erneut.

---

## Schritt 2: Visual Studio prüfen

Öffne den **Visual Studio Installer** (über die Windows-Suche) und stelle sicher, dass die Workload **"Desktop development with C++"** installiert ist. Falls nicht:

1. Klicke auf **"Modify"** neben deiner Visual Studio Installation
2. Setze den Haken bei **"Desktop development with C++"**
3. Klicke auf **"Modify"** unten rechts
4. Warte bis die Installation abgeschlossen ist

---

## Schritt 3: Projekt entpacken

1. Lade die Datei **xrpl-vanity.zip** herunter
2. Entpacke sie nach `C:\Dev\` (oder einem Ordner deiner Wahl)
3. Du solltest jetzt diese Struktur haben:

```
C:\Dev\xrpl-vanity\
├── src\
│   └── main.rs
├── Cargo.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── .gitignore
```

---

## Schritt 4: Projekt kompilieren

Öffne PowerShell und führe aus:

```powershell
cd C:\Dev\xrpl-vanity
cargo build --release
```

**Beim ersten Mal** dauert das 1–3 Minuten. Cargo lädt alle Dependencies herunter und kompiliert alles mit maximaler Optimierung. Du siehst dabei Ausgaben wie:

```
   Compiling ed25519-dalek v2.1.1
   Compiling sha2 v0.10.8
   Compiling rayon v1.10.0
   ...
   Compiling xrpl-vanity v1.0.0
    Finished release [optimized] target(s) in 1m 42s
```

Die fertige `.exe` liegt danach hier:

```
C:\Dev\xrpl-vanity\target\release\xrpl-vanity.exe
```

> **Wichtig:** Immer `--release` verwenden! Ohne dieses Flag ist das Programm ca. 20x langsamer.

---

## Schritt 5: Tests ausführen (optional)

Um sicherzustellen, dass alles korrekt funktioniert:

```powershell
cargo test
```

Erwartete Ausgabe:

```
running 10 tests
test tests::test_address_starts_with_r ... ok
test tests::test_address_length ... ok
test tests::test_address_valid_characters ... ok
test tests::test_deterministic_address ... ok
test tests::test_different_keys_different_addresses ... ok
test tests::test_seed_format ... ok
test tests::test_validate_chars_valid ... ok
test tests::test_validate_chars_invalid ... ok
test tests::test_estimate_attempts ... ok
test tests::test_format_large_number ... ok

test result: ok. 10 passed; 0 failed
```

---

## Schritt 6: Vanity-Adresse generieren

### Adresse mit gewünschtem Präfix finden

```powershell
.\target\release\xrpl-vanity.exe --prefix Bob
```

Findet eine Adresse wie `rBobK8q2F7TVr4pn9jLcE6MxB8a7VfJqHN`.

### Adresse mit gewünschtem Suffix finden

```powershell
.\target\release\xrpl-vanity.exe --suffix XRP
```

Findet eine Adresse wie `r9hG3kVn2bFT4q8mJcE6...XRP`.

### Groß-/Kleinschreibung ignorieren

```powershell
.\target\release\xrpl-vanity.exe --prefix bob -i
```

Findet `rBob...`, `rbob...`, `rBOB...` etc.

### Anzahl Threads festlegen

```powershell
.\target\release\xrpl-vanity.exe --prefix Cool --threads 8
```

### Fortschrittsanzeige anpassen

```powershell
.\target\release\xrpl-vanity.exe --prefix Hello --progress-every-million 5
```

### Hilfe anzeigen

```powershell
.\target\release\xrpl-vanity.exe --help
```

---

## Schritt 7: Ergebnis sichern

Wenn eine Adresse gefunden wird, zeigt das Programm drei wichtige Werte an:

```
  Address:      rBobK8q2F7TVr4pn9jLcE6MxB8a7VfJqHN
  Secret (hex): a3f1...b72e
  Seed:         sEdV...
```

- **Address** – deine neue XRPL-Wallet-Adresse
- **Secret (hex)** – der Private Key in Hex-Format
- **Seed** – der Private Key als importierbarer Seed (sEd...-Format)

### So sicherst du den Key:

1. Notiere den **Seed** (sEd...) auf Papier oder in einem Passwort-Manager
2. Schließe das Terminal danach
3. Der Seed reicht aus, um das Wallet in jeder XRPL-kompatiblen Software zu importieren (z.B. XUMM/Xaman, Ledger, etc.)

> **Niemals** den Secret Key / Seed online speichern, per E-Mail verschicken oder in einen Chat posten. Wer den Seed hat, kontrolliert das Wallet.

---

## Schritt 8: Wallet aktivieren

Eine neu generierte Adresse ist zunächst nicht aktiv auf dem XRPL. Um sie zu aktivieren:

1. Sende mindestens **10 XRP** (aktuelles Base Reserve) von einem bestehenden Wallet an deine neue Vanity-Adresse
2. Nach der Transaktion ist das Wallet aktiv und nutzbar

---

## Schritt 9: Auf GitHub veröffentlichen (optional)

Falls du das Projekt auf GitHub teilen möchtest:

### 9.1 – Repository auf GitHub erstellen

1. Öffne **https://github.com/new**
2. Repository Name: `xrpl-vanity`
3. Description: `High-performance XRPL vanity wallet address generator`
4. Setze auf **Public**
5. **Keine** README, .gitignore oder License hinzufügen (haben wir schon)
6. Klicke auf **"Create repository"**

### 9.2 – Code pushen

```powershell
cd C:\Dev\xrpl-vanity
git init
git add .
git commit -m "Initial release: XRPL vanity address generator"
git branch -M main
git remote add origin https://github.com/XRPLocutus/xrpl-vanity.git
git push -u origin main
```

> Falls Git nicht installiert ist: **https://git-scm.com/download/win** herunterladen und installieren. Danach PowerShell neu öffnen.

---

## Fehlerbehebung

| Problem | Lösung |
|---------|--------|
| `rustc` nicht gefunden | Neues Terminal öffnen oder PC neustarten |
| `LINK : fatal error LNK1181` | VS Build Tools mit "Desktop development with C++" installieren |
| `cargo build` bricht ab | Internetverbindung prüfen (Dependencies werden beim ersten Build heruntergeladen) |
| Programm ist sehr langsam | Sicherstellen dass `cargo build --release` verwendet wurde |
| `Invalid character` Fehler | XRPL nutzt ein eigenes Alphabet – nicht alle Buchstaben sind erlaubt. `--help` zeigt Details |
| Git nicht gefunden | Git for Windows installieren: https://git-scm.com/download/win |

---

## Gültige Zeichen für Vanity-Muster

XRPL-Adressen verwenden ein eigenes Base58-Alphabet. Nur diese Zeichen sind erlaubt:

```
r p s h n a f 3 9 w B U D N E G H J K L M 4 P Q R S T 7 V W X Y Z
2 b c d e C g 6 5 j k m 8 o F q i 1 t u v A x y z
```

**Nicht enthalten:** `0` (Null), `O` (großes O), `I` (großes I), `l` (kleines L)

---

## Geschätzte Suchzeiten

| Präfix-Länge | Ø Versuche | Bei 1M addr/s |
|---|---|---|
| 1 Zeichen | ~58 | instant |
| 2 Zeichen | ~3.364 | instant |
| 3 Zeichen | ~195K | < 1 Sek |
| 4 Zeichen | ~11M | ~11 Sek |
| 5 Zeichen | ~656M | ~11 Min |
| 6 Zeichen | ~38B | ~10 Std |
| 7+ Zeichen | ~2T+ | Tage |

Jedes zusätzliche Zeichen multipliziert die Suchzeit mit ~58.
