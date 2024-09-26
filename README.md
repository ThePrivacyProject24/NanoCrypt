
![nanocrypt](https://github.com/user-attachments/assets/15129cbc-2a2d-4b6f-8acb-787b995fc977)

# NanoCrypt

NanoCrypt är en säker krypteringsapplikation för filer och meddelanden.

## Features

- Asymmetrisk kryptering med RSA (4096 bitar)
- Symmetrisk kryptering med AES-256 GCM
- Hantera flera profiler med publika nycklar
- Automatisk låsning efter inaktivitet
- GUI byggd med PyQt5

## Installation

### Från Källkod

1. Klona repository:
    ```bash
    git clone https://github.com/ThePrivacyProject24/NanoCrypt.git
    cd NanoCrypt
    ```

2. Skapa och aktivera en virtuell miljö:
    ```bash
    python -m venv venv
    venv\Scripts\activate
    ```

3. Installera beroenden:
    ```bash
    pip install -r requirements.txt
    ```

4. Kör applikationen:
    ```bash
    python main.py
    ```

### Windows Executable

För användare som vill använda NanoCrypt utan att installera Python och beroenden, ladda ner den fristående `.exe`-filen från [Releases](https://github.com/ThePrivacyProject24/NanoCrypt/releases).

1. Gå till [Releases](https://github.com/ThePrivacyProject24/NanoCrypt/releases).
2. Ladda ner `CryptApp.exe` från den senaste releasen.
3. Kör `CryptApp.exe` för att starta applikationen.

## Usage

1. **Generera Nyckelpar:**
   Om det är första gången du kör applikationen, kommer guiden att hjälpa dig att generera ditt nyckelpar och välja en standardkatalog.

2. **Kryptera/Fördela Filer:**
   - **Fil-läge:** Dra och släpp filer för att kryptera dem med vald profil.
   - **Text-läge:** Skriv meddelanden för att kryptera och dekryptera text.
   - **Chat-läge:** Skicka krypterade meddelanden till valda profiler.

## Download

[![Download Executable](https://img.shields.io/badge/Download-Executable-brightgreen)](https://github.com/ThePrivacyProject24/NanoCrypt/releases/latest)

## License

MIT License


