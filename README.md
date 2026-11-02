# BTCVault

BTCVault is an air-gapped Bitcoin wallet toolkit for creating, exporting, reviewing, signing, and broadcasting Bitcoin transactions using a PSBT-based workflow.

It is designed around a split workflow:

- Offline machine: generate wallets, create encrypted keystores, and sign transactions
- Online machine: build unsigned PSBTs, scan watch-only wallets, and broadcast final transactions

This project is written in Python and uses a Tkinter GUI for local wallet operations.

## Features

- Generate a new wallet or restore from an existing BIP-39 seed phrase
- Encrypt keystores with scrypt + AES-256-GCM
- Export public watch-only wallet data for online use
- Scan wallet balances and UTXOs from Esplora-compatible APIs
- Build unsigned PSBTs from selected coins
- Independently review PSBT inputs and outputs before signing
- Sign PSBTs offline with wallet keystore data
- Broadcast signed transactions to a Bitcoin network explorer API
- Support for multiple address types and networks:
  - Legacy: P2PKH (BIP-44)
  - Nested SegWit: P2SH-P2WPKH (BIP-49)
  - Native SegWit: P2WPKH (BIP-84)
  - Taproot: P2TR (BIP-86)
- Networks: Mainnet, Testnet4, Testnet3, Signet, Regtest
- Keystone-style export support for compatible wallets

## Project layout

- `btcvault.py` — main application entry point and GUI coordinator
- `btcpanel.py` — tabbed UI for wallet creation, export, PSBT creation, signing, and broadcasting
- `btcv.py` — core Bitcoin logic, wallet derivation, PSBT handling, signing, and network tools
- `ur.py` — UR QR codec support for BC-UR compatible QR transfers

## Security model

BTCVault is designed as a cold-style wallet workflow and intentionally separates secrets from networked systems.

Important rules:

- Mainnet keystore creation and signing should happen on an offline / air-gapped machine
- Do not expose wallet seed phrases or encrypted keystore passwords to an online machine
- Only public watch-only data should be moved to the online side
- Always verify the recipient address and the transaction review before signing
- Test on Signet or Testnet with small amounts before using real funds

## Requirements

Install Python dependencies:

```bash
pip install embit pycryptodome
```

Optional packages for QR / camera support:

```bash
pip install qrcode pillow
pip install cbor2
pip install pyzbar opencv-python
```

## Run

Normal online coordinator mode:

```bash
python btcvault.py
```

Offline air-gapped signer mode:

```bash
python btcvault.py --offline
```

Self-test mode (offline validation, no network required):

```bash
python btcvault.py --selftest
```

## Typical workflow

1. On the offline machine:
   - Create a wallet or restore a seed
   - Save the encrypted keystore file
   - Export the watch-only public wallet data

2. On the online machine:
   - Import the watch-only key
   - Scan the wallet for balances and UTXOs
   - Build an unsigned PSBT
   - Transfer the PSBT to the offline signer

3. Back on the offline machine:
   - Load the unsigned PSBT and keystore
   - Review the transaction carefully
   - Sign the PSBT
   - Transfer the signed PSBT back to the online machine

4. On the online machine:
   - Review the signed transaction
   - Broadcast it to the network explorer or node API

## Notes

- The project is explicitly labeled educational / unaudited
- It is intended for careful testing and review before production use
- On Regtest, you may need to configure a local Esplora/electrs endpoint in the GUI

## Disclaimer

This software is provided for educational and experimental use. It is not a production-ready wallet implementation and should be used with caution. Always verify wallet behavior, transaction details, and security assumptions before trusting it with real funds.

## License

This repository does not currently declare a license in the metadata. If you plan to redistribute or publish the project, check whether a license should be added before doing so.
