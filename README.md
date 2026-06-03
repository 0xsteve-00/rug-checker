# 🔍 Rug Checker

Scan EVM token contracts for rug pull risks, honeypots, and suspicious functions.

## 🎯 Apa Ini?

**Rug Checker** adalah tool untuk scan smart contract token dan deteksi potensi rug pull. Sangat berguna untuk:

- **Pre-Purchase Check** — cek token sebelum beli, hindari scam
- **New Token Audit** — audit token baru yang baru launch
- **Trading Bot Safety** — integrasi ke bot trading sebagai safety check
- **Portfolio Scan** — scan semua token di wallet lo untuk risiko
- **Research** — analisis contract untuk bug bounty / security research

**Masalah yang diselesaikan:**
90% token baru adalah scam/rug. Tool ini scan contract dalam 30 detik dan kasih risk score 0-100 supaya lo gak kehilangan uang.

## Features

- 🔍 **Honeypot Detection** — check if token can be bought/sold
- 🚨 **Rug Pull Risk Score** — 0-100 risk rating
- 🔐 **Ownership Analysis** — renounced? proxy? admin keys?
- 💣 **Hidden Mint Detection** — can owner mint unlimited tokens?
- 🔒 **Liquidity Check** — is LP locked? burned?
- 📊 **Holder Analysis** — top holders concentration
- ⚠️ **Dangerous Functions** — blacklist, pause, fee change, max TX override
- 🌐 **Multi-Chain** — ETH, BSC, Base, Polygon, Arbitrum
- 🐍 **CLI + Python API** — use standalone or import in your code

## Installation

```bash
git clone https://github.com/0xsteve-00/rug-checker.git
cd rug-checker
pip install -r requirements.txt
```

## Quick Start

```bash
# Check a token
python checker.py 0xTOKEN_ADDRESS --chain eth

# Quick scan (honeypot + risk score only)
python checker.py 0xTOKEN_ADDRESS --chain bsc --quick

# Full audit
python checker.py 0xTOKEN_ADDRESS --chain eth --full --output report.json

# Batch check from file
python checker.py --batch tokens.txt --chain eth --output results.json
```

## Output Example

```
🔍 Rug Checker — Scanning 0x1234...abcd (Ethereum)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Token Info
  Name:     SafeMoonV2
  Symbol:   SFM
  Decimals: 9
  Supply:   1,000,000,000,000

🚨 Risk Score: 72/100 (HIGH RISK)

⚠️ Red Flags:
  ❌ Owner can change fees (up to 100%)
  ❌ Blacklist function detected
  ❌ Max TX limit can be set to 0
  ❌ Owner is NOT renounced
  ❌ Top 10 holders own 85% supply
  ⚠️ Low liquidity ($12,000)

✅ Passed:
  ✓ No hidden mint function
  ✓ No pause function
  ✓ Trading is enabled
  ✓ Contract verified

🔗 Full report: report.json
```

## Risk Score Breakdown

| Score  | Rating    | Meaning |
|--------|-----------|---------|
| 0-20   | 🟢 SAFE  | Low risk, standard token |
| 21-40  | 🟡 CAUTION | Some concerns, review flags |
| 41-60  | 🟠 RISKY | Multiple red flags |
| 61-80  | 🔴 HIGH RISK | Likely rug/scam |
| 81-100 | ☠️ DANGER | Do not interact |

## Use Cases

- 🛡️ Check tokens before buying
- 🔍 Audit new token launches
- 📊 Build trading bots with safety checks
- 🚨 Alert on suspicious contracts
- 📝 Generate audit reports

## Tech Stack

- Python 3.10+
- web3.py (contract interaction)
- requests (explorer APIs)

## Disclaimer

This tool provides automated analysis only. Always DYOR. Not financial advice.

## License

MIT
