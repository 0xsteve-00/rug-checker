# 🔍 Rug Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

> Scan token contracts to detect honeypots, rug pulls, hidden mints, and other scam patterns before you invest.

## 🎯 What Is This?

Rug Checker analyzes smart contracts on-chain to identify potential risks before you buy a token. Instead of relying on guesswork, this tool reads the actual contract code:

- **Honeypot Detection** — Can you actually sell after buying?
- **Rug Pull Risk** — Can the owner drain liquidity or mint unlimited tokens?
- **Hidden Functions** — Pause, blacklist, fee manipulation, proxy upgrades
- **Holder Analysis** — Is supply concentrated in a few wallets?

## 🤔 Who Needs This?

- **Traders** who want to verify tokens before buying
- **Airdrop farmers** checking if claim contracts are safe
- **Researchers** analyzing token security patterns
- **Anyone** who doesn't want to get scammed

## ⚡ Features

- 🔍 Honeypot simulation (buy + sell test)
- 🚨 Risk score 0-100 with detailed breakdown
- 💣 Hidden mint/pause/blacklist detection
- 🔐 Ownership renouncement verification
- 🔄 Proxy contract detection
- 📊 Holder concentration analysis
- 🌐 Multi-chain: ETH, BSC, Base, Polygon, Arbitrum
- 📦 Batch mode — scan hundreds of tokens at once
- 💾 JSON export for further analysis

## 📦 Installation

```bash
git clone https://github.com/0xsteve-00/rug-checker.git
cd rug-checker
pip install -r requirements.txt
```

## 🚀 Quick Start

```bash
# Scan a single token
python checker.py --token 0x1234...abcd --chain bsc

# Batch scan from file
python checker.py --file example_tokens.txt --chain eth --output results.json

# Quick honeypot check
python checker.py --token 0x1234...abcd --quick
```

## 📊 Risk Score Breakdown

| Score | Level | Meaning |
|-------|-------|---------|
| 0-20 | 🟢 Low Risk | Likely safe, standard contract |
| 21-50 | 🟡 Medium Risk | Some concerns, proceed with caution |
| 51-80 | 🟠 High Risk | Significant red flags |
| 81-100 | 🔴 Critical | Likely scam, do not buy |

## 📁 Project Structure

```
rug-checker/
├── checker.py           # Main scanning engine (400+ lines)
├── example_tokens.txt   # Sample token list for batch scanning
├── requirements.txt     # Python dependencies
├── .gitignore           # Git ignore rules
├── LICENSE              # MIT License
└── README.md            # This file
```

## ⚠️ Disclaimer

This tool provides automated analysis only. No tool can guarantee 100% accuracy. Always do your own research (DYOR) before investing. The authors are not responsible for any financial losses.

## 📜 License

MIT License — free to use, modify, and distribute.
