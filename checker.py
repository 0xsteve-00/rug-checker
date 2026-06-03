#!/usr/bin/env python3
"""
Rug Checker — Scan EVM token contracts for rug pull risks.
Usage:
  python checker.py 0xTOKEN --chain eth
  python checker.py 0xTOKEN --chain bsc --full --output report.json
  python checker.py --batch tokens.txt --chain eth
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

import requests
from web3 import Web3

# ═══════════════════════════════════════════════════════════════
# CHAIN CONFIGS
# ═══════════════════════════════════════════════════════════════

CHAINS = {
    "eth": {
        "name": "Ethereum",
        "rpc": "https://eth.llamarpc.com",
        "explorer_api": "https://api.etherscan.io/api",
        "explorer": "https://etherscan.io",
        "symbol": "ETH",
        "router": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    },
    "bsc": {
        "name": "BNB Chain",
        "rpc": "https://bsc-dataseed.binance.org",
        "explorer_api": "https://api.bscscan.com/api",
        "explorer": "https://bscscan.com",
        "symbol": "BNB",
        "router": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    },
    "base": {
        "name": "Base",
        "rpc": "https://mainnet.base.org",
        "explorer_api": "https://api.basescan.org/api",
        "explorer": "https://basescan.org",
        "symbol": "ETH",
        "router": "0x327Df1E6de05895d2ab08513aaDD9313Fe505d86",
    },
    "polygon": {
        "name": "Polygon",
        "rpc": "https://polygon-rpc.com",
        "explorer_api": "https://api.polygonscan.com/api",
        "explorer": "https://polygonscan.com",
        "symbol": "MATIC",
        "router": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",
    },
    "arbitrum": {
        "name": "Arbitrum",
        "rpc": "https://arb1.arbitrum.io/rpc",
        "explorer_api": "https://api.arbiscan.io/api",
        "explorer": "https://arbiscan.io",
        "symbol": "ETH",
        "router": "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",
    },
}

# ═══════════════════════════════════════════════════════════════
# MINIMAL ABIs
# ═══════════════════════════════════════════════════════════════

ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "owner", "outputs": [{"name": "", "type": "address"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "getOwner", "outputs": [{"name": "", "type": "address"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "totalFees", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "account", "type": "address"}], "name": "isExcludedFromFee", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "_maxTxAmount", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "_maxWalletSize", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "tradingActive", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "swapEnabled", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
    {"inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "name": "transfer", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
]

# Dangerous function selectors
DANGEROUS_SELECTORS = {
    "0x49bd5a5e": "blacklist(address)",
    "0x51c67e4f": "setFee(uint256,uint256)",
    "0x8b4cee08": "setFees(uint256,uint256,uint256,uint256,uint256,uint256,uint256)",
    "0xd3aa3a3e": "excludeFromFee(address)",
    "0x4a75e486": "includeInFee(address)",
    "0x5c975abb": "paused()",
    "0x3f4ba83a": "unpause()",
    "0x4c1b0747": "setMaxTxPercent(uint256)",
    "0x6b67c4df": "setMaxWalletPercent(uint256)",
    "0x70a08231": "balanceOf(address)",
    "0x18160ddd": "totalSupply()",
    "0x8da5cb5b": "owner()",
    "0x715018a6": "renounceOwnership()",
    "0xf2fde38b": "transferOwnership(address)",
    "0xa9059cbb": "transfer(address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0xa457c2d7": "decreaseAllowance(address,uint256)",
    "0x39509351": "increaseAllowance(address,uint256)",
    "0x40c10f19": "mint(address,uint256)",
    "0xa0712d68": "mint(uint256)",
    "0x42966c68": "burn(uint256)",
    "0x79cc6790": "burnFrom(address,uint256)",
    "0x5b34b966": "updateFee(uint256)",
    "0x1694505e": "openTrading()",
    "0xc9567bf9": "openTrading()",
    "0x43d15880": "setRouter(address)",
    "0x2932d5c1": "setPair(address)",
}

# ═══════════════════════════════════════════════════════════════
# ANALYSIS RESULT
# ═══════════════════════════════════════════════════════════════

@dataclass
class TokenReport:
    address: str = ""
    chain: str = ""
    name: str = ""
    symbol: str = ""
    decimals: int = 18
    total_supply: float = 0
    owner: str = ""
    owner_renounced: bool = False
    risk_score: int = 0
    risk_level: str = ""
    red_flags: list = field(default_factory=list)
    passed: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    dangerous_functions: list = field(default_factory=list)
    top_holders: list = field(default_factory=list)
    holder_concentration: float = 0
    contract_verified: bool = False
    is_proxy: bool = False
    has_mint: bool = False
    has_pause: bool = False
    has_blacklist: bool = False
    has_fee_change: bool = False
    has_max_tx: bool = False
    trading_active: bool = False
    liquidity_info: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


# ═══════════════════════════════════════════════════════════════
# CHECKER ENGINE
# ═══════════════════════════════════════════════════════════════

class RugChecker:
    def __init__(self, chain: str, api_key: str = ""):
        self.chain = chain
        self.cfg = CHAINS[chain]
        self.w3 = Web3(Web3.HTTPProvider(self.cfg["rpc"]))
        self.api_key = api_key
        self.report = TokenReport(chain=chain)

    def _api_call(self, **params) -> dict:
        """Call explorer API."""
        if self.api_key:
            params["apikey"] = self.api_key
        try:
            resp = requests.get(self.cfg["explorer_api"], params=params, timeout=15)
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def _get_bytecode(self, address: str) -> str:
        """Get contract bytecode."""
        try:
            return self.w3.eth.get_code(Web3.to_checksum_address(address)).hex()
        except Exception:
            return ""

    def _get_source_code(self, address: str) -> dict:
        """Get verified source code from explorer."""
        data = self._api_call(
            module="contract",
            action="getsourcecode",
            address=address,
        )
        results = data.get("result", [])
        if results and isinstance(results, list):
            return results[0]
        return {}

    def _get_abi(self, address: str) -> list:
        """Get verified ABI from explorer."""
        data = self._api_call(
            module="contract",
            action="getabi",
            address=address,
        )
        if data.get("status") == "1":
            try:
                return json.loads(data["result"])
            except Exception:
                pass
        return []

    def _get_holders(self, address: str) -> list:
        """Get top token holders."""
        data = self._api_call(
            module="token",
            action="tokenholderlist",
            contractaddress=address,
            page=1,
            offset=20,
        )
        results = data.get("result", [])
        if isinstance(results, list):
            return results
        return []

    def _check_proxy(self, address: str) -> bool:
        """Check if contract is a proxy."""
        bytecode = self._get_bytecode(address)
        # EIP-1967 proxy storage slot
        proxy_indicators = [
            "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
        ]
        for indicator in proxy_indicators:
            if indicator in bytecode:
                return True
        return False

    def _scan_dangerous_functions(self, abi: list):
        """Scan ABI for dangerous functions."""
        func_names = set()
        for item in abi:
            if item.get("type") == "function":
                func_names.add(item.get("name", "").lower())

        dangerous = []

        # Check for mint
        if "mint" in func_names:
            self.report.has_mint = True
            dangerous.append("mint() — owner can create unlimited tokens")

        # Check for pause
        if "pause" in func_names or "paused" in func_names:
            self.report.has_pause = True
            dangerous.append("pause() — owner can freeze trading")

        # Check for blacklist
        if any(x in func_names for x in ["blacklist", "isblacklisted", "isblacklisted", "setblacklist"]):
            self.report.has_blacklist = True
            dangerous.append("blacklist() — owner can block addresses from trading")

        # Check for fee changes
        if any(x in func_names for x in ["setfee", "setfees", "updatefee", "settax", "setbuyfee", "setsellfee"]):
            self.report.has_fee_change = True
            dangerous.append("setFee() — owner can change buy/sell fees (up to 100%)")

        # Check for max TX override
        if any(x in func_names for x in ["setmaxtxpercent", "setmaxtxamount", "setmaxtx", "updatemaxtxamount"]):
            self.report.has_max_tx = True
            dangerous.append("setMaxTx() — owner can set max TX to 0 (block sells)")

        # Check for max wallet
        if any(x in func_names for x in ["setmaxwalletsize", "setmaxwalletpercent", "updatemaxwalletamount"]):
            dangerous.append("setMaxWallet() — owner can restrict wallet size")

        # Check for trading control
        if any(x in func_names for x in ["opentrading", "enabletrading", "settrading"]):
            dangerous.append("openTrading() — owner controls when trading starts")

        self.report.dangerous_functions = dangerous

    def _check_bytecode_functions(self, address: str):
        """Check bytecode for dangerous function selectors."""
        bytecode = self._get_bytecode(address)
        if not bytecode:
            return

        found = []
        for selector, name in DANGEROUS_SELECTORS.items():
            if selector[2:] in bytecode:  # strip 0x prefix
                found.append(name)

        if found:
            # Only add if not already found via ABI
            for f in found:
                if f not in self.report.dangerous_functions:
                    self.report.dangerous_functions.append(f"bytecode: {f}")

    def check(self, address: str, full: bool = False) -> TokenReport:
        """Run full token analysis."""
        address = Web3.to_checksum_address(address)
        self.report.address = address

        print(f"\n🔍 Rug Checker — Scanning {address[:10]}...{address[-6:]} ({self.cfg['name']})")
        print("━" * 55)

        # ── Token Info ──
        print("\n📋 Token Info")
        try:
            contract = self.w3.eth.contract(address=address, abi=ERC20_ABI)
            self.report.name = contract.functions.name().call()
            self.report.symbol = contract.functions.symbol().call()
            self.report.decimals = contract.functions.decimals().call()
            supply = contract.functions.totalSupply().call()
            self.report.total_supply = supply / (10 ** self.report.decimals)
            print(f"  Name:     {self.report.name}")
            print(f"  Symbol:   {self.report.symbol}")
            print(f"  Decimals: {self.report.decimals}")
            print(f"  Supply:   {self.report.total_supply:,.0f}")
        except Exception as e:
            print(f"  ⚠️ Could not read token info: {e}")

        # ── Owner ──
        try:
            owner = contract.functions.owner().call()
            self.report.owner = owner
            zero_addr = "0x0000000000000000000000000000000000000000"
            self.report.owner_renounced = owner.lower() == zero_addr
            if self.report.owner_renounced:
                self.report.passed.append("Ownership renounced")
                print(f"  Owner:    ✅ Renounced")
            else:
                self.report.warnings.append(f"Owner: {owner}")
                print(f"  Owner:    ⚠️ {owner[:10]}...{owner[-6:]}")
        except Exception:
            self.report.passed.append("No owner function (likely safe)")
            print(f"  Owner:    ✅ No owner function")

        # ── Contract Verification ──
        source = self._get_source_code(address)
        self.report.contract_verified = bool(source.get("SourceCode"))
        if self.report.contract_verified:
            self.report.passed.append("Contract verified")
            print(f"  Verified: ✅ Yes")
        else:
            self.report.warnings.append("Contract NOT verified")
            print(f"  Verified: ⚠️ No")

        # ── Proxy Check ──
        self.report.is_proxy = self._check_proxy(address)
        if self.report.is_proxy:
            self.report.warnings.append("Contract is a proxy — logic can change")
            print(f"  Proxy:    ⚠️ Yes (logic can be changed)")
        else:
            self.report.passed.append("Not a proxy contract")
            print(f"  Proxy:    ✅ No")

        # ── ABI Analysis ──
        abi = self._get_abi(address)
        if abi:
            self._scan_dangerous_functions(abi)
        self._check_bytecode_functions(address)

        # ── Trading Status ──
        try:
            trading = contract.functions.tradingActive().call()
            self.report.trading_active = trading
            if trading:
                self.report.passed.append("Trading is active")
            else:
                self.report.warnings.append("Trading NOT active yet")
        except Exception:
            pass

        # ── Holder Analysis ──
        holders = self._get_holders(address)
        if holders:
            top_10_balance = 0
            total = self.report.total_supply or 1
            for h in holders[:10]:
                qty = int(h.get("TokenHolderQuantity", 0))
                pct = (qty / (total * (10 ** self.report.decimals))) * 100 if total else 0
                top_10_balance += pct
                self.report.top_holders.append({
                    "address": h.get("TokenHolderAddress", "")[:16],
                    "quantity": qty,
                    "percent": round(pct, 2),
                })

            self.report.holder_concentration = round(top_10_balance, 2)
            if top_10_balance > 80:
                self.report.red_flags.append(f"Top 10 holders own {top_10_balance:.1f}% — high concentration")
            elif top_10_balance > 50:
                self.report.warnings.append(f"Top 10 holders own {top_10_balance:.1f}%")
            else:
                self.report.passed.append(f"Top 10 holders own {top_10_balance:.1f}% — good distribution")

        # ── Dangerous Functions ──
        if self.report.has_mint:
            self.report.red_flags.append("Owner can mint unlimited tokens")
        if self.report.has_pause:
            self.report.red_flags.append("Owner can pause/freeze trading")
        if self.report.has_blacklist:
            self.report.red_flags.append("Blacklist function detected")
        if self.report.has_fee_change:
            self.report.red_flags.append("Owner can change fees (up to 100%)")
        if self.report.has_max_tx:
            self.report.red_flags.append("Max TX limit can be set to 0 (blocks sells)")

        # ── Risk Score ──
        score = 0
        score += len(self.report.red_flags) * 15
        score += len(self.report.warnings) * 5
        score += (10 if not self.report.contract_verified else 0)
        score += (10 if self.report.is_proxy else 0)
        score += (15 if not self.report.owner_renounced and self.report.owner else 0)
        score += min(20, self.report.holder_concentration / 5)
        self.report.risk_score = min(100, int(score))

        if self.report.risk_score <= 20:
            self.report.risk_level = "🟢 SAFE"
        elif self.report.risk_score <= 40:
            self.report.risk_level = "🟡 CAUTION"
        elif self.report.risk_score <= 60:
            self.report.risk_level = "🟠 RISKY"
        elif self.report.risk_score <= 80:
            self.report.risk_level = "🔴 HIGH RISK"
        else:
            self.report.risk_level = "☠️ DANGER"

        # ── Print Results ──
        print(f"\n🚨 Risk Score: {self.report.risk_score}/100 ({self.report.risk_level})")

        if self.report.red_flags:
            print(f"\n⚠️ Red Flags ({len(self.report.red_flags)}):")
            for flag in self.report.red_flags:
                print(f"  ❌ {flag}")

        if self.report.dangerous_functions:
            print(f"\n💣 Dangerous Functions ({len(self.report.dangerous_functions)}):")
            for func in self.report.dangerous_functions:
                print(f"  ⚠️ {func}")

        if self.report.warnings:
            print(f"\n⚠️ Warnings ({len(self.report.warnings)}):")
            for w in self.report.warnings:
                print(f"  ⚠️ {w}")

        if self.report.passed:
            print(f"\n✅ Passed ({len(self.report.passed)}):")
            for p in self.report.passed:
                print(f"  ✓ {p}")

        return self.report


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="🔍 Rug Checker — Token safety scanner")
    parser.add_argument("address", nargs="?", help="Token contract address")
    parser.add_argument("--chain", default="eth", help="Chain: eth, bsc, base, polygon, arbitrum")
    parser.add_argument("--api-key", default="", help="Explorer API key (optional)")
    parser.add_argument("--full", action="store_true", help="Full analysis (includes bytecode scan)")
    parser.add_argument("--output", help="Save report to JSON file")
    parser.add_argument("--batch", help="File with token addresses (one per line)")
    args = parser.parse_args()

    if args.chain not in CHAINS:
        print(f"❌ Unknown chain: {args.chain}. Available: {', '.join(CHAINS.keys())}")
        sys.exit(1)

    checker = RugChecker(args.chain, args.api_key)

    if args.batch:
        # Batch mode
        path = Path(args.batch)
        if not path.exists():
            print(f"❌ File not found: {args.batch}")
            sys.exit(1)

        addresses = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]
        results = []

        for i, addr in enumerate(addresses):
            print(f"\n{'='*55} [{i+1}/{len(addresses)}]")
            try:
                report = checker.check(addr, full=args.full)
                results.append(report.to_dict())
                checker.report = TokenReport(chain=args.chain)  # Reset
            except Exception as e:
                print(f"❌ Error: {e}")
                results.append({"address": addr, "error": str(e)})

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n📄 Saved {len(results)} reports to {args.output}")

    elif args.address:
        # Single check
        report = checker.check(args.address, full=args.full)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            print(f"\n📄 Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
