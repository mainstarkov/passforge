#!/usr/bin/env python3
"""PassForge — secure password generator with strength analysis."""

import argparse
import math
import os
import string
import sys


# ── Terminal colors ──────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


BANNER = f"""
{C.CYAN}{C.BOLD}  ██████╗  █████╗ ███████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██████╔╝███████║███████╗███████╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ██║     ██║  ██║███████║███████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝{C.RESET}
{C.GRAY}  ────────────────────────────────────────────────────────────────────{C.RESET}
{C.DIM}  Secure Password Generator v1.0                      {C.GRAY}by mainstarkov{C.RESET}
{C.GRAY}  ────────────────────────────────────────────────────────────────────{C.RESET}
"""


# ── Password generation ─────────────────────────────────────────────

def generate_password(length: int, upper: bool, lower: bool, digits: bool,
                      symbols: bool, exclude: str) -> str:
    charset = ""
    if upper:
        charset += string.ascii_uppercase
    if lower:
        charset += string.ascii_lowercase
    if digits:
        charset += string.digits
    if symbols:
        charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    for ch in exclude:
        charset = charset.replace(ch, "")

    if not charset:
        print(f"{C.RED}  ✗ Error: empty charset. Enable at least one character type.{C.RESET}")
        sys.exit(1)

    return "".join(charset[b % len(charset)] for b in os.urandom(length))


# ── Strength analysis ───────────────────────────────────────────────

def analyze_strength(password: str) -> dict:
    length = len(password)
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 29

    entropy = length * math.log2(charset_size) if charset_size > 0 else 0
    combinations = charset_size ** length if charset_size > 0 else 0

    # Target entropy for strong password (80 bits)
    target_entropy = 80
    missing_symbols = 0
    suggested_password = ""
    
    if entropy < target_entropy and charset_size > 0:
        # Calculate how many more characters needed
        min_length_needed = math.ceil(target_entropy / math.log2(charset_size))
        missing_symbols = max(0, min_length_needed - length)
        
        # Generate a suggested password if current is weak
        if missing_symbols > 0 or not all([has_lower, has_upper, has_digit, has_symbol]):
            suggested_charset = ""
            if not has_lower:
                suggested_charset += string.ascii_lowercase
            if not has_upper:
                suggested_charset += string.ascii_uppercase
            if not has_digit:
                suggested_charset += string.digits
            if not has_symbol:
                suggested_charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
            
            # Build suggested password: original + additional chars
            base = password
            additional_needed = max(missing_symbols, 4)  # At least 4 more if adding types
            
            # Add missing character types first
            if suggested_charset:
                for i, ch in enumerate(suggested_charset[:4]):
                    base += ch
            
            # Then add random chars to reach target length
            remaining = max(0, min_length_needed - len(base))
            if remaining > 0:
                full_charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
                base += "".join(full_charset[b % len(full_charset)] for b in os.urandom(remaining))
            
            suggested_password = base

    if entropy >= 80:
        grade, color = "EXCELLENT", C.GREEN
    elif entropy >= 60:
        grade, color = "STRONG", C.GREEN
    elif entropy >= 40:
        grade, color = "MODERATE", C.YELLOW
    elif entropy >= 28:
        grade, color = "WEAK", C.RED
    else:
        grade, color = "VERY WEAK", C.RED

    bar_len = min(int(entropy / 4), 20)
    bar = f"{color}{'█' * bar_len}{C.GRAY}{'░' * (20 - bar_len)}{C.RESET}"

    return {
        "length": length,
        "entropy": round(entropy, 1),
        "charset_size": charset_size,
        "combinations": combinations,
        "grade": grade,
        "color": color,
        "bar": bar,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "missing_symbols": missing_symbols,
        "suggested_password": suggested_password,
    }


def format_combinations(n: int) -> str:
    if n > 10**30:
        exp = int(math.log10(n))
        return f"~10^{exp}"
    if n > 1_000_000_000:
        return f"{n:.2e}"
    return f"{n:,}"


def crack_time(combinations: int) -> str:
    guesses_per_sec = 10_000_000_000
    seconds = combinations / guesses_per_sec

    if seconds < 1:
        return "instantly"
    elif seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.0f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.0f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.0f} days"
    elif seconds < 31536000 * 1000:
        return f"{seconds / 31536000:.0f} years"
    elif seconds < 31536000 * 1_000_000:
        return f"{seconds / 31536000:.0f} years"
    else:
        exp = int(math.log10(seconds / 31536000))
        return f"~10^{exp} years"


# ── Display ──────────────────────────────────────────────────────────

def display_password(password: str, analysis: dict):
    a = analysis

    print(f"\n  {C.BOLD}{C.WHITE}Generated Password:{C.RESET}")
    print(f"  ╔{'═' * (len(password) + 4)}╗")
    print(f"  ║  {C.BOLD}{C.CYAN}{password}{C.RESET}  ║")
    print(f"  ╚{'═' * (len(password) + 4)}╝")

    print(f"\n  {C.BOLD}Strength Analysis:{C.RESET}")
    print(f"  {a['bar']}  {a['color']}{C.BOLD}{a['grade']}{C.RESET}")
    print()
    print(f"  {C.YELLOW}{'Length':<18}{C.RESET} {a['length']} characters")
    print(f"  {C.YELLOW}{'Entropy':<18}{C.RESET} {a['entropy']} bits")
    print(f"  {C.YELLOW}{'Charset size':<18}{C.RESET} {a['charset_size']} characters")
    print(f"  {C.YELLOW}{'Combinations':<18}{C.RESET} {format_combinations(a['combinations'])}")
    print(f"  {C.YELLOW}{'Crack time':<18}{C.RESET} {crack_time(a['combinations'])} (10B guesses/s)")
    print()
    print(f"  {C.YELLOW}{'Character types':<18}{C.RESET} ", end="")
    types = []
    if a["has_lower"]:
        types.append(f"{C.GREEN}abc{C.RESET}")
    if a["has_upper"]:
        types.append(f"{C.GREEN}ABC{C.RESET}")
    if a["has_digit"]:
        types.append(f"{C.GREEN}123{C.RESET}")
    if a["has_symbol"]:
        types.append(f"{C.GREEN}!@#{C.RESET}")
    print("  ".join(types))
    
    # Show how many more symbols needed and suggest improved password
    if a["missing_symbols"] > 0 or a["suggested_password"]:
        print()
        if a["missing_symbols"] > 0:
            print(f"  {C.YELLOW}{'Need':<18}{C.RESET} {C.RED}+{a['missing_symbols']} more characters{C.RESET} for strong password (80+ bits)")
        if a["suggested_password"]:
            suggested_analysis = analyze_strength(a["suggested_password"])
            print(f"\n  {C.BOLD}{C.GREEN}💡 Suggested stronger password:{C.RESET}")
            print(f"  ╔{'═' * (len(a['suggested_password']) + 4)}╗")
            print(f"  ║  {C.BOLD}{C.GREEN}{a['suggested_password']}{C.RESET}  ║")
            print(f"  ╚{'═' * (len(a['suggested_password']) + 4)}╝")
            print(f"  {C.GREEN}  → Entropy: {suggested_analysis['entropy']} bits ({suggested_analysis['grade']}){C.RESET}")
    print()


# ── Entry point ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(prog="passforge", description="Secure password generator")
    parser.add_argument("-l", "--length", type=int, default=16, help="password length (default: 16)")
    parser.add_argument("-n", "--count", type=int, default=1, help="number of passwords to generate")
    parser.add_argument("--no-upper", action="store_true", help="exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="exclude digits")
    parser.add_argument("--no-symbols", action="store_true", help="exclude special characters")
    parser.add_argument("--exclude", default="", help="specific characters to exclude")
    parser.add_argument("--analyze", metavar="PWD", help="analyze strength of existing password")

    args = parser.parse_args()
    print(BANNER)

    if args.analyze:
        analysis = analyze_strength(args.analyze)
        display_password(args.analyze, analysis)
        return

    for i in range(args.count):
        pw = generate_password(
            length=args.length,
            upper=not args.no_upper,
            lower=not args.no_lower,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            exclude=args.exclude,
        )
        analysis = analyze_strength(pw)
        display_password(pw, analysis)
        if i < args.count - 1:
            print(f"  {C.GRAY}{'─' * 50}{C.RESET}")


if __name__ == "__main__":
    main()
