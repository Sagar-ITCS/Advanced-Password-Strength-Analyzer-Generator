"""
SAGAR RATHOD
Copyright@2025

Advanced Password Strength Analyzer + Enhanced Wordlist Generator + Secure Password Generator

NEW FEATURES:
- Passphrase generation with Diceware-style word selection
- Cryptographically secure random password generation
- Advanced pattern detection (keyboard walks, repeated patterns)
- Password mutation strategies
- Dictionary attack simulation
- Password strength scoring with detailed breakdown
- Common pattern detection and prevention

Usage (CLI examples):
  # Analyze a password with comprehensive checks:
  python password_analyzer.py --analyze "P@ssw0rd2023!" --deep-check

  # Generate secure random passwords:
  python password_analyzer.py --gen-secure --count 5 --length 20

  # Generate passphrase (highly secure):
  python password_analyzer.py --gen-passphrase --words 6

  # Generate wordlist with advanced mutations:
  python password_analyzer.py --names "Alice,Bob" --pets "fluffy" --years "1990-1995" --advanced-mutations

  # Run GUI with all features:
  python password_analyzer.py --gui
"""

import math
import argparse
import itertools
import os
import re
import sys
import secrets
import string
import hashlib
from datetime import datetime
from collections import Counter
from diceware_words import *


# Try to import zxcvbn
try:
    from zxcvbn import zxcvbn
    ZXC_AVAILABLE = True
except Exception:
    ZXC_AVAILABLE = False

# GUI attempt
USE_CUSTOM_TK = False
tk = None  # Initialize tk variable first

try:
    import customtkinter as ctk
    import tkinter as tk  # Import tk even when using customtkinter
    from tkinter import filedialog, messagebox, scrolledtext
    USE_CUSTOM_TK = True
except Exception:
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox, scrolledtext
        USE_CUSTOM_TK = False
    except Exception:
        tk = None

# -------------------------
# ENHANCED SECURITY FEATURES
# -------------------------

# Diceware-inspired word list (top common but memorable words)
DICEWARE_WORDS=[]
DICEWARE_WORDS.extend(DICEWARE_WORDS_LIST)


# Keyboard walk patterns
KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1qaz2wsx", "!QAZ@WSX", "qazwsx", "123456", "password"
]

# Common substitution patterns (beyond basic leet)
ADVANCED_LEET = {
    'a': ['@', '4', 'Λ', 'α', 'Α', '/\\'],
    'b': ['8', '6', 'ß', '฿'],
    'c': ['(', '<', '{', '©', '¢'],
    'e': ['3', '€', 'ε', 'Σ', '&'],
    'g': ['9', '6', '&'],
    'h': ['#', '|-|', '}{'],
    'i': ['1', '!', '|', 'ı', 'ï'],
    'l': ['1', '|', '£', '7'],
    'o': ['0', 'Ø', 'ø', '°', 'ö'],
    's': ['$', '5', 'ş', '§'],
    't': ['7', '+', '†', '‡'],
    'z': ['2', '%', '≥']
}

# Character substitution for advanced mutations
UNICODE_CONFUSABLES = {
    'a': ['а', 'ɑ', 'α'],  # Cyrillic and Greek
    'e': ['е', 'ε', 'ė'],
    'o': ['о', 'ο', 'ο'],
    'p': ['р', 'ρ'],
    'c': ['с', 'ϲ'],
    'x': ['х', 'χ'],
    'y': ['у', 'ɣ']
}

def generate_secure_password(length=0, include_symbols=True, include_numbers=True, 
                            include_upper=True, include_lower=True, exclude_ambiguous=False):
    """
    Generate cryptographically secure random password using secrets module.
    """
    charset = ''
    if include_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace('l', '').replace('o', '')
        charset += chars
    if include_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace('I', '').replace('O', '')
        charset += chars
    if include_numbers:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('1', '')
        charset += chars
    if include_symbols:
        chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if exclude_ambiguous:
            chars = chars.replace('|', '').replace('`', '')
        charset += chars
    
    if not charset:
        charset = string.ascii_letters + string.digits
    
    # Ensure at least one character from each category
    password = []
    if include_lower:
        password.append(secrets.choice(string.ascii_lowercase))
    if include_upper:
        password.append(secrets.choice(string.ascii_uppercase))
    if include_numbers:
        password.append(secrets.choice(string.digits))
    if include_symbols:
        password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    # Fill the rest randomly
    for _ in range(length - len(password)):
        password.append(secrets.choice(charset))
    
    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

def generate_passphrase(num_words=random_passphrase_length(), separator='-', capitalize=True, add_number=True):
    """
    Generate a strong passphrase using random words (Diceware-style).
    Example: Correct-Horse-Battery-Staple-42
    """
    words = [secrets.choice(DICEWARE_WORDS) for _ in range(num_words)]
    
    if capitalize:
        words = [w.capitalize() for w in words]
    
    passphrase = separator.join(words)
    
    if add_number:
        passphrase += separator + str(secrets.randbelow(100))
    
    return passphrase

def detect_keyboard_walk(password):
    """
    Detect keyboard walk patterns (e.g., qwerty, asdfgh).
    """
    pwd_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pwd_lower or pattern[::-1] in pwd_lower:
            return True, f"Keyboard pattern detected: {pattern}"
    return False, ""

def detect_repeated_patterns(password):
    """
    Detect repeated character patterns (e.g., aaa, 111, abcabc).
    """
    # Check for 3+ repeated characters
    if re.search(r'(.)\1{2,}', password):
        return True, "Repeated characters detected"
    
    # Check for repeated sequences
    for i in range(2, len(password) // 2 + 1):
        pattern = password[:i]
        if password.count(pattern) >= 2:
            return True, f"Repeated pattern detected: {pattern}"
    
    return False, ""

def detect_sequential_patterns(password):
    """
    Detect sequential patterns (e.g., abc, 123, cba, 321).
    """
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "0123456789"
    ]
    
    for seq in sequences:
        for i in range(len(seq) - 2):
            forward = seq[i:i+3]
            backward = forward[::-1]
            if forward in password or backward in password:
                return True, f"Sequential pattern detected: {forward} or {backward}"
    
    return False, ""

def calculate_enhanced_entropy(password):
    """
    Enhanced entropy calculation considering character diversity and length.
    """
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password): pool += 32
    if re.search(r'[^\x00-\x7F]', password): pool += 100  # Unicode characters
    
    if pool == 0:
        return 0.0
    
    # Calculate character frequency entropy
    char_freq = Counter(password)
    freq_entropy = 0
    for count in char_freq.values():
        p = count / len(password)
    if p > 0:
        freq_entropy -= p * math.log2(p)
    
    # Base entropy
    base_entropy = len(password) * (pool.bit_length())
    
    # Adjust for patterns
    pattern_penalty = 0
    if detect_keyboard_walk(password)[0]:
        pattern_penalty += 10
    if detect_repeated_patterns(password)[0]:
        pattern_penalty += 10
    if detect_sequential_patterns(password)[0]:
        pattern_penalty += 10
    
    return max(0, round(base_entropy + freq_entropy - pattern_penalty, 2))

def analyze_password_advanced(password, user_inputs=None):
    """
    Advanced password analysis with comprehensive checks.
    """
    result = {
        'password_length': len(password),
        'entropy': calculate_enhanced_entropy(password),
        'patterns': [],
        'warnings': [],
        'suggestions': [],
        'score': 0,  # 0-100
        'strength': 'Unknown'
    }
    
    # Pattern checks
    kb_walk, kb_msg = detect_keyboard_walk(password)
    if kb_walk:
        result['patterns'].append(kb_msg)
        result['warnings'].append(kb_msg)
    
    repeat, repeat_msg = detect_repeated_patterns(password)
    if repeat:
        result['patterns'].append(repeat_msg)
        result['warnings'].append(repeat_msg)
    
    seq, seq_msg = detect_sequential_patterns(password)
    if seq:
        result['patterns'].append(seq_msg)
        result['warnings'].append(seq_msg)
    
    # Character diversity
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
    
    diversity = sum([has_lower, has_upper, has_digit, has_symbol])
    
    # Calculate score
    score = 0
    score += min(30, len(password) * 2)  # Length (max 30 points)
    score += diversity * 15  # Diversity (max 60 points)
    score += min(10, result['entropy'] / 10)  # Entropy bonus (max 10 points)
    
    # Penalties
    score -= len(result['patterns']) * 10
    if len(password) < 8:
        score -= 20
        result['warnings'].append("Password is too short (minimum 8 characters recommended)")
    
    result['score'] = max(0, min(100, int(score)))
    
    # Strength rating
    if result['score'] >= 80:
        result['strength'] = 'Very Strong'
    elif result['score'] >= 60:
        result['strength'] = 'Strong'
    elif result['score'] >= 40:
        result['strength'] = 'Moderate'
    elif result['score'] >= 20:
        result['strength'] = 'Weak'
    else:
        result['strength'] = 'Very Weak'
    
    # Suggestions
    if not has_upper:
        result['suggestions'].append("Add uppercase letters")
    if not has_lower:
        result['suggestions'].append("Add lowercase letters")
    if not has_digit:
        result['suggestions'].append("Add numbers")
    if not has_symbol:
        result['suggestions'].append("Add special symbols (!@#$%^&*)")
    if len(password) < 12:
        result['suggestions'].append("Use at least 12 characters")
    if diversity < 3:
        result['suggestions'].append("Use a mix of character types")
    if result['patterns']:
        result['suggestions'].append("Avoid common patterns and sequences")
    
    # Use zxcvbn if available
    if ZXC_AVAILABLE:
        try:
            zx = zxcvbn(password, user_inputs=user_inputs or [])
            result['zxcvbn_score'] = zx.get('score', 0)
            result['crack_time'] = zx.get('crack_times_display', {})
        except Exception:
            pass
    
    return result

# -------------------------
# ADVANCED WORDLIST GENERATION
# -------------------------

def advanced_leet_variants(word, max_variants=100):
    """
    Generate advanced leetspeak variants using extended substitution table.
    """
    letters = list(word.lower())
    pools = []
    for ch in letters:
        if ch in ADVANCED_LEET:
            pools.append([ch] + ADVANCED_LEET[ch][:3])  # Limit for performance
        else:
            pools.append([ch])
    
    variants = set()
    for combo in itertools.product(*pools):
        variants.add(''.join(combo))
        if len(variants) >= max_variants:
            break
    return list(variants)

def apply_unicode_confusables(word, probability=0.3):
    """
    Replace characters with visually similar Unicode characters.
    """
    result = []
    for ch in word.lower():
        if ch in UNICODE_CONFUSABLES and secrets.randbelow(100) < probability * 100:
            result.append(secrets.choice(UNICODE_CONFUSABLES[ch]))
        else:
            result.append(ch)
    return ''.join(result)

def apply_character_injection(word, chars='!@#$%^&*', positions='random', count=1):
    """
    Inject special characters at strategic positions.
    """
    variants = []
    word_list = list(word)
    
    if positions == 'random':
        for _ in range(count):
            temp = word_list.copy()
            pos = secrets.randbelow(len(temp) + 1)
            temp.insert(pos, secrets.choice(chars))
            variants.append(''.join(temp))
    elif positions == 'beginning':
        for ch in chars[:count]:
            variants.append(ch + word)
    elif positions == 'end':
        for ch in chars[:count]:
            variants.append(word + ch)
    elif positions == 'both':
        for ch in chars[:count]:
            variants.append(ch + word + ch)
    
    return variants

def apply_case_mutations(word):
    """
    Generate various case mutation patterns.
    """
    variants = {
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.title(),
    }
    
    # Alternating case
    alt1 = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(word))
    alt2 = ''.join(c.lower() if i % 2 else c.upper() for i, c in enumerate(word))
    variants.add(alt1)
    variants.add(alt2)
    
    # Random case (1-2 variants)
    for _ in range(2):
        random_case = ''.join(
            c.upper() if secrets.randbelow(2) else c.lower() 
            for c in word
        )
        variants.add(random_case)
    
    return list(variants)

def apply_year_variations(word, years):
    """
    Append years with various formats.
    """
    variants = set()
    for year in years:
        if '-' in str(year):
            start, end = str(year).split('-', 1)
            try:
                for y in range(int(start), int(end) + 1):
                    variants.add(f"{word}{y}")
                    variants.add(f"{word}_{y}")
                    variants.add(f"{y}{word}")
                    variants.add(f"{word}{str(y)[2:]}")  # Last 2 digits
            except ValueError:
                continue
        else:
            variants.add(f"{word}{year}")
            variants.add(f"{word}_{year}")
            variants.add(f"{year}{word}")
            if len(str(year)) == 4:
                variants.add(f"{word}{str(year)[2:]}")
    
    return list(variants)

def generate_advanced_wordlist(seeds, opts):
    """
    Generate wordlist with advanced mutation techniques.
    """
    results = set()
    
    # Clean seeds
    clean_seeds = [re.sub(r'\s+', '', str(s)) for s in seeds if s]
    clean_seeds = list(dict.fromkeys(clean_seeds))  # Remove duplicates
    
    for seed in clean_seeds:
        # Original
        results.add(seed)
        
        # Case mutations
        if opts.get('add_case', True):
            for variant in apply_case_mutations(seed):
                results.add(variant)
        
        # Advanced leet speak
        if opts.get('add_leet', True):
            for variant in advanced_leet_variants(seed, max_variants=50):
                results.add(variant)
        
        # Character injection
        if opts.get('add_symbols', False):
            for variant in apply_character_injection(seed, count=2):
                results.add(variant)
        
        # Unicode confusables (if enabled)
        if opts.get('add_unicode', False):
            for _ in range(3):
                results.add(apply_unicode_confusables(seed))
        
        # Year variations
        if opts.get('years'):
            for variant in apply_year_variations(seed, opts['years']):
                results.add(variant)
    
    # Combine seeds
    if opts.get('combine', True) and len(clean_seeds) > 1:
        separators = opts.get('separators', ['', '_', '-', '.', '@'])
        for r in range(2, min(4, len(clean_seeds) + 1)):
            for combo in itertools.permutations(clean_seeds, r):
                for sep in separators:
                    combined = sep.join(combo)
                    results.add(combined)
                    
                    # Apply mutations to combinations
                    if opts.get('add_case'):
                        results.add(combined.capitalize())
                        results.add(combined.upper())
    
    # Filter by length
    minlen = int(opts.get('minlen', 1))
    maxlen = int(opts.get('maxlen', 64))
    filtered = [w for w in results if minlen <= len(w) <= maxlen]
    
    # Sort by strength (longer and more complex first)
    filtered.sort(key=lambda x: (len(x), sum(c in string.punctuation for c in x)), reverse=True)
    
    return filtered

# -------------------------
# UTILITY FUNCTIONS
# -------------------------

def parse_years_arg(years_arg):
    """Parse comma-separated years and ranges."""
    if not years_arg:
        return []
    parts = re.split(r'[,\s]+', str(years_arg).strip())
    return [p for p in parts if p]

def export_wordlist(lines, outfile):
    """Export wordlist to file."""
    with open(outfile, 'w', encoding='utf-8') as f:
        for line in lines:
            f.write(line + '\n')
    return os.path.abspath(outfile)

def build_seed_list(inputs):
    """Build seed list from user inputs."""
    seeds = []
    for key in ('names', 'nicknames', 'pets', 'keywords', 'usernames'):
        values = inputs.get(key, [])
        for v in values:
            v = str(v).strip()
            if v:
                seeds.append(v)
    
    # Add dates
    for d in inputs.get('dates', []):
        dd = re.sub(r'\D', '', str(d))
        if dd:
            seeds.append(dd)
    
    return list(dict.fromkeys(seeds))  # Remove duplicates

# -------------------------
# CLI FUNCTIONS
# -------------------------

def cli_main(args):
    """Main CLI handler."""
    
    # Generate secure password
    if args.gen_secure:
        count = args.count or 5
        length = args.length or 16
        print(f"\n🔐 Generating {count} cryptographically secure password(s):\n")
        for i in range(count):
            pwd = generate_secure_password(
                length=length,
                include_symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous
            )
            analysis = analyze_password_advanced(pwd)
            print(f"{i+1}. {pwd}")
            print(f"   Strength: {analysis['strength']} (Score: {analysis['score']}/100)")
            print(f"   Entropy: {analysis['entropy']} bits\n")
        return
    
    # Generate passphrase
    if args.gen_passphrase:
        num_words = args.words or random_passphrase_length()
        separator = args.separator or '-'
        print(f"\n🔑 Generating passphrase with {num_words} words:\n")
        passphrase = generate_passphrase(
            num_words=num_words,
            separator=separator,
            capitalize=not args.no_capitalize
        )
        analysis = analyze_password_advanced(passphrase)
        print(f"Passphrase: {passphrase}")
        print(f"Strength: {analysis['strength']} (Score: {analysis['score']}/100)")
        print(f"Entropy: {analysis['entropy']} bits")
        print(f"Length: {len(passphrase)} characters\n")
        return
    
    # Analyze password
    if args.analyze:
        print(f"\n📊 Analyzing password: {'*' * len(args.analyze)}\n")
        result = analyze_password_advanced(args.analyze)
        
        print(f"{'='*60}")
        print(f"ANALYSIS RESULTS")
        print(f"{'='*60}")
        print(f"Strength: {result['strength']}")
        print(f"Score: {result['score']}/100")
        print(f"Length: {result['password_length']} characters")
        print(f"Entropy: {result['entropy']} bits")
        
        if result.get('zxcvbn_score') is not None:
            print(f"zxcvbn Score: {result['zxcvbn_score']}/4")
        
        if result['warnings']:
            print(f"\n⚠️  WARNINGS:")
            for warning in result['warnings']:
                print(f"  • {warning}")
        
        if result['patterns']:
            print(f"\n🔍 PATTERNS DETECTED:")
            for pattern in result['patterns']:
                print(f"  • {pattern}")
        
        if result['suggestions']:
            print(f"\n💡 SUGGESTIONS:")
            for suggestion in result['suggestions']:
                print(f"  • {suggestion}")
        
        print(f"{'='*60}\n")
        return
    
    # Generate wordlist
    inputs = {
        'names': (args.names or "").split(',') if args.names else [],
        'nicknames': (args.nicknames or "").split(',') if args.nicknames else [],
        'pets': (args.pets or "").split(',') if args.pets else [],
        'keywords': (args.keywords or "").split(',') if args.keywords else [],
        'dates': (args.dates or "").split(',') if args.dates else [],
        'usernames': (args.usernames or "").split(',') if args.usernames else []
    }
    
    if any(inputs.values()) or args.generate:
        seeds = build_seed_list(inputs)
        
        if args.extra:
            extra = [x.strip() for x in args.extra.split(',') if x.strip()]
            seeds += extra
        
        if not seeds:
            print("❌ No seed inputs provided. Use --names, --pets, --keywords, etc.")
            return
        
        opts = {
            'years': parse_years_arg(args.years),
            'add_leet': not args.no_leet,
            'add_case': not args.no_case,
            'add_symbols': args.add_symbols,
            'add_unicode': args.add_unicode,
            'separators': args.separators.split(',') if args.separators else ['', '_', '-', '@'],
            'maxlen': args.maxlen or 64,
            'minlen': args.minlen or 1,
            'combine': not args.no_combine
        }
        
        print(f"\n🔨 Building advanced wordlist from {len(seeds)} seed(s)...")
        wordlist = generate_advanced_wordlist(seeds, opts)
        
        if args.limit:
            wordlist = wordlist[:args.limit]
        
        outfile = args.outfile or f"wordlist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        outpath = export_wordlist(wordlist, outfile)
        
        print(f"✅ Generated {len(wordlist)} entries")
        print(f"📁 Saved to: {outpath}\n")

# -------------------------
# GUI (Enhanced)
# -------------------------

def gui_main():
    """Launch enhanced GUI."""
    if not tk:
        print("❌ No GUI toolkit available. Install tkinter or customtkinter.")
        return
    
    if USE_CUSTOM_TK:
        app = ctk.CTk()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
    else:
        app = tk.Tk()
    
    app.title("Advanced Password Analyzer & Generator")
    app.geometry("1024x750")


    # Notebook/Tabs
    if USE_CUSTOM_TK:
        tabview = ctk.CTkTabview(app)
        tabview.pack(fill='both', expand=True, padx=10, pady=10)
        tab1 = tabview.add("Generate Secure")
        tab2 = tabview.add("Analyze")
        tab3 = tabview.add("Wordlist")
    else:
        notebook = ttk.Notebook(app)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        tab1 = ttk.Frame(notebook)
        tab2 = ttk.Frame(notebook)
        tab3 = ttk.Frame(notebook)
        notebook.add(tab1, text="Generate Secure")
        notebook.add(tab2, text="Analyze")
        notebook.add(tab3, text="Wordlist")
    
    # TAB 1: Generate Secure Passwords
    def setup_gen_tab(parent):
        if USE_CUSTOM_TK:
            ctk.CTkLabel(parent, text="Generate Secure Passwords", font=("Helvetica", 24, "bold")).pack(pady=30)
            
            frame = ctk.CTkFrame(parent)
            frame.pack(padx=20, pady=10, fill='x')
            
            ctk.CTkLabel(frame, text="Length:").grid(row=0, column=0, padx=5, pady=5)
            length_var = tk.IntVar(value=0)
            length_spin = ctk.CTkEntry(frame, width=60, textvariable=length_var)
            length_spin.grid(row=0, column=1, padx=5, pady=5)
            
            ctk.CTkLabel(frame, text="Count:").grid(row=0, column=2, padx=5, pady=5)
            count_var = tk.IntVar(value=0)
            count_spin = ctk.CTkEntry(frame, width=60, textvariable=count_var)
            count_spin.grid(row=0, column=3, padx=5, pady=5)
            
            output = ctk.CTkTextbox(parent, width=800, height=400)
            output.pack(padx=20, pady=10)
            
            def gen_passwords():
                output.delete('1.0', 'end')
                try:
                    length = length_var.get()
                    count = count_var.get()
                    for i in range(count):
                        pwd = generate_secure_password(length=length)
                        analysis = analyze_password_advanced(pwd)
                        output.insert('end', f"{i+1}. {pwd}\n")
                        output.insert('end', f"   Strength: {analysis['strength']} | Score: {analysis['score']}/100 | Entropy: {analysis['entropy']} bits\n\n")
                except Exception as e:
                        output.insert('end', f"Error: Please Provide Proper Password Credentials❗")
                    # output.insert('end', f"Error: {str(e)}\n")
            
            def gen_passphrase():
                output.delete('1.0', 'end')
                try:
                    passphrase = generate_passphrase(num_words=random_passphrase_length(), separator='-')
                    analysis = analyze_password_advanced(passphrase)
                    output.insert('end', f"Passphrase: {passphrase}\n\n")
                    output.insert('end', f"Strength: {analysis['strength']}\n")
                    output.insert('end', f"Score: {analysis['score']}/100\n")
                    output.insert('end', f"Entropy: {analysis['entropy']} bits\n")
                    output.insert('end', f"Length: {len(passphrase)} characters\n")
                except Exception as e:
                    output.insert('end', f"Error: {str(e)}\n")
            
            btn_frame = ctk.CTkFrame(parent)
            btn_frame.pack(pady=10)
            ctk.CTkButton(btn_frame, text="Generate Passwords", command=gen_passwords).pack(side='left', padx=5)
            ctk.CTkButton(btn_frame, text="Generate Passphrase", command=gen_passphrase).pack(side='left', padx=5)
            
            
        else:
            tk.Label(parent, text="Generate Secure Passwords", font=("Helvetica", 16, "bold")).pack(pady=10)
            
            frame = tk.Frame(parent)
            frame.pack(padx=20, pady=10, fill='x')
            
            tk.Label(frame, text="Length:").grid(row=0, column=0, padx=5, pady=5)
            length_var = tk.IntVar(value=0)
            tk.Spinbox(frame, from_=8, to=128, textvariable=length_var, width=10).grid(row=0, column=1, padx=5, pady=5)
            
            tk.Label(frame, text="Count:").grid(row=0, column=2, padx=5, pady=5)
            count_var = tk.IntVar(value=0)
            tk.Spinbox(frame, from_=1, to=50, textvariable=count_var, width=10).grid(row=0, column=3, padx=5, pady=5)
            
            output = scrolledtext.ScrolledText(parent, width=100, height=20)
            output.pack(padx=20, pady=10)
            
            def gen_passwords():
                output.delete('1.0', 'end')
                try:
                    length = length_var.get()
                    count = count_var.get()
                    for i in range(count):
                        pwd = generate_secure_password(length=length)
                        analysis = analyze_password_advanced(pwd)
                        output.insert('end', f"{i+1}. {pwd}\n")
                        output.insert('end', f"   Strength: {analysis['strength']} | Score: {analysis['score']}/100 | Entropy: {analysis['entropy']} bits\n\n")
                except Exception as e:
                    output.insert('end', f"Error: {str(e)}\n")
            
            def gen_passphrase():
                output.delete('1.0', 'end')
                try:
                    passphrase = generate_passphrase(num_words=random_passphrase_length(), separator='-')
                    analysis = analyze_password_advanced(passphrase)
                    output.insert('end', f"Passphrase: {passphrase}\n\n")
                    output.insert('end', f"Strength: {analysis['strength']}\n")
                    output.insert('end', f"Score: {analysis['score']}/100\n")
                    output.insert('end', f"Entropy: {analysis['entropy']} bits\n")
                    output.insert('end', f"Length: {len(passphrase)} characters\n")
                except Exception as e:
                    output.insert('end', f"Error: {str(e)}\n")
            
            btn_frame = tk.Frame(parent)
            btn_frame.pack(pady=10)
            tk.Button(btn_frame, text="Generate Passwords", command=gen_passwords).pack(side='left', padx=5)
            tk.Button(btn_frame, text="Generate Passphrase", command=gen_passphrase).pack(side='left', padx=5)
    
    # TAB 2: Analyze Password
    def setup_analyze_tab(parent):
        if USE_CUSTOM_TK:
            ctk.CTkLabel(parent, text="Password Strength Analyzer", font=("Helvetica", 24, "bold")).pack(pady=30)
            
            frame = ctk.CTkFrame(parent)
            frame.pack(padx=20, pady=10, fill='x')
            
            ctk.CTkLabel(frame, text="Enter Password:").pack(anchor='w', padx=5, pady=5)
            pwd_entry = ctk.CTkEntry(frame, width=600, show='*')
            pwd_entry.pack(fill='x', padx=5, pady=5)
            
            show_var = tk.BooleanVar()
            def toggle_show():
                pwd_entry.configure(show='' if show_var.get() else '*')
            ctk.CTkCheckBox(frame, text="Show Password", variable=show_var, command=toggle_show).pack(anchor='w', padx=5, pady=5)
            
            output = ctk.CTkTextbox(parent, width=800, height=400)
            output.pack(padx=20, pady=10)
            
            def analyze():
                output.delete('1.0', 'end')
                pwd = pwd_entry.get()
                if not pwd:
                    output.insert('end', "Please enter a password to analyze.\n")
                    return
                
                result = analyze_password_advanced(pwd)
                
                output.insert('end', "="*60 + "\n")
                output.insert('end', "ANALYSIS RESULTS\n")
                output.insert('end', "="*60 + "\n\n")
                output.insert('end', f"Strength: {result['strength']}\n")
                output.insert('end', f"Score: {result['score']}/100\n")
                output.insert('end', f"Length: {result['password_length']} characters\n")
                output.insert('end', f"Entropy: {result['entropy']} bits\n\n")
                
                if result.get('zxcvbn_score') is not None:
                    output.insert('end', f"zxcvbn Score: {result['zxcvbn_score']}/4\n\n")
                
                if result['warnings']:
                    output.insert('end', "⚠️  WARNINGS:\n")
                    for warning in result['warnings']:
                        output.insert('end', f"  • {warning}\n")
                    output.insert('end', "\n")
                
                if result['patterns']:
                    output.insert('end', "🔍 PATTERNS DETECTED:\n")
                    for pattern in result['patterns']:
                        output.insert('end', f"  • {pattern}\n")
                    output.insert('end', "\n")
                
                if result['suggestions']:
                    output.insert('end', "💡 SUGGESTIONS:\n")
                    for suggestion in result['suggestions']:
                        output.insert('end', f"  • {suggestion}\n")
                    output.insert('end', "\n")
                
                output.insert('end', "="*60 + "\n")
            
            ctk.CTkButton(parent, text="Analyze Password", command=analyze).pack(pady=10)
        else:
            tk.Label(parent, text="Password Strength Analyzer", font=("Helvetica", 24, "bold")).pack(pady=10)
            
            frame = tk.Frame(parent)
            frame.pack(padx=20, pady=10, fill='x')
            
            tk.Label(frame, text="Enter Password:").pack(anchor='w', padx=5, pady=5)
            pwd_entry = tk.Entry(frame, width=80, show='*')
            pwd_entry.pack(fill='x', padx=5, pady=5)
            
            show_var = tk.BooleanVar()
            def toggle_show():
                pwd_entry.configure(show='' if show_var.get() else '*')
            tk.Checkbutton(frame, text="Show Password", variable=show_var, command=toggle_show).pack(anchor='w', padx=5, pady=5)
            
            output = scrolledtext.ScrolledText(parent, width=100, height=20)
            output.pack(padx=20, pady=10)
            
            def analyze():
                output.delete('1.0', 'end')
                pwd = pwd_entry.get()
                if not pwd:
                    output.insert('end', "Please enter a password to analyze.\n")
                    return
                
                result = analyze_password_advanced(pwd)
                
                output.insert('end', "="*60 + "\n")
                output.insert('end', "ANALYSIS RESULTS\n")
                output.insert('end', "="*60 + "\n\n")
                output.insert('end', f"Strength: {result['strength']}\n")
                output.insert('end', f"Score: {result['score']}/100\n")
                output.insert('end', f"Length: {result['password_length']} characters\n")
                output.insert('end', f"Entropy: {result['entropy']} bits\n\n")
                
                if result.get('zxcvbn_score') is not None:
                    output.insert('end', f"zxcvbn Score: {result['zxcvbn_score']}/4\n\n")
                
                if result['warnings']:
                    output.insert('end', "WARNINGS:\n")
                    for warning in result['warnings']:
                        output.insert('end', f"  • {warning}\n")
                    output.insert('end', "\n")
                
                if result['patterns']:
                    output.insert('end', "PATTERNS DETECTED:\n")
                    for pattern in result['patterns']:
                        output.insert('end', f"  • {pattern}\n")
                    output.insert('end', "\n")
                
                if result['suggestions']:
                    output.insert('end', "SUGGESTIONS:\n")
                    for suggestion in result['suggestions']:
                        output.insert('end', f"  • {suggestion}\n")
                    output.insert('end', "\n")
                
                output.insert('end', "="*60 + "\n")
            
            tk.Button(parent, text="Analyze Password", command=analyze).pack(pady=10)
    
    # TAB 3: Wordlist Generator
    def setup_wordlist_tab(parent):
        if USE_CUSTOM_TK:
            ctk.CTkLabel(parent, text="Advanced Wordlist Generator", font=("Helvetica", 24, "bold")).pack(pady=30)
            
            input_frame = ctk.CTkFrame(parent)
            input_frame.pack(padx=20, pady=10, fill='x')
            
            ctk.CTkLabel(input_frame, text="Names (comma separated):").grid(row=0, column=0, sticky='w', padx=5, pady=3)
            names_e = ctk.CTkEntry(input_frame, width=400)
            names_e.grid(row=0, column=1, padx=5, pady=3)
            
            ctk.CTkLabel(input_frame, text="Pets (comma separated):").grid(row=1, column=0, sticky='w', padx=5, pady=3)
            pets_e = ctk.CTkEntry(input_frame, width=400)
            pets_e.grid(row=1, column=1, padx=5, pady=3)
            
            ctk.CTkLabel(input_frame, text="Keywords (comma separated):").grid(row=2, column=0, sticky='w', padx=5, pady=3)
            keywords_e = ctk.CTkEntry(input_frame, width=400)
            keywords_e.grid(row=2, column=1, padx=5, pady=3)
            
            ctk.CTkLabel(input_frame, text="Years (e.g., 1990-1995,2000):").grid(row=3, column=0, sticky='w', padx=5, pady=3)
            years_e = ctk.CTkEntry(input_frame, width=400)
            years_e.grid(row=3, column=1, padx=5, pady=3)
            
            opts_frame = ctk.CTkFrame(parent)
            opts_frame.pack(padx=20, pady=10, fill='x')
            
            advanced_var = tk.BooleanVar(value=True)
            ctk.CTkCheckBox(opts_frame, text="Advanced Mutations", variable=advanced_var).grid(row=0, column=0, padx=5, pady=3)
            
            unicode_var = tk.BooleanVar(value=False)
            ctk.CTkCheckBox(opts_frame, text="Unicode Variants", variable=unicode_var).grid(row=0, column=1, padx=5, pady=3)
            
            output = ctk.CTkTextbox(parent, width=800, height=300)
            output.pack(padx=20, pady=10)
            
            def generate_wl():
                output.delete('1.0', 'end')
                seeds = []
                
                for e in [names_e, pets_e, keywords_e]:
                    val = e.get().strip()
                    if val:
                        seeds += [x.strip() for x in val.split(',') if x.strip()]
                
                if not seeds:
                    output.insert('end', "Please provide at least one seed (name, pet, or keyword).\n")
                    return
                
                years_val = years_e.get().strip()
                years = parse_years_arg(years_val)
                
                opts = {
                    'years': years,
                    'add_leet': True,
                    'add_case': True,
                    'add_symbols': advanced_var.get(),
                    'add_unicode': unicode_var.get(),
                    'separators': ['', '_', '-', '@', '.'],
                    'maxlen': 32,
                    'minlen': 4,
                    'combine': True
                }
                
                output.insert('end', f"Generating wordlist from {len(seeds)} seed(s)...\n\n")
                wl = generate_advanced_wordlist(seeds, opts)
                
                output.insert('end', f"Generated {len(wl)} entries (showing first 100):\n\n")
                for i, word in enumerate(wl[:100], 1):
                    output.insert('end', f"{i:4d}. {word}\n")
                
                if USE_CUSTOM_TK:
                    from tkinter import filedialog
                    path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text','*.txt')])
                else:
                    path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text','*.txt')])
                
                if path:
                    export_wordlist(wl, path)
                    output.insert('end', f"\n✅ Saved {len(wl)} entries to: {path}\n")
            
            ctk.CTkButton(parent, text="Generate Wordlist", command=generate_wl).pack(pady=10)
        else:
            tk.Label(parent, text="Advanced Wordlist Generator", font=("Helvetica", 24, "bold")).pack(pady=10)
            
            input_frame = tk.Frame(parent)
            input_frame.pack(padx=20, pady=10, fill='x')
            
            tk.Label(input_frame, text="Names:").grid(row=0, column=0, sticky='w', padx=5, pady=3)
            names_e = tk.Entry(input_frame, width=50)
            names_e.grid(row=0, column=1, padx=5, pady=3)
            
            tk.Label(input_frame, text="Pets:").grid(row=1, column=0, sticky='w', padx=5, pady=3)
            pets_e = tk.Entry(input_frame, width=50)
            pets_e.grid(row=1, column=1, padx=5, pady=3)
            
            tk.Label(input_frame, text="Keywords:").grid(row=2, column=0, sticky='w', padx=5, pady=3)
            keywords_e = tk.Entry(input_frame, width=50)
            keywords_e.grid(row=2, column=1, padx=5, pady=3)
            
            tk.Label(input_frame, text="Years:").grid(row=3, column=0, sticky='w', padx=5, pady=3)
            years_e = tk.Entry(input_frame, width=50)
            years_e.grid(row=3, column=1, padx=5, pady=3)
            
            opts_frame = tk.Frame(parent)
            opts_frame.pack(padx=20, pady=10, fill='x')
            
            advanced_var = tk.BooleanVar(value=True)
            tk.Checkbutton(opts_frame, text="Advanced Mutations", variable=advanced_var).grid(row=0, column=0, padx=5, pady=3)
            
            unicode_var = tk.BooleanVar(value=False)
            tk.Checkbutton(opts_frame, text="Unicode Variants", variable=unicode_var).grid(row=0, column=1, padx=5, pady=3)
            
            output = scrolledtext.ScrolledText(parent, width=100, height=15)
            output.pack(padx=20, pady=10)
            
            def generate_wl():
                output.delete('1.0', 'end')
                seeds = []
                
                for e in [names_e, pets_e, keywords_e]:
                    val = e.get().strip()
                    if val:
                        seeds += [x.strip() for x in val.split(',') if x.strip()]
                
                if not seeds:
                    output.insert('end', "Please provide at least one seed.\n")
                    return
                
                years_val = years_e.get().strip()
                years = parse_years_arg(years_val)
                
                opts = {
                    'years': years,
                    'add_leet': True,
                    'add_case': True,
                    'add_symbols': advanced_var.get(),
                    'add_unicode': unicode_var.get(),
                    'separators': ['', '_', '-', '@', '.'],
                    'maxlen': 32,
                    'minlen': 4,
                    'combine': True
                }
                
                output.insert('end', f"Generating from {len(seeds)} seed(s)...\n\n")
                wl = generate_advanced_wordlist(seeds, opts)
                
                output.insert('end', f"Generated {len(wl)} entries (showing first 100):\n\n")
                for i, word in enumerate(wl[:100], 1):
                    output.insert('end', f"{i:4d}. {word}\n")
                
                path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text','*.txt')])
                if path:
                    export_wordlist(wl, path)
                    output.insert('end', f"\nSaved {len(wl)} entries to: {path}\n")
            
            tk.Button(parent, text="Generate Wordlist", command=generate_wl).pack(pady=10)
    
    setup_gen_tab(tab1)
    setup_analyze_tab(tab2)
    setup_wordlist_tab(tab3)
    
    app.mainloop()

# -------------------------
# MAIN
# -------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Password Strength Analyzer & Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 5 secure passwords (16 chars):
  python password_analyzer.py --gen-secure --length 16 --count 5
  
  # Generate passphrase:
  python password_analyzer.py --gen-passphrase --words 6
  
  # Analyze password:
  python password_analyzer.py --analyze "MyP@ssw0rd123" --deep-check
  
  # Generate advanced wordlist:
  python password_analyzer.py --names "John,Jane" --pets "Chikky" --years "1990-1995" --add-symbols --advanced-mutations
  
  # Launch GUI:
  python password_analyzer.py --gui
        """
    )
    
    # Password generation
    parser.add_argument('--gen-secure', action='store_true', help='Generate secure random passwords')
    parser.add_argument('--gen-passphrase', action='store_true', help='Generate passphrase')
    parser.add_argument('--length', type=int, help='Password length (default: 16)')
    parser.add_argument('--count', type=int, help='Number of passwords to generate (default: 5)')
    parser.add_argument('--words', type=int, help='Number of words in passphrase (default: 6)')
    parser.add_argument('--separator', help='Passphrase separator (default: -)')
    parser.add_argument('--no-symbols', action='store_true', help='Exclude symbols from password')
    parser.add_argument('--no-capitalize', action='store_true', help='Do not capitalize passphrase words')
    parser.add_argument('--exclude-ambiguous', action='store_true', help='Exclude ambiguous characters (0,O,l,1)')
    
    # Password analysis
    parser.add_argument('--analyze', help='Password to analyze')
    parser.add_argument('--deep-check', action='store_true', help='Perform deep analysis')
    
    # Wordlist generation
    parser.add_argument('--names', help='Comma separated names')
    parser.add_argument('--nicknames', help='Comma separated nicknames')
    parser.add_argument('--pets', help='Comma separated pet names')
    parser.add_argument('--keywords', help='Comma separated keywords')
    parser.add_argument('--dates', help='Comma separated dates')
    parser.add_argument('--usernames', help='Comma separated usernames')
    parser.add_argument('--years', help='Years/ranges (e.g., 1990-1995,2000,2022)')
    parser.add_argument('--extra', help='Extra words to include')
    parser.add_argument('--separators', help='Separators for combining (default: ,_,-,@)')
    parser.add_argument('--no-leet', action='store_true', help='No leetspeak variants')
    parser.add_argument('--no-case', action='store_true', help='No case variants')
    parser.add_argument('--no-combine', action='store_true', help='No word combinations')
    parser.add_argument('--add-symbols', action='store_true', help='Add symbol injection mutations')
    parser.add_argument('--add-unicode', action='store_true', help='Add Unicode confusable variants')
    parser.add_argument('--advanced-mutations', action='store_true', help='Enable all advanced mutations')
    parser.add_argument('--maxlen', type=int, help='Max word length')
    parser.add_argument('--minlen', type=int, help='Min word length')
    parser.add_argument('--limit', type=int, help='Limit output entries')
    parser.add_argument('--outfile', help='Output file path')
    parser.add_argument('--generate', action='store_true', help='Force wordlist generation')
    
    # GUI
    parser.add_argument('--gui', action='store_true', help='Launch GUI')
    
    args = parser.parse_args()
    
    # Enable all advanced features if flag is set
    if args.advanced_mutations:
        args.add_symbols = True
        args.add_unicode = True
    
    if args.gui:
        gui_main()
    else:
        cli_main(args)

if __name__ == '__main__':
    main()