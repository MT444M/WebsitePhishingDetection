"""
File: feature_derivation.py
Description:
This module implements custom feature derivation for phishing website detection.
It contains two sections:
  (A) URL Composition & Complexity Measures
      - Features: URLComplexity, CharacterComplexity, LetterCntInURL, URLLetterRatio,
        DigitCntInURL, URLDigitRatio, EqualCharCntInURL, QuesMarkCntInURL,
        AmpCharCntInURL, OtherSpclCharCntInURL, URLOtherSpclCharRatio, NumberOfHashtags
  (B) Security & Statistical Metrics
      - Features: ShannonEntropy, KolmogorovComplexity, FractalDimension,
        HexPatternCnt, Base64PatternCnt
"""

import math
import re
import zlib
import numpy as np

# -----------------------------
# (A) URL Composition & Complexity Measures
# -----------------------------
def get_url_composition_features(url: str) -> dict:
    """
    Compute various URL composition features based solely on the URL string.
    
    Returns a dictionary with the following keys:
      - URLComplexity: Ratio of unique characters to total length.
      - CharacterComplexity: Average absolute difference between adjacent character ASCII codes.
      - LetterCntInURL: Count of alphabetic characters.
      - URLLetterRatio: Ratio of letters to total URL length.
      - DigitCntInURL: Count of digits.
      - URLDigitRatio: Ratio of digits to total URL length.
      - EqualCharCntInURL: Count of '=' characters.
      - QuesMarkCntInURL: Count of '?' characters.
      - AmpCharCntInURL: Count of '&' characters.
      - OtherSpclCharCntInURL: Count of non-alphanumeric characters excluding '=', '?', '&', '#'.
      - URLOtherSpclCharRatio: Ratio of other special character count to total URL length.
      - NumberOfHashtags: Count of '#' characters.
    """
    features = {}
    url_length = len(url) if len(url) > 0 else 1  # Avoid division by zero

    # URLComplexity: ratio of unique char count to length.
    features['URLComplexity'] = len(set(url)) / url_length

    # CharacterComplexity: average absolute difference between consecutive characters.
    if url_length > 1:
        diffs = [abs(ord(url[i]) - ord(url[i - 1])) for i in range(1, url_length)]
        features['CharacterComplexity'] = sum(diffs) / (len(diffs))
    else:
        features['CharacterComplexity'] = 0

    # Count letters and digits
    letter_count = sum(1 for c in url if c.isalpha())
    digit_count = sum(1 for c in url if c.isdigit())
    features['LetterCntInURL'] = letter_count
    features['URLLetterRatio'] = letter_count / url_length
    features['DigitCntInURL'] = digit_count
    features['URLDigitRatio'] = digit_count / url_length

    # Specific symbol counts
    equal_count = url.count('=')
    ques_count = url.count('?')
    amp_count = url.count('&')
    hashtag_count = url.count('#')
    features['EqualCharCntInURL'] = equal_count
    features['QuesMarkCntInURL'] = ques_count
    features['AmpCharCntInURL'] = amp_count
    features['NumberOfHashtags'] = hashtag_count

    # Count "other" special characters:
    # Define other special as any non alphanumeric char excluding: '=', '?', '&', '#'
    special_count = 0
    for c in url:
        if not c.isalnum() and c not in ['=', '?', '&', '#']:
            special_count += 1
    features['OtherSpclCharCntInURL'] = special_count
    features['URLOtherSpclCharRatio'] = special_count / url_length

    return features

# -----------------------------
# (B) Security & Statistical Metrics
# -----------------------------
def shannon_entropy(url: str) -> float:
    """
    Compute the Shannon entropy of the URL string.
    
    Entropy is calculated as: sum(-p * log2(p)) for each unique symbol.
    """
    if len(url) == 0:
        return 0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(url)
        entropy -= p * math.log(p, 2)
    return entropy

def kolmogorov_complexity(url: str) -> float:
    """
    Provide a rough approximation of the Kolmogorov Complexity
    by comparing the size after compression to the original size.
    
    Lower ratio suggests higher compressibility (less complexity).
    """
    if len(url) == 0:
        return 0
    original_bytes = url.encode('utf-8')
    compressed = zlib.compress(original_bytes)
    return len(compressed) / len(original_bytes)

def higuchi_fractal_dimension(url: str, kmax: int = 10) -> float:
    """
    Compute an approximation of the fractal dimension of the URL string
    using the Higuchi method. The URL is first converted into a time series
    of ASCII values.
    
    Returns the estimated fractal dimension.
    """
    # Convert URL to numeric time series (list of ASCII values)
    x = np.array([ord(c) for c in url], dtype=float)
    N = len(x)
    if N < 2:
        return 0

    L = []
    kmax = min(kmax, N // 2) if N // 2 >= 1 else 1

    for k in range(1, kmax + 1):
        Lk = []
        for m in range(k):
            Lmk = 0
            n_max = int(np.floor((N - m - 1) / k))
            if n_max == 0:
                continue
            for i in range(1, n_max + 1):
                Lmk += abs(x[m + i * k] - x[m + (i - 1) * k])
            Lmk = (Lmk * (N - 1)) / (n_max * k)
            Lk.append(Lmk)
        if Lk:
            L.append(np.mean(Lk))
    if not L:
        return 0

    lnL = np.log(L)
    ln_k = -np.log(np.arange(1, len(L) + 1))
    # Linear regression via polyfit; slope approximates fractal dimension
    coeffs = np.polyfit(ln_k, lnL, 1)
    return float(coeffs[0])

def count_hex_patterns(url: str) -> int:
    """
    Count occurrences of hexadecimal patterns in the URL.
    
    This regex finds words composed solely of hexadecimal digits with a length of 6 or more.
    """
    pattern = re.compile(r'\b[0-9A-Fa-f]{6,}\b')
    matches = pattern.findall(url)
    return len(matches)



def count_base64_patterns(url: str) -> int:
    """
    Count occurrences of substrings that match a basic Base64 pattern.
    
    Note: This is a heuristic approach. The regex below matches sequences of characters
    that look like Base64 strings (8 or more characters optionally ending with '=' or '==').
    """
    pattern = re.compile(r'(?:[A-Za-z0-9+/]{8,}(?:==|=)?)')
    matches = pattern.findall(url)
    return len(matches)

# -----------------------------
# Aggregating All Derived Features
# -----------------------------
def derive_features(url: str) -> dict:
    """
    Given a URL string, compute and return a dictionary containing:
      - All URL composition metrics.
      - All security/statistical metrics.
      
    Ignores features (like LikelinessIndex and aggregated scores) we are not sure about.
    """
    features = {}
    
    # Section (A) URL Composition & Complexity
    composition = get_url_composition_features(url)
    features.update(composition)
    
    # Section (B) Security & Statistical Metrics
    features['ShannonEntropy'] = shannon_entropy(url)
    features['KolmogorovComplexity'] = kolmogorov_complexity(url)
    features['FractalDimension'] = higuchi_fractal_dimension(url)
    features['HexPatternCnt'] = count_hex_patterns(url)
    features['Base64PatternCnt'] = count_base64_patterns(url)
    
    return features

# -----------------------------
# EXAMPLE USAGE
# -----------------------------
if __name__ == '__main__':
    test_url = "https://example.com/path/page?id=1234&param=test#section"
    derived = derive_features(test_url)
    
    print("Derived URL Features for:", test_url)
    for key, value in derived.items():
        print(f"{key}: {value}")
