Python Exploit Pattern Tool
===========================

Python implementation of Metasploit's pattern generator and search.

Starts faster and rolls both tools into one.

## Generate a pattern

    $> pattern.py 100
    Aa0Aa0Aa1Aa1Aa2Aa2Aa3Aa3Aa4Aa4Aa5Aa5Aa6Aa6Aa7Aa7Aa8Aa8Aa9Aa9Ab0Ab0Ab1Ab1Ab2Ab2Ab3Ab3Ab4Ab4Ab5Ab5Ab6A

## Search for a pattern

    $> pattern.py Bf4B
    Pattern Bf4 first occurrence at position 942 in pattern.
    $> pattern.py 0x42346642
    Pattern 0x42346642 first occurrence at position 942 in pattern.
    
Use it how you want.
