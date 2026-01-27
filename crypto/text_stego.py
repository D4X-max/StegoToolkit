import binascii

# Invisible Unicode characters
# U+200B (Zero Width Space) = binary 0
# U+200C (Zero Width Non-Joiner) = binary 1
ZERO_WIDTH_MAP = {'0': '\u200b', '1': '\u200c'}
REVERSE_MAP = {'\u200b': '0', '\u200c': '1'}

def hide_text_in_text(cover_text, secret_encrypted):
    # Convert encrypted string to binary
    binary_secret = ''.join(format(ord(c), '08b') for c in secret_encrypted)
    
    # Map bits to invisible characters
    invisible_string = ''.join(ZERO_WIDTH_MAP[bit] for bit in binary_secret)
    
    # Inject into the middle of the cover text
    mid = len(cover_text) // 2
    return cover_text[:mid] + invisible_string + cover_text[mid:]

def extract_text_from_text(stego_text):
    extracted_bits = ""
    for char in stego_text:
        if char in REVERSE_MAP:
            extracted_bits += REVERSE_MAP[char]
            
    if not extracted_bits:
        return ""

    # Convert binary back to string
    chars = [chr(int(extracted_bits[i:i+8], 2)) for i in range(0, len(extracted_bits), 8)]
    return "".join(chars)