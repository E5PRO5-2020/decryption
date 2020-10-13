"""
Implements decryption function for Kamstrup OmniPower wm-bus telegram
Uses a specific key and field values from a specific telegram to demonstrate the decryption

Janus Bo Andersen, October 2020
"""

from Crypto.Cipher import AES
from Crypto.Util import Counter
from binascii import hexlify, unhexlify


def test_aes_128():

    # AES-128 key for the OmniPower meter
    key = '9A25139E3244CC2E391A8EF6B915B697'

    # Encrypted portion of telegram
    ciphertext = 'D3A4F149B1B8F5783DF7434B8A66A55786499ABE7BAB59'

    # For mode 5 encryption, the prefix to counter value
    # is made from manufacturer and telegram data (see DS/EN 13757-3 or -7)
    prefix = '2D2C576866323002202187032000'

    # Make binary representations
    key = unhexlify(key)
    ciphertext = unhexlify(ciphertext)
    prefix = unhexlify(prefix)

    # Create cryptographic objects
    counter = Counter.new(nbits=16, prefix=prefix, initial_value=0x0000)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)

    # Perform decryption
    return hexlify(cipher.decrypt(ciphertext))

# Run the test
plaintext = test_aes_128()

# Comparison value from analyzed telegram (see slides)
comparison_value = '117079138C4491CE000000000000000300000000000000'.encode()

# Debug print
print(plaintext)
print(comparison_value)

# Test and compare binary representations
assert unhexlify(plaintext) == unhexlify(comparison_value)
