

# test for so far

from spn import mainKeyGen, generate_round_keys, encrypt, sbox, pbox
import random

def run_test():
    # plain text
    plaintext = random.getrandbits(64)
    print(hex(plaintext))

    # main key
    main_key = int(mainKeyGen(), 16)
    print(hex(main_key))

    # round keys
    round_keys = generate_round_keys(main_key, 31)
    print(hex(k) for k in round_keys[:3])   # first 3 round keys

    # encrypt
    ciphertext = encrypt(plaintext, sbox, pbox, round_keys)
    print(hex(ciphertext))

run_test()