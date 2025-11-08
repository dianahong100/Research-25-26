# Baseline SPN with the main cipher design
# Rotate master key by 1 byte each round
# 8 rounds
# 4 x 4 S-boxes


# 10/19/2025
# 64-bit block with 31 rounds

import random
import math


blockSize = 64
verboseState = False
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
# 4 x 4 S-box (16-entries)
# PRESENT S-box
sbox = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
]

# inverse s-box
sbox_inverse =  [0] * 16
for i in range(16):
    sbox_inverse[sbox[i]] = i


# Apply sbox (1) to a 16 bit state and return the result

def apply_sbox(state, sbox):
    # applying the s box on each nibble of state
    for i in range(64 // 4):
        nibbles = [state >> (4 * i) & 0xF]
        # replace each nibble val with s-box output
        result = [sbox[n] for n in nibbles]
        # put trasnformed nibbles back to bit position
        return sum([result[i] << (4 * i) for i in range (4)])


# p box
pbox = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63}


def apply_pbox(state, pbox):
    PBOX = pbox
    output = 0
    for i in range(64):
        bit = (state >> i) & 1
        output |= bit << PBOX[i]
    return output

# main key generation
def mainKeyGen ():
    # generate 128 random bits to simulate a random key
    key = random.getrandbits(128)
    # bit mix to add diffusion manually
    for i in range(3):
        key ^= (key << 13) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        key &= (key >> 7)
        key ^= (key << 17) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    
    # convert to hex and slice into 20 characters
    hex_key = hex(key) [2:2 + 20]
    return hex_key      # main key to be turned into round keys

# generating round keys
def generate_round_keys(mainKey, num_rounds):
    round_keys = []
    key = mainKey
    for i in range(num_rounds):
        # extract 16 bit round key
        round_key = key & 0xFFFF    # keeps only lowest 16 bits
        round_keys.append(round_key)    # adds round keys to round_keys

        # key rotation: left 4 bits next round
        key = ((key << 4) | (key >> 12) & 0xFFFF)
    return round_keys



# encryption routine (😅😅😅✌️✌️)
plaintext = random.getrandbits(64)
roundkeys = generate_round_keys(mainKeyGen, 31)

def encrypt (pla_text, s_box, p_box, round_keys):
    state = pla_text;   # starting block

    # 30 rounds
    for r in range(31 - 1):
        # add (mix) round key
        state ^= round_keys[r]
        # susbstitution
        state = apply_sbox(state, sbox)
        # permute
        state = apply_sbox(state)

    # final round
    # sbox, then final key
    state ^= round_keys[-2]
    state = apply_sbox(state, sbox)
    state ^= round_keys[-1]

    return state    # cipher text

# REMINDER: MAKE DECRYPTION
# MUST MAKE DECRYPTION

