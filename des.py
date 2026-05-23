"""
DES encryption module - translated from the school's des.js (strEnc function).
Used to encrypt username/password before submitting to idm.swu.edu.cn.
"""

# S-box tables (identical to des.js)
S1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
]

S2 = [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
]

S3 = [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
]

S4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
]

S5 = [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
]

S6 = [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
]

S7 = [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
]

S8 = [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]

S_BOXES = [S1, S2, S3, S4, S5, S6, S7, S8]


def str_to_bt(s):
    """Convert a string (length <= 4) to a 64-element bit array."""
    bt = [0] * 64
    length = len(s)
    for i in range(length):
        k = ord(s[i])
        for j in range(16):
            pow_val = 1
            for m in range(15, j, -1):
                pow_val *= 2
            bt[16 * i + j] = (k // pow_val) % 2
    for p in range(length, 4):
        for q in range(16):
            bt[16 * p + q] = 0
    return bt


def get_key_bytes(key):
    """Split a key string into an array of 64-bit blocks."""
    key_bytes = []
    length = len(key)
    iterator = length // 4
    remainder = length % 4
    for i in range(iterator):
        key_bytes.append(str_to_bt(key[i * 4 : i * 4 + 4]))
    if remainder > 0:
        key_bytes.append(str_to_bt(key[i * 4 + 4 :]))
    return key_bytes


def bt64_to_hex(byte_data):
    """Convert 64-bit array to 16-char hex string."""
    hex_str = ""
    for i in range(16):
        bt = ""
        for j in range(4):
            bt += str(byte_data[i * 4 + j])
        hex_str += _bt4_to_hex(bt)
    return hex_str


def _bt4_to_hex(binary):
    mapping = {
        "0000": "0", "0001": "1", "0010": "2", "0011": "3",
        "0100": "4", "0101": "5", "0110": "6", "0111": "7",
        "1000": "8", "1001": "9", "1010": "A", "1011": "B",
        "1100": "C", "1101": "D", "1110": "E", "1111": "F",
    }
    return mapping[binary]


def _get_box_binary(i):
    mapping = {
        0: "0000", 1: "0001", 2: "0010", 3: "0011",
        4: "0100", 5: "0101", 6: "0110", 7: "0111",
        8: "1000", 9: "1001", 10: "1010", 11: "1011",
        12: "1100", 13: "1101", 14: "1110", 15: "1111",
    }
    return mapping[i]


def xor(a, b):
    return [a[i] ^ b[i] for i in range(len(a))]


def init_permute(original_data):
    ip = [0] * 64
    m, n = 1, 0
    for i in range(4):
        for j in range(7, -1, -1):
            ip[i * 8 + (7 - j)] = original_data[j * 8 + m]
            ip[i * 8 + (7 - j) + 32] = original_data[j * 8 + n]
        m += 2
        n += 2
    return ip


def expand_permute(right_data):
    ep = [0] * 48
    for i in range(8):
        if i == 0:
            ep[0] = right_data[31]
        else:
            ep[i * 6] = right_data[i * 4 - 1]
        ep[i * 6 + 1] = right_data[i * 4]
        ep[i * 6 + 2] = right_data[i * 4 + 1]
        ep[i * 6 + 3] = right_data[i * 4 + 2]
        ep[i * 6 + 4] = right_data[i * 4 + 3]
        if i == 7:
            ep[i * 6 + 5] = right_data[0]
        else:
            ep[i * 6 + 5] = right_data[i * 4 + 4]
    return ep


def s_box_permute(expand_byte):
    s_box_byte = [0] * 32
    for m in range(8):
        i_val = expand_byte[m * 6] * 2 + expand_byte[m * 6 + 5]
        j_val = (
            expand_byte[m * 6 + 1] * 8
            + expand_byte[m * 6 + 2] * 4
            + expand_byte[m * 6 + 3] * 2
            + expand_byte[m * 6 + 4]
        )
        binary = _get_box_binary(S_BOXES[m][i_val][j_val])
        for k in range(4):
            s_box_byte[m * 4 + k] = int(binary[k])
    return s_box_byte


def p_permute(s_box_byte):
    p_box = [0] * 32
    mapping = [
        15, 6, 19, 20, 28, 11, 27, 16,
        0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10, 3, 24,
    ]
    for i in range(32):
        p_box[i] = s_box_byte[mapping[i]]
    return p_box


def finally_permute(end_byte):
    fp = [0] * 64
    mapping = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24,
    ]
    for i in range(64):
        fp[i] = end_byte[mapping[i]]
    return fp


def generate_keys(key_byte):
    key = [0] * 56
    for i in range(7):
        for j in range(8):
            key[i * 8 + j] = key_byte[8 * (7 - j) + i]

    loop = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    keys = [[0] * 48 for _ in range(16)]

    for i in range(16):
        for _ in range(loop[i]):
            temp_left = key[0]
            temp_right = key[28]
            for k in range(27):
                key[k] = key[k + 1]
                key[28 + k] = key[29 + k]
            key[27] = temp_left
            key[55] = temp_right

        temp_key = [0] * 48
        pc2 = [
            13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
            22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
            40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
        ]
        for m in range(48):
            temp_key[m] = key[pc2[m]]
        keys[i] = temp_key

    return keys


def enc(data_byte, key_byte):
    """DES encryption core - encrypt 64-bit block with 64-bit key."""
    k = generate_keys(key_byte)
    ip_byte = init_permute(data_byte)
    ip_left = ip_byte[:32]
    ip_right = ip_byte[32:]

    for i in range(16):
        temp_left = ip_left[:]
        ip_left = ip_right[:]
        temp_right = xor(
            p_permute(s_box_permute(xor(expand_permute(ip_right), k[i]))),
            temp_left,
        )
        ip_right = temp_right

    final_data = ip_right + ip_left
    return finally_permute(final_data)


def str_enc(data, first_key, second_key="", third_key=""):
    """
    Encrypt a string using the school's custom DES implementation.
    Equivalent to JS: strEnc(data, firstKey, secondKey, thirdKey)
    """
    enc_data = ""
    first_key_bt = get_key_bytes(first_key) if first_key else []
    second_key_bt = get_key_bytes(second_key) if second_key else []
    third_key_bt = get_key_bytes(third_key) if third_key else []

    leng = len(data)
    if leng == 0:
        return ""

    iterator = leng // 4
    remainder = leng % 4

    for i in range(iterator):
        temp_data = data[i * 4 : i * 4 + 4]
        temp_byte = str_to_bt(temp_data)
        enc_byte = _encrypt_block(temp_byte, first_key_bt, second_key_bt, third_key_bt)
        enc_data += bt64_to_hex(enc_byte)

    if remainder > 0:
        remainder_data = data[iterator * 4 :]
        temp_byte = str_to_bt(remainder_data)
        enc_byte = _encrypt_block(temp_byte, first_key_bt, second_key_bt, third_key_bt)
        enc_data += bt64_to_hex(enc_byte)

    return enc_data


def _encrypt_block(block, first_key_bt, second_key_bt, third_key_bt):
    """Encrypt a 64-bit block with sequence of keys."""
    temp = block
    for kb in first_key_bt:
        temp = enc(temp, kb)
    for kb in second_key_bt:
        temp = enc(temp, kb)
    for kb in third_key_bt:
        temp = enc(temp, kb)
    return temp
