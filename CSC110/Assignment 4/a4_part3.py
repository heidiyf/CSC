"""CSC110 Fall 2022 Assignment 4, Part 3: Number Theory, Cryptography, and Algorithm Running Time Analysis

Instructions (READ THIS FIRST!)
===============================

This Python module contains the functions you should complete for Part 3 of this assignment.

Copyright and Usage Information
===============================

This file is provided solely for the personal and private use of students
taking CSC110 at the University of Toronto St. George campus. All forms of
distribution of this code, whether as given or with any changes, are
expressly prohibited. For more information on copyright for CSC110 materials,
please consult our Course Syllabus.

This file is Copyright (c) 2022 David Liu and Tom Fairgrieve
"""
# import math

# You may uncomment this statement to import the math module in this file
import math

from python_ta.contracts import check_contracts


###############################################################################
# Part (a): From strings to numbers
###############################################################################
@check_contracts
def base128_to_int(digits: list[int]) -> int:
    """Return the integer represented by the given base-128 representation.

    The input list has the units (128 ** 0) digit at the LAST index.

    Preconditions:
        - digits != []
        - all({0 <= d < 128 for d in digits})

    >>> base128_to_int([1])
    1
    >>> base128_to_int([3, 2, 4])  # 3 * (128 ** 2) + 2 * (128 ** 1) + 4 * (128 ** 0)
    49412
    >>> base128_to_int([72, 101, 108, 108, 111])
    19540948591

    NOTE: this function can be implemented by either a for loop or a comprehension.
    For practice, we strongly recommend trying both implementations.
    """
    num = len(digits) - 1
    num_so_far = 0

    for digit in digits:
        if num >= 0:
            num_so_far += digit * (128 ** num)
            num -= 1
    return num_so_far


@check_contracts
def int_to_base128(n: int) -> list[int]:
    """Return the base-128 representation of the given number.

    The returned list has the units (128 ** 0) digit at the LAST index.
    The returned list should not have any leading zeros (i.e., the first element should be > 0).

    Preconditions:
    - n >= 1

    >>> int_to_base128(1)
    [1]
    >>> int_to_base128(49412)
    [3, 2, 4]

    HINTS: Here are two possible (ideas for) algorithms to solve this problem.
    You may use a different approach, as long as you use only programming elements and techniques
    allowed for this assignment. In particular, "recursion" is not permitted.

    APPROACH 1 ("big to small"):
        Start by computing the largest power of 128 that's less than n, and then compute the
        quotient (n // (128 ** ___)); that gives you the first element of the list.
        Update n in some way, and then repeat. You will find the math.log function useful.

    APPROACH 2 ("small to big"):
        Compute the remainder n % 128. That gives you the units digit (last element of the list).
        Update n in some way, and then repeat.
    """
    list_so_far = []
    while n >= 1:
        list_so_far.insert(0, n % 128)
        n = n // 128
    return list_so_far


###############################################################################
# Part (b): Encrypting and decrypting blocks
###############################################################################
@check_contracts
def rsa_encrypt_block(public_key: tuple[int, int], plaintext: str) -> list[int]:
    """Encrypt the given plaintext using the recipient's public key.

    Preconditions:
        - public_key is a valid RSA public key (n, e)
        - public_key[0] >= 128
        - all({ord(c) < 128 for c in plaintext})
        - plaintext != ''
        - len(plaintext) is divisibile by the block length

    NOTES:

    1. Use the math.pow function to compute a modular exponentiation, not ** and %.
       math.pow is much more efficient for larger numbers!
    2. You may find it useful to use range with THREE arguments, e.g. range(0, 10, 2).
       Experiment with this in the Python console!
    """
    # Divide the plaintext message into blocks of the calculated block length
    block_length = int(math.log(public_key[0]) / math.log(128))
    length = len(plaintext)
    text_block = [plaintext[i: i + block_length] for i in range(0, length, block_length)]

    # Convert string to integer (one integer per block)
    digits = []
    for block in text_block:
        digits.append([ord(letter) for letter in block])

    # Convert each block into an integer using the base-128 transformation
    plaintext_integer = []
    for digit in digits:
        plaintext_integer.append(base128_to_int(digit))

    # Apply the standard RSA modular exponentiation
    n, e = public_key[0], public_key[1]
    ciphertext = []
    for integer in plaintext_integer:
        ciphertext.append(pow(integer, e, n))
    return ciphertext


@check_contracts
def rsa_decrypt_block(private_key: tuple[int, int, int], ciphertext: list[int]) -> str:
    """Decrypt the given ciphertext using the recipient's private key.

    Preconditions:
        - private_key is a valid RSA private key (p, q, d)
        - private_key[0] * private_key[1] >= 128
        - ciphertext != []
        - all({0 <= num < private_key[0] * private_key[1] for num in ciphertext})
    """
    p, q, d = private_key[0], private_key[1], private_key[2]
    n = p * q

    block_length = int(math.log(n) / math.log(128))

    plaintext_int = []
    for integer in ciphertext:
        plaintext_int.append(pow(integer, d, n))

    digits = []
    for number in plaintext_int:
        lst = int_to_base128(number)
        while len(lst) < block_length:
            lst.insert(0, 0)
        digits.append(lst)

    plaintext = ''
    for digit in digits:
        for num in digit:
            plaintext += chr(num)
    return plaintext


if __name__ == '__main__':
    import doctest

    doctest.testmod(verbose=True)

    # When you are ready to check your work with python_ta, uncomment the following lines.
    # # (In PyCharm, select the lines below and press Ctrl/Cmd + / to toggle comments.)
    import python_ta

    python_ta.check_all(config={
        'max-line-length': 120,
        'disable': ['use-a-generator'],
        'extra-imports': ['math']
    })
