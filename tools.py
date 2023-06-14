import sys, io

def xor_bytes(first, second, third=None):
    """XOR bytes together"""
    if third == None:
        third = bytes(len(first))
    xor = b''
    for f, s, t in zip(first, second, third):
        xor += bytes([(f ^ s ^ t)])
    return xor

