from p3 import K, msg_to_binary
from p2 import dec_to_bin, PRF
n = 64

def cbc_mac(msg, key=K):
    msg = msg_to_binary(msg)
    msg_len = len(msg)
    len_bin = dec_to_bin(msg_len).zfill(n)

    prf = PRF(len_bin, K)

    for i in range(0,msg_len,n):
        msg_block = msg[i:i+n]
        if len(msg_block)!=n:
            msg_block = msg_block.ljust(n,"0")
        xor = dec_to_bin(int(msg_block,2) ^ int(prf,2)).zfill(n)
        prf = PRF(xor, K)
    return prf

text = "string to be encrypted"
mac = cbc_mac(text, K)
print("text :",text)
print("mac",mac)