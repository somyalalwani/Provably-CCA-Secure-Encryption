from p2 import dec_to_bin,PRF
def msg_to_binary(msg):
    bstring = ''.join(format(ord(i), '08b') for i in msg)
    return str(bstring)

def binary_to_msg(num):
    deci = int(num,2)
    n = 7+deci.bit_length()
    x = deci.to_bytes(n//8,'big')
    X = x.decode("utf-8" ,"surrogatepass")
    return X or '\0'

def cpa_encrypt(msg,key,cnt):
    msg = msg_to_binary(msg)
    result = ""
    l = len(msg)
    n = 64
    for i in range(0,l,n):
        prf_val = PRF(cnt.zfill(n),key)
        xx1 = prf_val[0:len(msg[i:i+n])]
        xx2 = msg[i:i+n]
        xor = dec_to_bin(int(xx2,2) ^ int(xx1,2)).zfill(len(xx2))
        result= result+xor
        cnt = bin(int(cnt.zfill(n),2) + 1).replace('0b','').zfill(n)
    return result

def cpa_decrypt(enc, key, cnt):
    result = ""
    n =64
    l = len(enc)
    for i in range(0,l,n):
        prf_val = PRF(cnt.zfill(n),key)
        xx= enc[i:i+n]
        xx_len = len(xx)
        xor = dec_to_bin(int(xx,2) ^ int(prf_val[0:xx_len],2)).zfill(xx_len)
        result= result+xor
        cnt = bin(int(cnt.zfill(n),2)+1).replace('0b','').zfill(n)
    return binary_to_msg(result)

K ="10111"
def main():
    cnt = dec_to_bin(921504606846976)
    string = "testing the cpa encryption scheme"
    print("Text :" , string)
    cpa = cpa_encrypt(string, K, cnt)
    print("Before encryption :")
    print(string)
    print("****************")
    print("After encryption :")
    print(cpa)
    print("****************")
    print("After decryption :")
    apc = cpa_decrypt(cpa, K, cnt)
    print(apc)

if __name__ == '__main__':
    main()
