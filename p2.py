def bin_to_dec(x):
  return int( str(x),2 )

def dec_to_bin(x):
  return bin(x)[2:]

g = 47
p = 27527

def func_h(a,b):
    mod_exp_final = dec_to_bin(pow(g, bin_to_dec(a), p)).zfill(16)
    hcb = 0 #hcb
    l = len(a)
    for i in range(l):
        anding = int(a[i]) & int(b[i])
        hcb =hcb^anding
    return mod_exp_final + b,str(hcb)


def PRG(initial_seed,output_len):
    bstring = initial_seed.zfill(32)
    ans=""
    for i in range(output_len):
        x = len(bstring)//2
        a,b = bstring[:x] , bstring[x:]
        bstring,ans_bit=func_h(a,b)
        ans=ans + ans_bit
    return ans


def PRF(seed,K):
    result=K
    for i in seed:
        result = str(PRG(result, 2*len(seed)))
        x = len(seed)
        if i!=0:
            result = result[x:]
        else:
            result = result[:x]
    return result


def main():
    seed = str(input("Enter seed : ")) # 10101011010011
    k = str(input("Enter k : ")) # 10111
    print(PRF(seed, k))

if __name__ == '__main__':
    main()

#input : 10101011010011, 10111

#print(PRF("10101011010011", "10111"))
#k ="10111"
