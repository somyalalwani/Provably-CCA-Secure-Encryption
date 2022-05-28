import sys
from p3 import cpa_encrypt , cpa_decrypt
from p4 import cbc_mac
from p2 import dec_to_bin



def cca_encryption(key_enc,key_mac,message,random):
	encrypted_message = cpa_encrypt(message,key_enc,random)
	mac = cbc_mac(encrypted_message,key_mac)
	FINAL_TEXT = encrypted_message + "@@" + mac
	return FINAL_TEXT

def cca_decryption(key_enc,key_mac,cipher_text,random):
	rcvd_message ,rcvd_mac = cipher_text.split("@@")
	calc_mac = cbc_mac(rcvd_message , key_mac)
	if(rcvd_mac == calc_mac):
		decrypted_message = cpa_decrypt(rcvd_message, key_enc,random)
		return decrypted_message
	else:
		return "ALERT : MAC does not match, resend message"


key_enc="110001000111"
key_mac="11000100110101010"

message="1111100111110110000000011111111101010101010010101010101010101010000000001111111111"
random=dec_to_bin(3277)

print("------------------------------")
print("orignal_text:{},{}".format(message,len(message)))

print("---------------------------------------------------encrypt doing")
cipher_text=cca_encryption(key_enc,key_mac,message,random)
print("cipher_text:{},{}".format(cipher_text,len(cipher_text)))

print("---------------------------------------------------encrypt done")

recieved_text=cca_decryption(key_enc,key_mac,cipher_text,random)
print("recieved_text:{},{}".format(recieved_text,len(recieved_text)))

print("---------------------------------------------------decrypt done")


wrong_message=cipher_text+"000000011"
recieved_text=cca_decryption(key_enc,key_mac,wrong_message,random)
print("recieved_text:{},{}".format(recieved_text,len(recieved_text)))
