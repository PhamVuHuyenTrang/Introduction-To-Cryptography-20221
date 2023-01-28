from RLWEKEX import *
import re
def binaryToDecimal(binary):
     
    decimal, i = 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal

def xor_cipher(st, key):
    originaltext_characters = list(st)
    
    encrypted_characters = []
    for character in originaltext_characters:
        ascii_original_value = ord(character)
        ascii_encrypted_value = key^ascii_original_value
        encrypted_character = chr(ascii_encrypted_value)
        encrypted_characters.append(encrypted_character)
    return ''.join(encrypted_characters)


print("ONE PASS KEY EXCHANGE:")
q = int(input("Enter the value of q: "))
n = int(input("Enter the value of n: "))
b = int(input("Enter the value of b: "))
print("Alice: Key generation")
alice = RLWE_KEX(q, n, b)
print("\tsA:", alice.s)
print("\teA:", alice.e)
alice_public, alice_a = alice.calculate_public() # pA = aA.sA + 2eA
print("\taA:", alice_a)
print("\tpA:", alice_public)
print()

print("Bob: Key generation")
bob = RLWE_KEX(q, n, b, a=alice_a)
print("\tsB:", bob.s)
print("\teB:", bob.e)
bob_public, bob_a = bob.calculate_public() # pB = aB.sB + 2eB
print("\taB:", bob_a)
print("\tpB:", bob_public)
print()

print("Alice: Shared-key computation")
alice.calculate_private(bob_public) # kA = pB.sA + 2gA
signal_info = alice.generate_signal() #wA = Sig(kA)
alice.reconcile_key() #skA = Mod2(kA, wA)
print("\tkA:", alice.k)
print("\twA:", alice.w)
print("\tskA:", alice.get_key_stream())
print("\tAlice sends pA, wA to Bob.")
print()

print("Bob: Shared-key computation")
bob.calculate_private(alice_public) # kB = pA.sB + 2gB
bob.reconcile_key(signal_info) #skA = Mod2(kB, wA)
print("\tkB:", bob.k)
print("\tskB:", bob.get_key_stream())
print()
print("Finish!")
print("\tskA:", alice.get_key_stream())
print("\tskB:", bob.get_key_stream())
key_list = [int(x) for x in alice.get_key_stream().tolist()]

#Encryption and decryption using XOR cypher
print("ENCRYPTION AND DECRYPTION USING XOR CIPHER")
key_list = [str(int(x)) for x in alice.get_key_stream().tolist()]
key = binaryToDecimal(int(''.join(key_list)))
string = input("Enter String: ")
encrypted = xor_cipher(string, key)
decrypted = xor_cipher(encrypted, key)
print("Original text: " + string)
print("Encrypted text: " + encrypted)
print("Decrypted text: " + decrypted)
