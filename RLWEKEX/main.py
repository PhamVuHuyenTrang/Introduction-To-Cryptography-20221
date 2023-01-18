from RLWEKEX import *

print("ONE PASS KEY EXCHANGE:")

print("Alice: Key generation")
alice = RLWE_KEX(q=3079, n=32, b=5)
print("\tsA:", alice.s)
print("\teA:", alice.e)
alice_public, alice_a = alice.calculate_public() # pA = aA.sA + 2eA
print("\taA:", alice_a)
print("\tpA:", alice_public)
print()

print("Bob: Key generation")
bob = RLWE_KEX(q=3079, n=32, b=5, a=alice_a)
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
