from RLWEKEX import *
from utils import *
import numpy as np
from numpy.polynomial import Polynomial
import random
from checker import Checker
from cipher import *


class KEXProtocol(RLWE_KEX):
    def __init__(self, n, q):
        super().__init__(q, n, b=None)
        self.a = self.shake128()
        self.s_A = self.discrete_gaussian()
        self.s_B = self.discrete_gaussian()

    def gen_public_key_a(self, a=None):
        if a is None:
            return self.shake128()
        else:
            return a

    def gen_private_key_s_A(self, s=None):
        if s is None:
            self.s_A = self.discrete_gaussian()
        else:
            self.s_A = s

    def gen_private_key_s_B(self, s=None):
        if s is None:
            self.s_B = self.discrete_gaussian()
        else:
            self.s_B = s

    def key_exchange(self, a=None, s_A=None, e_A=None, g_A=None, s_B=None, e_B=None, g_B=None, g_B_used=False, flip=False):
        # Initialize third party at the beginning of session
        self.invoke_third_party()

        a = self.a if a is None else a
        s_A_ = self.s_A if s_A is None else s_A
        s_B_ = self.s_B if s_B is None else s_B
        # A generate session/error key e_A
        e_A_ = self.discrete_gaussian() if e_A is None else e_A
        print(f'Error key e_A: {e_A_}')
        # A calculate public key p_A
        self.p_A = self.calculate_public(a, s_A_, e_A_)
        print(f'Public key p_A: {self.p_A}')
        # B receive public key p_A and a
        # B generate session/error key e_B
        e_B_ = self.discrete_gaussian() if e_B is None else e_B
        print(f'Error key e_B: {e_B_}')
        # B calculate public key p_A
        self.p_B = self.calculate_public(a, s_B_, e_B_)
        print(f'Public key p_B: {self.p_B}')
        # A receive public key p_B
        # A generate session/ error key g_A and calculate k_A using p_B
        g_A_ = self.discrete_gaussian() if g_A is None else g_A
        k_A = self.calculate_private(self.p_B, s_A_, g_A_)
        print(f'k_A: {k_A}')
        # A calculate signal w_A
        w_A = self.generate_signal(k_A)
        print("Signal w_A:", w_A)
        # A calculate share key sk_A and send to third party
        self.sk_A = self.calc_mod2_reconciliation(k_A, w_A)
        self.third_party.receive_share_key(self.sk_A)

        w_A_flip = Polynomial(np.append(w_A.coef[:-1], 1))
        # B receive flipped signal w_A and generate session/error key g_B
        if g_B_used:
            g_B_ = self.discrete_gaussian() if g_B is None else g_B
        else:
            g_B_ = Polynomial(np.zeros(s_B.coef.shape[0]))
        print(g_B_.coef)
        print(self.p_A.coef)
        print(s_B_.coef)
        print("Check:", self.reduce_back_into_ring(self.p_A * s_B_))
        k_B = self.calculate_private(self.p_A, s_B_, g_B_)
        print(f'k_B: {k_B}')
        # B calculate share key sk_B and send to third party
        self.sk_B = self.calc_mod2_reconciliation(k_B, w_A_flip)
        self.third_party.receive_share_key(self.sk_B)

        print("\tskA:", self.sk_A)
        print("\tskB:", self.sk_B)

        return self.third_party.confirm_key_exchange()

    def invoke_third_party(self):
        self.third_party = Checker()

    def shake128(self): # TODOO
        a = np.zeros(self.n)
        for i in range(0, self.n):
            a[i] = random.randint(0, self.q)
        return Polynomial(a)
        # return np.random.randint(-int(self.q / 2) - 1, int(self.q / 2), size=self.n)

    def discrete_gaussian(self): # TODOO
        b_list = [5, 4, 3, 2, 1, 0, -1, -2, -3, -4, -5]

        a = np.zeros(self.n)
        for i in range(0, self.n):
            rand_indx = random.randint(0, 9)
            a[i] = b_list[rand_indx]
        return Polynomial(a)
        # return np.random.randint(-int(self.q / 2) - 1, int(self.q / 2), size=self.n)

    def encrypt_decrypt(self, plain_text, type="xor"):
        if type=="xor":
            key_list = [str(int(x)) for x in self.sk_A.tolist()]
            key = binaryToDecimal(int(''.join(key_list)))
            encrypted = xor_cipher(plain_text, key)
            decrypted = xor_cipher(encrypted, key)

    def attack(self, ):
        # Step 1: Determine the signs of the coefficients

