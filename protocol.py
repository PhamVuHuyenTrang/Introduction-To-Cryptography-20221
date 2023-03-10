from RLWEKEX import *
from utils import *
import numpy as np
from numpy.polynomial import Polynomial
from checker import Checker
from cipher import *
from sample_gauss import *
from scipy.stats import shapiro


class KEXProtocol(RLWE_KEX):
    def __init__(self, n, q, sigma=1, thres=100, accept_k=0.05, accept_s=0.05):
        super().__init__(q, n, sigma=sigma)
        self.a = self.shake128()
        self.s_A = self.discrete_gaussian()
        self.s_B = self.discrete_gaussian()
        self.DISTRIBUTION_THRESHOLD = thres
        self.accept_thres_k = accept_k
        self.accept_thres_s = accept_s

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

    def key_exchange(self, a=None, s_A=None, e_A=None, g_A=None, s_B=None, e_B=None, g_B=None,
                     g_A_used=False, g_B_used=False, print_result=False):
        # Initialize third party at the beginning of session
        self.invoke_third_party()

        a = self.a if a is None else a
        s_A_ = self.s_A if s_A is None else s_A
        s_B_ = self.s_B if s_B is None else s_B
        # A generate session/error key e_A
        e_A_ = self.discrete_gaussian() if e_A is None else e_A
        # A calculate public key p_A
        self.p_A = self.calculate_public(a, s_A_, e_A_)
        # B receive public key p_A and a
        # B generate session/error key e_B
        e_B_ = self.discrete_gaussian() if e_B is None else e_B

        # B calculate public key p_A
        self.p_B = self.calculate_public(a, s_B_, e_B_)

        # A receive public key p_B
        # A generate session/ error key g_A and calculate k_A using p_B
        if g_A_used:
            g_A_ = self.discrete_gaussian() if g_A is None else g_A
        else:
            g_A_ = Polynomial(np.zeros(self.n))

        k_A = self.calculate_private(self.p_B, s_A_, g_A_)

        # A calculate signal w_A
        w_A = self.generate_signal(k_A)

        # A calculate share key sk_A and send to third party
        self.sk_A = self.calc_mod2_reconciliation(k_A, w_A)
        self.third_party.receive_share_key(self.sk_A)

        w_A_flip = Polynomial(np.append(w_A.coef[:-1], 1))
        # B receive flipped signal w_A and generate session/error key g_B
        if g_B_used:
            g_B_ = self.discrete_gaussian() if g_B is None else g_B
        else:
            g_B_ = Polynomial(np.zeros(self.n))

        k_B = self.calculate_private(self.p_A, s_B_, g_B_)
        # B calculate share key sk_B and send to third party
        self.sk_B = self.calc_mod2_reconciliation(k_B, w_A_flip)
        self.third_party.receive_share_key(self.sk_B)

        if print_result:
            print(f"Secret key s_A: {s_A_}")
            print(f"Public key a: {a}")
            print(f"Public key p_A: {self.p_A}")
            print(f"Secret key s_B: {s_B_}")
            print(f"Public key p_B: {self.p_B}")
            print(f"Signal w_A: {w_A}")
            print(f"Shared key sk_A: {self.sk_A}")
            print(f"Shared key sk_B: {self.sk_B}")
        return self.third_party.confirm_key_exchange()

    def invoke_third_party(self):
        self.third_party = Checker()

    def shake128(self):  # TODOO
        return Polynomial(np.random.randint(-int(self.q / 2) - 1, int(self.q / 2), size=self.n))

    def discrete_gaussian(self):
        a = np.zeros(self.n)
        for i in range(self.n):
            sigma2 = self.sigma ** 2
            coeff=sample_dgauss(sigma2)
            a[i] = coeff
        return Polynomial(a)
        # return np.random.randint(-int(self.q / 2) - 1, int(self.q / 2), size=self.n)

    def encrypt_decrypt(self, plain_text, type="xor"):
        if type == "xor":
            key_list = [str(int(x)) for x in self.sk_A.tolist()]
            key = binaryToDecimal(int(''.join(key_list)))
            encrypted = xor_cipher(plain_text, key)
            decrypted = xor_cipher(encrypted, key)
            print("Original text: " + plain_text)
            print("Encrypted text: " + encrypted)
            print("Decrypted text: " + decrypted)

    def attack(self, a_=None, s_B_=None, e_B_=None, custom=True):
        # From the last exchange, we got p_B be calculated
        a = self.a if a_ is None else a_
        s_B = self.s_B if s_B_ is None else s_B_
        e_B = self.discrete_gaussian() if e_B_ is None else e_B_

        s_A = Polynomial(np.zeros(self.n))
        s_B_pred = Polynomial(np.zeros(self.n))

        p_B = 0
        if custom:
            p_B = self.calculate_public(a, s_B, e_B)
        else:
            try:
                p_B = self.p_B
            except AttributeError:
                print("There is no key exchange session has been created")
        print(f'Public key p_B: {p_B}')

        # Step 1: Determine the signs of the coefficients
        sign_output = np.zeros(self.n)
        ## query B with p_A correponding to k = 0
        for i in range(self.n - 1, -1, -1):
            e_A = np.zeros(self.n)
            e_A[i] = 1
            e_A_ = Polynomial(e_A)
            confirm = self.key_exchange(a=a, s_A=s_A, e_A=e_A_, g_A=None,
                                        s_B=s_B, e_B=e_B, g_B=None,
                                        g_A_used=False, g_B_used=False)

            sign_output[self.n - 1 - i] = confirm
        print(f"Sign output: {sign_output}")

        ## confirm the sign of coefficients
        ### 0: positive | 1: negative | -1: zero
        for i in range(self.n):
            if sign_output[i] == 1:
                e_A = np.zeros(self.n)
                e_A[self.n - 1 - i] = -1
                e_A_ = Polynomial(e_A)
                confirm_ = self.key_exchange(a=a, s_A=s_A, e_A=e_A_, g_A=None,
                                             s_B=s_B, e_B=e_B, g_B=None,
                                             g_A_used=False, g_B_used=False)
                if confirm_ == 1:
                    s_B_pred.coef[i] = 0
                    sign_output[i] = -1
                    print(f"The {i}-index of s_B is confirmed to be zero.")
                else:
                    print(f"The {i}-index of s_B is confirmed to be negative.")
                    sign_output[i] = 1

        # Step 2: Determine j such that s_B[j] = +-1
        ## Assuming j=f, we calculate remained positions of s_B
        stop = False
        j_list = np.array(range(len(sign_output)))[sign_output != -1]
        id = 0
        best_s = -1
        best_k = -1
        count = 0
        while not stop:
            j = j_list[id]
            s_B_iter = Polynomial(s_B_pred.coef)
            s_B_iter.coef[j] = 1
            for i in range(self.n):
                if i != j and sign_output[i] == 0:
                    e_A = np.zeros(self.n)
                    e_A[self.n - 1 - i] = 1
                    stop_ = False
                    k = 0
                    while not stop_:
                        e_A[self.n - 1 - j] = -1 * k
                        e_A_ = Polynomial(e_A)
                        if self.key_exchange(a=a, s_A=s_A, e_A=e_A_, g_A=None,
                                             s_B=s_B, e_B=e_B, g_B=None,
                                             g_A_used=False, g_B_used=False) == 1:
                            s_B_iter.coef[i] = k
                            stop_ = True
                        k += 1
                elif i != j and sign_output[i] == 1:
                    e_A = np.zeros(self.n)
                    e_A[self.n - 1 - i] = 1
                    stop_ = False
                    k = 0
                    while not stop_:
                        e_A[self.n - 1 - j] = k
                        e_A_ = Polynomial(e_A)
                        if self.key_exchange(a=a, s_A=s_A, e_A=e_A_, g_A=None,
                                             s_B=s_B, e_B=e_B, g_B=None,
                                             g_A_used=False, g_B_used=False) == 0:
                            s_B_iter.coef[i] = -1 * (k - 1)
                            stop_ = True
                        k += 1
            if self.n <= self.DISTRIBUTION_THRESHOLD:
                print(f'Secret key s_B found if j={j}: {s_B_iter}')

            ### After calculating s_B based on this assumption, we use Shapiro-Wilk Test to determine
            ### whether (p_B - a*s_B) follow normal distribution
            if self.n > self.DISTRIBUTION_THRESHOLD:
                k_p_value = self.verify_distribution(self.add(p_B, -self.multiply(a, s_B_iter, self.q), self.q).coef)
                s_p_value = self.verify_distribution(s_B_iter.coef)
                print(f'p value of k:\t{k_p_value:11f}')
                print(f'p value of s_B:\t{s_p_value:11f}')
                if k_p_value > best_k and s_p_value > best_s:
                    best_k = k_p_value
                    best_s = s_p_value
                    s_B_pred_wise = s_B_iter
                    count = 1
                elif abs(k_p_value - best_k) < 1e-6 and abs(s_p_value - best_s) < 1e-6:
                    count += 1

                if k_p_value > self.accept_thres_k:
                    if s_p_value > self.accept_thres_s:
                        stop = True
                        s_B_pred = s_B_iter
                elif id == j_list.shape[0]-1:
                    stop = True
                    j = -1
            if id == j_list.shape[0]-1:
                stop = True
                s_B_pred = s_B_iter
            id += 1
        if j == -1:
            if count > 1:
                print(f"Predicted s_B with low-sample distribution: {s_B_pred_wise}") if (self.n > self.DISTRIBUTION_THRESHOLD) else print()
                print(f"Actual s_B: {s_B}")
                print(f"p_value of s_B: {self.verify_distribution(s_B.coef)}")
            else:
                print(f"Actual s_B: {s_B}")
                print("Cannot find j such that s_B[j] = +-1")
        else:
            print(f"Predicted s_B: {s_B_pred}") if self.n > self.DISTRIBUTION_THRESHOLD else print()
            print(f"Actual s_B: {s_B}")
            print(f"p_value of s_B: {self.verify_distribution(s_B.coef)}")

    def verify_distribution(self, x):
        return shapiro(x)[1]
