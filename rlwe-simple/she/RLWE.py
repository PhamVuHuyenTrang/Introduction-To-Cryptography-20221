import numpy as np
from Rq import Rq
from utils import crange

class Party:
    def __init__(self, n, q, name, std=1):
        self.n = n
        self.q = q
        self.name = name
        self.std = std
        self.s = None #secret key
        self.a = None #first public key
        self.p = None #second public key
        self.w = None
        self.k = None
        self.sk = None #shared key
        self.party = None 
        
    def generate_keys(self):
        print("{} is generating keys:".format(self.name))
        self.s = discrete_gaussian(self.n, self.q, std=self.std)
        e = discrete_gaussian(self.n, self.q, std=self.std)
        self.a = discrete_uniform(self.n, self.q)
        self.p = (self.a * self.s) + (e * 2)
        print("\ts{}:".format(self.name), self.s)
        print("\ta{}:".format(self.name), self.a)
        print("\te{}:".format(self.name), e)
        print("\tp{}:".format(self.name), self.p)
                       
    
class RLWE:
    def __init__(self, n, q, std=1):
        assert np.log2(n) == int(np.log2(n))
        self.n = n
        self.q = q
        self.std = std
        self.Alice = Party(self.n, self.q, "A", self.std)
        self.Bob = Party(self.n, self.q, "B", self.std)
        self.Alice.party = self.Bob
        self.Bob.party = self.Alice
        
    def two_pass(self):
        print("TWO PASS KEY EXCHANGE:")
        self.Alice.generate_keys()
        self.Bob.generate_keys()
        
        print(self.Alice.name)
        print("\tSend p{} to {}".format(self.Alice.name, self.Alice.party.name))
        
        print(self.Bob.name)
        gB = discrete_gaussian(self.n, self.q, std=self.std)
        self.Bob.k = (self.Bob.party.p * self.Bob.s) + (gB * 2)
        self.Bob.w = self.Bob.k.sign()
        self.Bob.sk = self.Bob.k.mod2(self.Bob.w)
        print("\tg{}:".format(self.Bob.name), gB)
        print("\tk{}:".format(self.Bob.name), self.Bob.k)
        print("\tw{}:".format(self.Bob.name), self.Bob.w)
        print("\tsk{}:".format(self.Bob.name), self.Bob.sk)
        print("Send p{}, w{} to {}".format(self.Bob.name, self.Bob.name, self.Bob.party.name))
        
        print(self.Alice.name)
        gA = discrete_gaussian(self.n, self.q, std=self.std)
        self.Alice.k = (self.Alice.party.p * self.Alice.s) + (gA * 2)
        self.Alice.sk = self.Alice.k.mod2(self.Alice.party.w)
        print("\tg{}:".format(self.Alice.name), gA)
        print("\tk{}:".format(self.Alice.name), self.Alice.k)
        print("\tsk{}:".format(self.Alice.name), self.Alice.sk)
        
        print()
        print(self.Alice.sk + self.Bob.sk*(-1))
        
    def one_pass(self):
        print("ONE PASS KEY EXCHANGE:")
        self.Alice.generate_keys()
        self.Bob.generate_keys()
        
        print(self.Alice.name)
        gA = discrete_gaussian(self.n, self.q, std=self.std)
        self.Alice.k = (self.Alice.party.p * self.Alice.s) + (gA * 2)
        self.Alice.w = self.Alice.k.sign()
        self.Alice.sk = self.Alice.k.mod2(self.Alice.w)
        print("\tg{}:".format(self.Alice.name), gA)
        print("\tk{}:".format(self.Alice.name), self.Alice.k)
        print("\tw{}:".format(self.Alice.name), self.Alice.w)
        print("\tsk{}:".format(self.Alice.name), self.Alice.sk)
        print("\tSend p{}, w{} to {}".format(self.Alice.name, self.Alice.name, self.Alice.party.name))
        
        print(self.Bob.name)
        gB = discrete_gaussian(self.n, self.q, std=self.std)
        self.Bob.k = (self.Bob.party.p * self.Bob.s) + (gB * 2)
        self.Bob.sk = self.Bob.k.mod2(self.Bob.party.w)
        print("\tg{}:".format(self.Bob.name), gB)
        print("\tk{}:".format(self.Bob.name), self.Bob.k)
        print("\tsk{}:".format(self.Bob.name), self.Bob.sk)
        
        print()
        print(self.Alice.sk + self.Bob.sk*(-1))
    """def encrypt(self, m, a):
        '''
        # Args:
            m: plaintext (mod t)
            a: public key (a0, a1)
        '''
        a0, a1 = a
        e = [discrete_gaussian(self.n, self.p, std=self.std)
             for _ in range(3)]

        m = Rq(m.poly.coeffs, self.p)

        return (m + a0 * e[0] + self.t * e[2], a1 * e[0] + self.t * e[1])

    def decrypt(self, c, s):
        '''
        # Args:
            c: ciphertext (c0, c1, ..., ck)
            s: secret key
        '''
        c = [ci * s**i for i, ci in enumerate(c)]

        m = c[0]
        for i in range(1, len(c)):
            m += c[i]

        m = Rq(m.poly.coeffs, self.t)

        return m

    def add(self, c0, c1):
        '''
        # Args:
            c0: ciphertext (c0, c1, ..., ck)
            c1: ciphertext (c'0, c'1, ..., c'k')
        '''
        c = ()

        k0 = len(c0)  # not necessary to compute (len - 1)
        k1 = len(c1)

        if k0 > k1:
            (c0, c1) = (c1, c0)  # c0 is always shorter

        for _ in range(abs(k0 - k1)):
            c0 += (Rq([0], self.p),)  # add 0 to shorter ciphertext

        for i in range(len(c0)):
            c += (c0[i] + c1[i],)

        return c

    def mul(self, c0, c1):
        '''
        # Args:
            c0: ciphertext (c0, c1, ..., ck)
            c1: ciphertext (c'0, c'1, ..., c'k')
        '''
        c = ()

        k0 = len(c0) - 1
        k1 = len(c1) - 1

        for _ in range(k1):
            c0 += (Rq([0], self.p),)

        for _ in range(k0):
            c1 += (Rq([0], self.p),)

        for i in range(k0 + k1 + 1):
            _c = Rq([0], self.p)
            for j in range(i+1):
                _c += c0[j] * c1[i-j]
            c += (_c,)

        return c
"""

def discrete_gaussian(n, q, mean=0., std=1.):
    coeffs = np.round(std * np.random.randn(n))
    return Rq(coeffs, q)


def discrete_uniform(n, q, min=0., max=None):
    if max is None:
        max = q
    coeffs = np.random.randint(min, max, size=n)
    return Rq(coeffs, q)

if __name__ == "__main__":
    x = RLWE(16, 65537)
    x.one_pass()
