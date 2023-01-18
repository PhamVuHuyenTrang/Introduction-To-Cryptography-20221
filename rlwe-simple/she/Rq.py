import numpy as np
from utils import crange


class Rq(object):
    '''
    Ring-Polynomial: Fq[x] / (x^n + 1)
        range of the reminder is set to (−q/2, q/2]
    '''
    def __init__(self, coeffs, q):
        '''
        # Args
            coeffs: coefficients array of a polynomial
            q: modulus
        '''
        n = len(coeffs)  # degree of a polynomial

        f = np.zeros((n+1), dtype=np.int64)  # x^n + 1
        f[0] = f[-1] = 1
        f = np.poly1d(f)
        self.f = f

        self.q = q
        coeffs = np.array(coeffs, dtype=np.int64) % q
        coeffs = crange(coeffs, q)
        self.poly = np.poly1d(np.array(coeffs, dtype=np.int64))

    def __repr__(self):
        template = 'Rq: {} (mod {}), reminder range: ({}, {}]'
        return template.format(self.poly.__repr__(), self.q,
                               -self.q//2, self.q//2)

    def __len__(self):
        return len(self.poly)  # degree of a polynomial

    def __add__(self, other):
        coeffs = np.polyadd(self.poly, other.poly).coeffs
        return Rq(coeffs, self.q)

    def __mul__(self, other):
        if type(other) == int:
            coeffs = (self.poly.coeffs * other)
            return Rq(coeffs, self.q)
        else:
            q, r = np.polydiv(np.polymul(self.poly, other.poly), self.f)
            coeffs = r.coeffs
            return Rq(coeffs, self.q)

    def __pow__(self, integer):
        if integer == 0:
            return Rq([1], self.q)
        ret = self
        for i in range(integer-1):
            ret *= ret
        return ret
    
    def mod2(self, other):
        integer = (self.q - 1) // 2
        rs = self + other * integer
        coeffs = rs.poly.coeffs % 2
        return Rq(coeffs, self.q)
    
    def sign(self):
        coeffs = self.poly.coeffs.tolist()
        rs = []
        for i in coeffs:
            if - (self.q // 4) <= i <= round(self.q / 4):
                rs.append(0)
            else:
                rs.append(1)      
        return Rq(rs, self.q)
        
    
if __name__ == "__main__":
    q = 101
    A = Rq(np.array([83,23,51,77]), q)
    B = Rq(np.array([1,0,0,100]), q)
    #f = Rq(np.array([1,0,1]), q)
    e = Rq(np.array([1,1,100,0]), q)
    print(A*B)
    print(A.f.coeffs)
    print(e*2)
    print(A*B + e)
        
