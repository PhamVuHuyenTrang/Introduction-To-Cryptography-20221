from numpy.polynomial import Polynomial
import numpy as np
import random
import random #Default random number generator,
#random.SecureRandom() provides high-quality randomness from /dev/urandom or similar
from fractions import Fraction #we will work with rational numbers
#sample uniformly from range(m)
#all randomness comes from calling this
def sample_uniform(m,rng):
    assert isinstance(m,int) #python 3
    #assert isinstance(m,(int,long)) #python 2
    assert m>0
    return rng.randrange(m)

#sample from a Bernoulli(p) distribution
#assumes p is a rational number in [0,1]
def sample_bernoulli(p,rng):
    assert isinstance(p,Fraction)
    assert 0 <= p <= 1
    m=sample_uniform(p.denominator,rng)
    if m < p.numerator:
        return 1
    else:
        return 0

#sample from a Bernoulli(exp(-x)) distribution
#assumes x is a rational number in [0,1]
def sample_bernoulli_exp1(x,rng):
    assert isinstance(x,Fraction)
    assert 0 <= x <= 1
    k=1
    while True:
        if sample_bernoulli(x/k,rng)==1:
            k=k+1
        else:
            break
    return k%2

#sample from a Bernoulli(exp(-x)) distribution
#assumes x is a rational number >=0
def sample_bernoulli_exp(x,rng):
    assert isinstance(x,Fraction)
    assert x >= 0
    #Sample floor(x) independent Bernoulli(exp(-1))
    #If all are 1, return Bernoulli(exp(-(x-floor(x))))
    while x>1:
        if sample_bernoulli_exp1(Fraction(1,1),rng)==1:
            x=x-1
        else:
            return 0
    return sample_bernoulli_exp1(x,rng)

#sample from a geometric(1-exp(-x)) distribution
#assumes x is a rational number >= 0
def sample_geometric_exp_slow(x,rng):
    assert isinstance(x,Fraction)
    assert x >= 0
    k=0
    while True:
        if sample_bernoulli_exp(x,rng)==1:
            k=k+1
        else:
            return k
            
#sample from a geometric(1-exp(-x)) distribution
#assumes x >= 0 rational
def sample_geometric_exp_fast(x,rng):
    assert isinstance(x,Fraction)
    if x==0: return 0 #degenerate case
    assert x>0

    t=x.denominator
    while True:
        u=sample_uniform(t,rng)
        b=sample_bernoulli_exp(Fraction(u,t),rng)
        if b==1:
            break
    v=sample_geometric_exp_slow(Fraction(1,1),rng)
    value = v*t+u
    return value//x.numerator
    
#sample from a discrete Laplace(scale) distribution
#Returns integer x with Pr[x] = exp(-abs(x)/scale)*(exp(1/scale)-1)/(exp(1/scale)+1)
#casts scale to Fraction
#assumes scale>=0
def sample_dlaplace(scale,rng=None):
    if rng is None:
        rng = random.SystemRandom()
    scale = Fraction(scale)
    assert scale >= 0
    while True:
        sign=sample_bernoulli(Fraction(1,2),rng)
        magnitude=sample_geometric_exp_fast(1/scale,rng)
        if sign==1 and magnitude==0: continue
        return magnitude*(1-2*sign)
        
#compute floor(sqrt(x)) exactly
#only requires comparisons between x and integer
def floorsqrt(x):
    assert x >= 0
    #a,b integers
    a=0 #maintain a^2<=x
    b=1 #maintain b^2>x
    while b*b <= x:
        b=2*b #double to get upper bound
    #now do binary search
    while a+1<b:
        c=(a+b)//2 #c=floor((a+b)/2)
        if c*c <= x:
            a=c
        else:
            b=c
    #check nothing funky happened
    #assert isinstance(a,int) #python 3
    #assert isinstance(a,(int,long)) #python 2
    return a
    
#sample from a discrete Gaussian distribution N_Z(0,sigma2)
#Returns integer x with Pr[x] = exp(-x^2/(2*sigma2))/normalizing_constant(sigma2)
#mean 0 variance ~= sigma2 for large sigma2
#casts sigma2 to Fraction
#assumes sigma2>=0
def sample_dgauss(sigma2,rng=None):
    if rng is None:
        rng = random.SystemRandom()
    sigma2=Fraction(sigma2)
    if sigma2==0: return 0 #degenerate case
    assert sigma2 > 0
    t = floorsqrt(sigma2)+1
    while True:
        candidate = sample_dlaplace(t,rng=rng)
        bias=((abs(candidate)-sigma2/t)**2)/(2*sigma2)
        if sample_bernoulli_exp(bias,rng)==1:
            return candidate

class RLWE_KEX:
    def __init__(self, q, n, sigma, a=None):
        self.sigma = sigma
        self.n = n
        self.q = q

    def reduce_back_into_ring(self, poly):
        # This method reduces polynomials with terms of a higher degree back down so they are of a degree
        # included in the polynomial ring. This is step one of reduction back into the ring. The other is reducing
        # the coefficients. See reduce_coefficients for this.

        # For more information on polynomial rings try:
        # https://en.wikipedia.org/wiki/Polynomial_ring

        # Params: Input: poly - polynomial with terms of a higher degree than what is included in the
        #                polynomial ring
        #         Output: reduced_poly - polynomial with terms reduced into the ring

        reduced_poly = np.zeros(self.n)
        if poly.coef.shape[0] > self.n:
            a = poly.coef
            # Initialize the first n values
            for i in range(0, self.n):
                reduced_poly[i] = a[i]
            # Now iterate over the values of a higher degree and put them back where they belong
            for i in range(0, self.n-1):
                if i + self.n < a.shape[0]:
                    reduced_poly[i] = reduced_poly[i] - a[i+self.n]
            return Polynomial(reduced_poly)
        return poly

    def reduce_coefficients(self, poly, mod_val):
        # This method reduces polynomial coefficients back into the ring. Everywhere else, this is referred to
        # to as a mod q reduction. It is actually a subset of this with it becoming-(q-1/2) through to (q-1)/2.

        # For more information on polynomial rings try:
        # https://en.wikipedia.org/wiki/Polynomial_ring

        # Params: Input: poly - polynomial with terms of a higher degree than what is included in the
        #                polynomial ring
        #                mod_val - value to be used for the reduction
        #         Output: ret_val - polynomial with terms reduced into the ring

        # Reduce coefficients mod q
        ret_val = Polynomial(poly.coef % mod_val)

        # Coerce back Zq. Note this is a subset of mod q. It becomes -(q-1/2) through to (q-1)/2.
        # This must be done to have the signal function work correctly.
        middle = (self.q - 1) / 2
        for i in range(0, ret_val.coef.shape[0]):
            if ret_val.coef[i] > middle:
                ret_val.coef[i] = ret_val.coef[i] - self.q
        return ret_val

    def add(self, poly1, poly2, mod_val):
        # This method performs addition within the polynomial ring.

        # Params: Input: poly1 - polynomial to be added
        #                poly2 - polynomial to be added
        #                mod_val - modulo value for reduction of the coefficients
        #         Output: add_result- resulting polynomial with terms reduced into the ring

        # Perform straight up addition of two polynomials not considering the ring
        add_result = Polynomial(poly1.coef + poly2.coef)

        # Reduce the coefficients mod q
        return self.reduce_coefficients(add_result, mod_val)

    def multiply(self, poly1, poly2, mod_val):
        # This method performs multiplication within the polynomial ring.

        # Params: Input: poly1 - polynomial to be multiplied
        #                poly2 - polynomial to be multiplied
        #                mod_val - modulo value for reduction of the coefficients
        #         Output: mul_result - resulting polynomial with terms reduced into the ring

        # Perform straight up multiplication of the two polynomials not considering the ring
        mul_result = poly1 * poly2
        # Reduce terms of a higher degree than what is included in the ring
        mul_result = self.reduce_back_into_ring(mul_result)
        # Reduce the coefficients mod q
        mul_result = self.reduce_coefficients(mul_result, mod_val)
        return mul_result

    def get_random_poly(self):
        # This method generates a random polynomial of highest degree n-1 with small coefficients between
        # b and -b. Currently hardcoded to b=5.

        # NOTE: We use discrete Gauss sample these coefficients.

        # Params: Output : a - generated polynomial
        a = np.zeros(self.n)
        for i in range(self.n):
            sigma2 = self.sigma ** 2
            coeff=sample_dgauss(sigma2)
            a[i] = coeff
        return Polynomial(a)

    def generate_signal(self, k):
        # This method generates the 'signal' to be used in the reconciliation function.

        # Params: Input: this_poly - polynomial to be used as input to the function
        #         Output: w_out - signal to be used for reconciliation

        w = k.coef
        w_out = np.ones(w.shape[0])
        up_bound = (self.q - 1) / 4
        low_bound = -1 * up_bound
        for i in range(0, w_out.shape[0]):
            if w[i] >= low_bound and w[i] <= up_bound:
                w_out[i] = 0
        w = Polynomial(w_out)
        return w

    def calc_mod2_reconciliation(self, k, w):
        # This method performs the reconciliation of the approximately equal secrets using the
        # 'signal'

        # Params: Input: w - signal for reconciliation

        q_scalar = ((self.q - 1) / 2)
        multiply_w = Polynomial(w.coef * q_scalar)
        ret_skr = self.add(k, multiply_w, self.q)
        return ret_skr.coef % 2

    def calculate_public(self, a, s, e=None):
        # This method calculates the public value of a party in the key exchange. It also returns the shared
        # value 'a' to allow it to be provided to the other party in the exchange.
        # Calculation for the public_value = sa + 2e
        # Params: Output: p - public value polynomial
        #                 a - public value shared between parties in the exchange
        if e is not None:
            return self.add(self.multiply(a, s, self.q), Polynomial((2 * e.coef)), self.q)
        else:
            return self.multiply(a, s, self.q)

    def calculate_private(self, p_in, s, g=None):
        # This method calculates the private value of a party in the key exchange.
        # Calculation for the private value = sp_in + 2e1
        # Params: Input: p_in - public value polynomial of other participant in the exchange
        if g is not None:
            return self.add(self.multiply(p_in, s, self.q), Polynomial((2 * g.coef)), self.q)
        else:
            return self.multiply(p_in, s, self.q)


