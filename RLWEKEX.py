from numpy.polynomial import Polynomial
import numpy as np


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


