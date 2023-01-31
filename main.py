from protocol import KEXProtocol
from numpy.polynomial import Polynomial


def main():
    proto = KEXProtocol(n=8, q=257)
    a = Polynomial((-15, 69, 33, -57, -3, 87, -105, 7))
    s_B = Polynomial((2, 3, 0, 0, -5, 2, 3, 1))
    e_B = Polynomial((-1, -5, 0, 2, -3, 3, 0, 3))
    e_A = Polynomial((-1, 0, 0, 0, 0, 0, 0, 1))
    s_A = Polynomial((0, 0, 0, 0, 0, 0, 0, 0))
    # # Check key exchange protocol
    # accept = proto.key_exchange(a=a, s_A=s_A, s_B=s_B, e_B=e_B, e_A=e_A, g_B_used=False)
    # print("Accept share key:", accept)
    proto.attack(a, s_B, e_B, custom=True)

if __name__ == "__main__":
    main()