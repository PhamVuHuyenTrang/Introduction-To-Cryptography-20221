from protocol import KEXProtocol
from numpy.polynomial import Polynomial


def main():
    proto = KEXProtocol(n=64, q=257, sigma=3, thres=30, accept_k=0.05, accept_s=0.05)
    # proto = KEXProtocol(n=101, q=257)
    a = Polynomial((-15, 69, 33, -57, -3, 87, -105, 7))
    s_B = Polynomial((2, 3, 0, 0, -5, 2, 3, 1))
    e_B = Polynomial((-1, -5, 0, 2, -3, 3, 0, 3))
    e_A = Polynomial((-1, 0, 0, 0, 0, 0, 0, 1))
    s_A = Polynomial((0, 0, 0, 0, 0, 0, 0, 0))
    # # Check key exchange protocol
    # accept = proto.key_exchange()
    # print("Accept share key:", accept)
    #proto.attack(a, s_B, e_B, custom=True)
    proto.attack()
if __name__ == "__main__":
    main()
