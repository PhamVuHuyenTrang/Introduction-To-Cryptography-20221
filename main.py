from protocol import KEXProtocol
from numpy.polynomial import Polynomial
from argparse import ArgumentParser

def main(args):
    proto = KEXProtocol(n=8, q=257, sigma=3, thres=30, accept_k=0.05, accept_s=0.05)
    # proto = KEXProtocol(n=101, q=257)
    a = Polynomial((-15, 69, 33, -57, -3, 87, -105, 7))
    s_B = Polynomial((2, 3, 0, 0, -5, 2, 3, 1))
    e_B = Polynomial((-1, -5, 0, 2, -3, 3, 0, 3))
    e_A = Polynomial((-1, 0, 0, 0, 0, 0, 0, 1))
    s_A = Polynomial((0, 0, 0, 0, 0, 0, 0, 0))
    # # Check key exchange protocol
    if args.kex:
        accept = proto.key_exchange(print_result=args.print_result)
        if args.ende:
            proto.encrypt_decrypt(plain_text="I am human")
        if args.attack:
            if args.use_default:
                proto.attack(a, s_B, e_B, custom=True)
            else:
                proto.attack()
        print("Accept share key:", accept)

if __name__ == "__main__":
    # Parse parameters
    parser = ArgumentParser(description="What to do")
    parser.add_argument('--kex', action="store_true", help="Make key exchange")
    parser.add_argument('--ende', action="store_true", help="Make encryption and decryption")
    parser.add_argument('--attack', action="store_true", help="Open attack on the protocol")
    parser.add_argument('--use_default', action="store_true", help='Present attack on default values');
    parser.add_argument('--print_result', action="store_true", help='Print the result');
    args = parser.parse_args()
    main(args)
