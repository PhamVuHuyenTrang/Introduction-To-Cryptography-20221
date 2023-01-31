import numpy as np

class Checker:
    def __init__(self):
        self.sk_list = list()

    def receive_share_key(self, sk):
        self.sk_list.append(sk)

    def confirm_key_exchange(self):
        assert len(self.sk_list) > 1, "Number of share keys receive is currently smaller than 2, please provide enough share keys"
        sk_0 = self.sk_list[0]
        for sk in self.sk_list[1:]:
            accept = self.compare_key(sk_0, sk)
            if not accept:
                return 0
        return 1

    def compare_key(self, k_a, k_b):
        c = k_a == k_b
        return c.all()
