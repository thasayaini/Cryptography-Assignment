import random

class RSA:
    def __init__(self, key_size=512):
        self.key_size = key_size
        self.p = self.generate_large_prime()
        self.q = self.generate_large_prime()
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = self.choose_public_key()
        self.d = self.modular_inverse(self.e, self.phi)

    def generate_large_prime(self):
        """Generate a large prime number using the Miller-Rabin test."""
        while True:
            num = random.getrandbits(self.key_size // 2)
            if self.is_prime(num):
                return num

    def is_prime(self, n, k=5):
        """Miller-Rabin primality test to check if a number n is prime."""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False  # Even numbers >2 are not prime

        # Write n as d * 2^r + 1 with d odd (i.e., factor out powers of 2 from n - 1)
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        # Perform k iterations for accuracy
        for _ in range(k):
            a = random.randint(2, n - 2)  # Pick a random base a
            x = pow(a, d, n)  # Compute a^d % n

            if x == 1 or x == n - 1:
                continue  # Likely prime, move to the next round

            for _ in range(r - 1):  # Check if x becomes n-1 after squaring
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False  # Definitely composite

        return True  # Probably prime

    def choose_public_key(self):
        """Choose an encryption exponent e."""
        e = 65537  # Commonly used public exponent
        if self.gcd(e, self.phi) == 1:
            return e
        return 3  # Fallback option

    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def modular_inverse(self, e, phi):
        """Compute modular inverse of e modulo phi using the extended Euclidean algorithm."""
        def extended_gcd(a, b):
            if b == 0:
                return a, 1, 0
            g, x, y = extended_gcd(b, a % b)
            return g, y, x - (a // b) * y

        g, x, _ = extended_gcd(e, phi)
        return x % phi if g == 1 else None

    def encrypt(self, plaintext):
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext):
        return pow(ciphertext, self.d, self.n)