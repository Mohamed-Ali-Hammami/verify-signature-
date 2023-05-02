p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

G = (Gx, Gy)


def mod_inv(a, p):
    """
    Returns the inverse of a modulo p.
    """
    for x in range(1, p):
        if (a*x) % p == 1:
            return x
    return None

def point_addition(p, q, a, p_mod):
    """
    Computes the addition of two points on an elliptic curve.
    """
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and p[1] == (-q[1] % p_mod):
        return None
    if p[0] == q[0]:
        m = ((3 * p[0]**2 + a) * mod_inv(2 * p[1], p_mod)) % p_mod
    else:
        m = ((q[1] - p[1]) * mod_inv(q[0] - p[0], p_mod)) % p_mod
    x_r = (m**2 - p[0] - q[0]) % p_mod
    y_r = (m * (p[0] - x_r) - p[1]) % p_mod
    return (x_r, y_r)

def point_multiplication(n, p, a, p_mod):
    """
    Computes the multiplication of a point on an elliptic curve by a scalar.
    """
    result = None
    addend = p
    while n > 0:
        if n % 2 == 1:
            result = point_addition(result, addend, a, p_mod)
        addend = point_addition(addend, addend, a, p_mod)
        n //= 2
    return result

def ecdsa_sign(message, private_key, curve_order, generator_point, a, p_mod):
    """
    Generates an ECDSA signature for the given message and private key on an elliptic curve.
    """
    h = int.from_bytes(message, 'big')
    z = h % curve_order
    k = 1
    r = None
    s = None
    while r is None or s is None or r == 0 or s == 0:
        k += 1
        if k >= curve_order:
            raise Exception("Failed to generate ECDSA signature.")
        k_inverse = mod_inv(k, curve_order)
        if k_inverse is None:
            raise Exception("Failed to generate ECDSA signature.")
        x, y = point_multiplication(k, generator_point, a, p_mod)
        r = x % curve_order
        s = (k_inverse * (z + r*private_key)) % curve_order
    return r, s

def ecdsa_verify(message, signature, public_key, curve_order, generator_point, a, p_mod):
    """
    Verifies an ECDSA signature for the given message and public key on an elliptic curve.
    """
    h = int.from_bytes(message, 'big')
    z = h % curve_order
    r, s = signature
    if r < 1 or r > curve_order-1 or s < 1 or s > curve_order-1:
        return False
    w = mod_inv(s, curve_order)
    u1 = (z * w) % curve_order
    u2 = (r * w) % curve_order
    x, y = point_addition(point_multiplication(u1, generator_point, a, p_mod), point_multiplication(u2, public_key, a, p_mod), a,p_mod)
    if x is None:
     return False
    else:
     return r == x % curve_order

# Generate random private key
private_key = 0x4a85b27c7dc8f16e73cf7d1f96ca1adff2f4e4d9afdf4fb632f69b882e8c3b1d


# Compute corresponding public key
public_key = point_multiplication(private_key, G, a, p)

# Test the signature generation and verification
message = b"Hello, world!"
signature = ecdsa_sign(message, private_key, n, G, a, p)
assert ecdsa_verify(message, signature, public_key, n, G, a, p)

print(public_key)