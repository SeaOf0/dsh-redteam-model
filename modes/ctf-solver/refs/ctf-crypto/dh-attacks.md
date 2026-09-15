# CTF Crypto - Classic Diffie-Hellman Attacks

Finite-field DH (`p, g`) key-exchange attacks. For ECDH invalid-curve/small-subgroup, see [ecc-attacks.md](ecc-attacks.md#invalid-curve-attacks). For Pohlig-Hellman/BSGS primitives, see [advanced-math.md](advanced-math.md#baby-step-giant-step-for-general-dlp).

## Table of Contents
- [Triage: Is This Classic DH?](#triage-is-this-classic-dh)
- [Trivial Generator Values (g = 0, 1, p-1)](#trivial-generator-values-g--0-1-p-1)
- [Pohlig-Hellman When p-1 Is Smooth](#pohlig-hellman-when-p-1-is-smooth)
- [Small-Subgroup Confinement / Lim-Lee (Static Key Recovery via CRT)](#small-subgroup-confinement--lim-lee-static-key-recovery-via-crt)
- [Static vs Ephemeral + Logjam Downgrade Notes](#static-vs-ephemeral--logjam-downgrade-notes)

## Triage: Is This Classic DH?

- Parameters `p` (large prime), `g` (generator), public values `A = g^a`, `B = g^b`, shared secret `S = g^(ab)`.
- Key derivation is usually `SHA256(S)` or `MD5(S)` truncated to AES key; oracle is MAC/encrypt/decrypt success.
- Check in order: (1) trivial `g`, (2) `p-1` smooth, (3) static key + composite `p-1` with small factors.

```python
from sympy import factorint
fac = factorint(p - 1)
print(fac)  # smooth (all < 40 bits) -> Pohlig-Hellman; else look for small-factor subgroup confinement
```

## Trivial Generator Values (g = 0, 1, p-1)

Server accepts attacker-influenced `g` or peer public value without validation.

- `g = 0` -> all secrets `0`.
- `g = 1` -> all secrets `1`.
- `g = p-1` (`order 2`) -> secret is `1` (even private) or `p-1` (odd private): 1-bit leak per query, or full break when combined with predictable parity.
- Peer sends `A = 0, 1, p-1` or `p` (`= 0 mod p`): shared secret becomes known constant.

```python
# Probe: send A = p - 1, observe oracle with S = 1 vs S = p - 1
for guess_secret in (1, p - 1):
    key = derive(guess_secret)
    if oracle_accepts(key):
        parity = 0 if guess_secret == 1 else 1
        break  # private exponent mod 2 = parity
```

**Detection:** `g` is `0/1/p-1`, or server skips `2 <= A <= p-2` range check. Always try these three before any lattice/BSGS.

## Pohlig-Hellman When p-1 Is Smooth

Same primitive as [advanced-math.md](advanced-math.md#baby-step-giant-step-for-general-dlp): factor `p-1`, solve DLP per prime-power subgroup via BSGS, CRT combine. CTF pattern is server regenerating weak `p` per connection: retry until smooth.

```python
def pohlig_hellman_dh(g, h, p):
    """Solve g^x = h mod p when p-1 is smooth.
    Hand-rolled BSGS per prime-power subgroup + sympy factorint/crt.
    (sympy.ntheory.discrete_log is NOT used: it raises "Log does not
    exist" on valid composite-order inputs, e.g. discrete_log(211, 2, 107).)
    """
    from math import isqrt
    from sympy import factorint
    from sympy.ntheory.modular import crt

    order = p - 1
    res, mod = [], []
    for prime, exp in factorint(order).items():
        pe = prime ** exp
        co = order // pe
        # BSGS on prime-power subgroup of order pe
        m = isqrt(pe) + 1
        base = pow(g, co, p)
        table, cur = {}, 1
        for j in range(m):
            table.setdefault(cur, j)
            cur = cur * base % p
        factor = pow(pow(base, -1, p), m, p)
        gamma = pow(h, co, p)
        xi = None
        for i in range(m):
            if gamma in table:
                xi = i * m + table[gamma]
                break
            gamma = gamma * factor % p
        res.append(xi)
        mod.append(pe)
    x, _ = crt(mod, res)
    return int(x % (p - 1))
```

## Small-Subgroup Confinement / Lim-Lee (Static Key Recovery via CRT)

**When:** static server key `b` reused across sessions, `p-1 = q * h` with many small factors in `h`. Attacker sends element of small order `r | h`, server computes `S = element^b`, oracle (MAC/decrypt/encrypt with derived key) reveals `b mod r` by brute-forcing `r` candidates. Repeat for coprime `r_i`, CRT to full `b`. Lim-Lee 1997; RFC 2785.

```python
from sympy import factorint
from sympy.ntheory.modular import crt

def subgroup_generator(g, p, r):
    """Element of exact order r (r | p-1)."""
    assert (p - 1) % r == 0
    h = pow(g, (p - 1) // r, p)
    assert pow(h, r, p) == 1 and h != 1
    return h

def recover_mod_r(malicious_pub, r, oracle_derive_check):
    """Brute-force b mod r: try S_j = malicious_pub^j, check oracle."""
    for j in range(r):
        if oracle_derive_check(pow(malicious_pub, j, p)):
            return j
    return None

# Workflow: for each small prime factor r of (p-1)/q:
#   w = subgroup_generator(g, p, r)
#   send w as peer public key, server derives S = w^b
#   b_mod_r = recover_mod_r(w, r, lambda S: try_decrypt_or_verify(S))
# residues.append(b_mod_r); moduli.append(r)
# b, _ = crt(moduli, residues)  # if prod(moduli) > q, full key; else BSGS/Lambda remainder
```

**Oracle shapes:** server returns `HMAC(S, msg)` tag, encrypts known plaintext under `KDF(S)`, or success/failure on attacker ciphertext. The `r` candidates each give a candidate `KDF(S_j)`; the one the server accepts is `b mod r`.

**Mitigations (recognition):** safe prime `p = 2q+1` (only subgroup order 2, 1-bit leak), subgroup membership test `A^q == 1 mod p`, cofactor clearing, ephemeral keys (ECDHE/DHE limits collection to one session).

<details><summary>Sage fallback (optional)</summary>

```python
# Sage: subgroup element + Pohlig per factor is automatic via discrete_log on the subgroup
# w = g^((p-1)/r) mod p  (order r); b_mod_r = discrete_log(Mod(server_S, p), Mod(w, p))
```

</details>

## Static vs Ephemeral + Logjam Downgrade Notes

- **Static DH:** long-term `b` reused -> Lim-Lee collects `b mod r_i` across sessions. Ephemeral (DHE/ECDHE) limits attacker to one confinement per session.
- **Unauthenticated ephemeral:** MITM replaces both `A, B` with small-order element (e.g., `-1`): both sides derive predictable `S` from tiny set.
- **Logjam triage (export-grade):** server accepts 512-bit `p` or attacker downgrades negotiation to weak group. Precompute once per `p` (NFS/DLP precomputation), then per-connection log is cheap. CTF analogue: challenge pins small `p` (512-768 bit) or reuses RFC 5114 group; check `p.bit_length() <= 768` and `openssl dhparam` known-group reuse before lattice work.

**References:** Lim-Lee 1997 (Crypto '97, LNCS 1295); RFC 2785 (small-subgroup countermeasures); RFC 7748 §6-7 (all-zero check, non-contributory behavior); Adrian et al. Logjam 2015.
