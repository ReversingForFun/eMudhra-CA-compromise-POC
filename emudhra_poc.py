import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509

from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import util


# get the paranoid objects from x509certs
def get_paranoid(x509cert):
	pnum = x509cert.public_key().public_numbers()
	key = paranoid_pb2.ECKey()
	key.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP384R1
	key.ec_info.x = util.Int2Bytes(pnum.x)
	key.ec_info.y = util.Int2Bytes(pnum.y)
	return key

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

# load all of the .pem files from the path and check them with paranoid_crypto
# if any 'CheckWeakECPrivateKey' failures are found then we will send them to be bruteforced otherwise just print the failure
def load_and_check(path):
	filepaths = os.listdir(path)
	for f in filepaths:
		if '.pem' in f[-4:]:
			c = x509.load_pem_x509_certificate(open(path + f, 'rb').read())
			print(f'testing {c.subject}')
			test_key = get_paranoid(c)
			paranoid.CheckAllEC([test_key], log_level=0)
			WeakECPrivate = util.GetTestResult(test_key.test_info, "CheckWeakECPrivateKey")
			if WeakECPrivate:
				print(f'found weak EC result, brute forcing private key!')
				test_weak_private_keys(c)
			else:
				for test_result in test_key.test_info.test_results:
					if test_result.result:
						print(f'found weak result!')
						print(test_result)


load_and_check('./certs/')

