from pyasn1.type import univ

__all__ = (
	'id_kp_timeStamping', 'id_sha1', 'id_sha256', 'id_sha384',
	'id_sha512', 'id_ct_TSTInfo', 'oid_to_hash', 'availableHashOIDS', 'id_baseline_policy'
)

id_kp_timeStamping = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 3, 8))
id_ct_TSTInfo = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 4))
id_baseline_policy = univ.ObjectIdentifier((0, 4, 0, 2023, 1, 1))
id_signing_certificate = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 2, 12))

# Secure hash algorithms
id_sha1 = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))
id_sha256 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))
id_sha384 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 2))
id_sha512 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 3))

id_rsa = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))

availableHashOIDS = set([id_sha1, id_sha256, id_sha384, id_sha512])

oid_to_hash = {
	id_sha1: 'sha1',
	id_sha256: 'sha256',
	id_sha384: 'sha384',
	id_sha512: 'sha512',
}
