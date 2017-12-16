import classes
import constants
import uuid
import datetime

from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder

from pyasn1.type import useful, tag, univ

import rfc3852, rfc3280

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib

pem_data = open('cert/certificate.pem', 'r').read()
cert = x509.load_pem_x509_certificate(pem_data, default_backend())

pem_data = open('cert/key.pem', 'r').read()
rsa_key = serialization.load_pem_private_key(pem_data, password=b"grupoflam", backend=default_backend())

class TSATimeStamper(object):
	def __init__(self, timestamp_request):
		self.timestamp_request = timestamp_request
		self.certificate = cert
		self.private_key = rsa_key
		self.status_code = 200

	def verify(self):
		verified, request = self.decode_timestamp_request(self.timestamp_request)
		if not verified:
			self.status_code = 400
			return False, classes.PKIFailureInfo("badDataFormat")

		self.timestamp_request = request

		if request.version != 1:
			self.status_code = 400
			return False, classes.PKIFailureInfo("badDataFormat")

		if request.extensions != None and len(request.extensions) > 0: # No aceptamos extensiones
			return False, classes.PKIFailureInfo("unacceptedExtension")

		if request.reqPolicy  != None:
			if request.reqPolicy != constants.id_baseline_policy: # Unica politica aceptada
				return False, classes.PKIFailureInfo("unacceptedPolicy")

		verified, failInfo = self.checkMessageImprint(request.messageImprint)
		if not verified:
			return False, failInfo

		return True, None

	def checkMessageImprint(self, messageImprint):
		if not isinstance(messageImprint, classes.MessageImprint):
			self.status_code = 400
			return False, classes.PKIFailureInfo("badDataFormat")

		if messageImprint.hash_algorithm['algorithm'] not in constants.availableHashOIDS:
			return False, classes.PKIFailureInfo("badAlg")

		return True, None

	def serial_number(self):
		return uuid.uuid4().int

	def gen_time(self):
		return useful.GeneralizedTime().fromDateTime(datetime.datetime.now())

	def timestamp_response(self):
		verified, failureInfo = self.verify()

		if not verified:
			return self.error_response(failureInfo)

		# TST Info
		tst_info = classes.TSTInfo()
		tst_info['version'] = 1
		tst_info['policy'] = constants.id_baseline_policy
		tst_info['messageImprint'] = self.timestamp_request.messageImprint
		tst_info['serialNumber'] = self.serial_number()

		try:
			time = self.gen_time()
		except:
			return self.error_response(classes.PKIFailureInfo("timeNotAvailable"))
		
		tst_info['genTime'] = time

		if self.timestamp_request.nonce != None:
			tst_info['nonce'] = self.timestamp_request.nonce

		# ContentInfo
		encodedContent =  der_encoder.encode(tst_info)

		contentInfo = rfc3852.EncapsulatedContentInfo()
		contentInfo['eContentType'] = constants.id_ct_TSTInfo
		contentInfo['eContent'] = univ.OctetString().subtype(value=encodedContent, explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

		# DigestAlgorithm
		algorithm_identifier = rfc3280.AlgorithmIdentifier()
		algorithm_identifier.setComponentByPosition(0, constants.id_sha256)
		algorithm_identifier.setComponentByPosition(1, univ.Null(''))

		digestAlgorithms = rfc3852.DigestAlgorithmIdentifiers()
		digestAlgorithms.setComponentByPosition(0, algorithm_identifier)

		# SignerInfo
		signerInfo = rfc3852.SignerInfo()
		signerInfo['version'] = 1 # rfc 3852

		issuer = rfc3852.IssuerAndSerialNumber()
		issuer['issuer'] = self.cert_issuer_name()
		issuer['serialNumber'] = rfc3280.CertificateSerialNumber(self.certificate.serial_number)

		sid = rfc3852.SignerIdentifier()
		sid['issuerAndSerialNumber'] = issuer
		signerInfo['sid'] = sid

		signerDigestAlgorithm = rfc3280.AlgorithmIdentifier()
		signerDigestAlgorithm.setComponentByPosition(0, constants.id_sha256)
		signerDigestAlgorithm.setComponentByPosition(1, univ.Null(''))
		signerInfo['digestAlgorithm'] = signerDigestAlgorithm

		signerEncryptionAlgorithm = rfc3280.AlgorithmIdentifier()
		signerEncryptionAlgorithm.setComponentByPosition(0, constants.id_rsa)
		signerEncryptionAlgorithm.setComponentByPosition(1, univ.Null(''))
		signerInfo['signatureAlgorithm'] = signerEncryptionAlgorithm

		# SignedAttributes
		attributes = rfc3852.SignedAttributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

		# Content Type
		attr_content_type = self.attr_content_type()
		attributes.setComponentByPosition(0, attr_content_type)

		# Message digest
		attr_message_digest = self.attr_message_digest(encodedContent)
		attributes.setComponentByPosition(1, attr_message_digest)

		# Signing Certificate
		attr_signing_certificate = self.attr_signing_certificate()
		attributes.setComponentByPosition(2, attr_signing_certificate)

		signerInfo['signedAttrs'] = attributes

		# Signature
		s = univ.SetOf()
		for i, x in enumerate(attributes):
			s.setComponentByPosition(i, x)
		signed_data = der_encoder.encode(s)

		signature = self.private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
		signerInfo['signature'] = signature

		signerInfos = rfc3852.SignerInfos()
		signerInfos.setComponentByPosition(0, signerInfo)

		signedContent = rfc3852.SignedData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
		signedContent['version'] = 3
		signedContent['digestAlgorithms'] = digestAlgorithms
		signedContent['encapContentInfo'] = contentInfo
		signedContent['signerInfos'] = signerInfos

		# Certificates
		if self.timestamp_request.certReq == True:
			certificate, substrate = der_decoder.decode(self.certificate.public_bytes(serialization.Encoding.DER), asn1Spec=rfc3280.Certificate())
			ext_certificate = rfc3852.CertificateChoices()
			ext_certificate['certificate'] = certificate

			certificates = rfc3852.CertificateSet().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
			certificates.setComponentByPosition(0, ext_certificate)
			signedContent['certificates'] = certificates

		# Token
		token = classes.TimeStampToken()
		token['content'] = signedContent
		token['contentType'] = rfc3852.id_signedData

		# Status
		statusInfo = classes.PKIStatusInfo()
		statusInfo['status'] = classes.PKIStatus('granted')

		# Response
		response = classes.TimeStampResp()
		response['status'] = statusInfo
		response['timeStampToken'] = token

		return self.encode_timestamp_response(response)

	def attr_content_type(self):
		attribute = rfc3852.Attribute()
		attribute['attrType'] = constants.id_content_type

		values = univ.Set()
		values.setComponentByPosition(0, constants.id_ct_TSTInfo)

		attribute['attrValues'] = values
		return attribute

	def attr_signing_time(self):
		return None

	def attr_message_digest(self, content):
		attribute = rfc3852.Attribute()
		attribute['attrType'] = constants.id_message_digest

		contentDigest = hashlib.sha256(content).digest()

		values = univ.Set()
		values.setComponentByPosition(0, univ.OctetString(contentDigest))

		attribute['attrValues'] = values
		return attribute

	def attr_signing_certificate(self):
		issuerSerial = classes.IssuerSerial()
		issuerSerial['issuer'] = self.cert_issuer_name()
		issuerSerial['serialNumber'] = self.certificate.serial_number

		essCertId = classes.ESSCertID()
		essCertId['certHash'] = self.certificate.public_bytes(serialization.Encoding.DER)
		essCertId['issuerSerial'] = issuerSerial

		essCertsIds = univ.Sequence()
		essCertsIds.setComponentByPosition(0, essCertId)

		signing_certificate = classes.SigningCertificate()
		signing_certificate['certs'] = essCertsIds

		attribute = rfc3852.Attribute()
		attribute['attrType'] = constants.id_signing_certificate

		values = univ.Set()
		values.setComponentByPosition(0, signing_certificate)

		attribute['attrValues'] = values

		return attribute

	def cert_issuer_name(self):
		issuer_name, substrate = der_decoder.decode(self.certificate.issuer.public_bytes(default_backend()), asn1Spec=rfc3280.Name())
		return issuer_name

	def error_response(self, failureInfo):
		status = classes.PKIStatus('rejection')

		statusInfo = classes.PKIStatusInfo()
		statusInfo['status'] = status
		statusInfo['failInfo'] = failureInfo

		response = classes.TimeStampResp()
		response['status'] = statusInfo

		return self.encode_timestamp_response(response)

	def decode_timestamp_request(self, request):
		try:
			tsq, substrate = der_decoder.decode(request, asn1Spec=classes.TimeStampReq())
			if substrate:
				return False
			pass
		except:
			return False
		return True, tsq

	def encode_timestamp_response(self, response):
		try:
			return der_encoder.encode(response)
		except:
			return self.error_response(classes.PKIFailureInfo("systemFailure"))

	def get_status_code(self):
		return self.status_code
