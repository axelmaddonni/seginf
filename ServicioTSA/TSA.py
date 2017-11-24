import classes
import constants

from pyasn1.codec.der import encoder, decoder

class TSA(object):
	def __init__(self, timestamp_request):
		self.timestamp_request = timestamp_request
		# self.certificate = certificate

	def verify(self):
		verified, request = self.decode_timestamp_request(self.timestamp_request)
		if not verified:
			return False, classes.PKIFailureInfo("badDataFormat")

		if request.version != 1:
			return False, classes.PKIFailureInfo("badDataFormat")

		if not isinstance(request.messageImprint, classes.MessageImprint):
			return False, classes.PKIFailureInfo("badDataFormat")

		if request.messageImprint.hash_algorithm not in constants.availableHashOIDS:
			return False, classes.PKIFailureInfo("badAlg")

		# TODO: Completar verificaciones
		# if request.extensions != NULL:  #podemos no aceptar extensiones
			# return False, PKIFailureInfo("unacceptedExtension")

		# if reqPolicy  in aceptedPolicies:
			#return PKIFailureInfo(unacceptedPolicy)

		return True, None


	def timestamp_response(self):
		verified, failureInfo = self.verify()
		if not verified:
			return self.error_response(failureInfo)

		signedContent = SignedData()
		# TODO: ARmar el signedContent
		# class SignedData(univ.Sequence):
		#     componentType = namedtype.NamedTypes(
		#         namedtype.NamedType('version', Version()),
		#         namedtype.NamedType('digestAlgorithms', DigestAlgorithmIdentifiers()),
		#         namedtype.NamedType('contentInfo', ContentInfo()),
		#         namedtype.OptionalNamedType('certificates', ExtendedCertificatesAndCertificates().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
		#         namedtype.OptionalNamedType('crls', CertificateRevocationLists().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
		#         namedtype.NamedType('signerInfos', SignerInfos())
		#         )

		token = classes.TimeStampToken()
		token['content'] = signedContent

		statusInfo = classes.PKIStatusInfo()
		statusInfo['status'] = classes.PKIStatus('granted')

		response = classes.TimeStampResp()
		response['status'] = statusInfo
		response['timeStampToken'] = token

		return self.encode_timestamp_response(response)

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
			tsq, substrate = decoder.decode(request, asn1Spec=classes.TimeStampReq())
			if substrate:
				return False
			pass
		except:
			return False
		return True, tsq

	def encode_timestamp_response(self, response):
		try:
			return encoder.encode(response)
		except:
			return self.error_response(classes.PKIFailureInfo("systemFailure"))


# ================================================================================

# Ejemplo de TimeStamp Response

# ================================================================================

# TimeStampResp:
#  status=PKIStatusInfo:
#   status=granted

#  timeStampToken=TimeStampToken:
#   contentType=1.2.840.113549.1.7.2
#   content=SignedData:
#    version=3
#    digestAlgorithms=DigestAlgorithmIdentifiers:
#     DigestAlgorithmIdentifier:
#      algorithm=1.3.14.3.2.26
#      parameters=0x0500

#    contentInfo=ContentInfo:
#     contentType=1.2.840.113549.1.9.16.1.4
#     content=0x0482017f3082017b02010106042a030401302f300b06096086480165030402010420bca2837a7b5d7116ef6d466629654e135f012c6ab3b383e04b47080e2aee7cda020305b86e181632303137313132343032303334332e3531313337315a300a020101800201f48101640101ffa0820111a482010d308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726e

#    signerInfos=SignerInfos:
#     SignerInfo:
#      version=1
#      issuerAndSerialNumber=IssuerAndSerialNumber:
#       issuer=Name:
#        =RDNSequence:
#         RelativeDistinguishedName:
#          AttributeTypeAndValue:
#           type=2.5.4.10
#           value=0x13084672656520545341
#         RelativeDistinguishedName:
#          AttributeTypeAndValue:
#           type=2.5.4.11
#           value=0x1307526f6f74204341
#         RelativeDistinguishedName:
#          AttributeTypeAndValue:
#           type=2.5.4.3
#           value=0x130f7777772e667265657473612e6f7267
#         RelativeDistinguishedName:
#          AttributeTypeAndValue:
#           type=1.2.840.113549.1.9.1
#           value=0x1613627573696c657a617340676d61696c2e636f6d
#         RelativeDistinguishedName:
#          AttributeTypeAndValue:
#           type=2.5.4.7
#           value=0x1309577565727a62757267
#         RelativeDistinguishedName:
#          AttributeTypeAndValue:
#           type=2.5.4.8
#           value=0x130642617965726e
#         RelativeDistinguishedName:
#          AttributeTypeAndValue:
#           type=2.5.4.6
#           value=0x13024445


#       serialNumber=13972846748170250626

#      digestAlgorithm=DigestAlgorithmIdentifier:
#       algorithm=1.3.14.3.2.26
#       parameters=0x0500

#      authenticatedAttributes=Attributes:
#       Attribute:
#        type=1.2.840.113549.1.9.3
#        values=SetOf:
#         0x060b2a864886f70d0109100104
#       Attribute:
#        type=1.2.840.113549.1.9.5
#        values=SetOf:
#         0x170d3137313132343032303334335a
#       Attribute:
#        type=1.2.840.113549.1.9.4
#        values=SetOf:
#         0x0414ee404859fddcbaec41643845b7ef7c1813f62481
#       Attribute:
#        type=1.2.840.113549.1.9.16.2.12
#        values=SetOf:
#         0x301a301830160414916da3d860ecca82e34bc59d1793e7e968875f14

#      digestEncryptionAlgorithm=DigestEncryptionAlgorithmIdentifier:
#       algorithm=1.2.840.113549.1.1.1
#       parameters=0x0500

#      encryptedDigest=0x406ad27cb58b99e7bfd14244f428f147f0dfe25af92c8abb1f27d96517d6aaf58d4e557db04126ae384cc2d6ff1601af4d33a8f51c8b8f9ca6dba344a4aee0e2fa2028c2254197079a8202170ccff9a2165306e3a46f6baf75c559786d49a4a38c656d64f803d6bcfc0998f8ad891911cd12809a45bce7410befe03286f7fed02b14a9dd3291c66bc748805b727ac0c60e52a46b5773271632ea364b43022463f401de417efaf156f6f7e06394bfb8ac9808583d9fe3be6e5fe32907c0742559d246d3ccc82cf2a11d920e6bf4ed54af5cf956bcc1f9455e3829dd4f97625bd3f96d91482bab0de66b99ff60e72e5c0a9973a735f8b02d651a2313ca95c854e94183ee5ef403df05b5be5ee48547edb997dc26255ae36728a759182f560abc906fc4721c66bfb01f1bdc1c0cebb391e37537057d6df856c5d06e7b0101d4b39fdff6ef59914be4f348eff7022f20f3f608c7123f70279e5f264cf2a54f069a838410e3ffb300f1050a81fef0cf1286d4c440879676396b3cde35179c03861c519aa2d6e70fd9594c7cdbebc974062c0e2c8f0bf0c96619fe6ef7af2a04054b837ea8f247e81bc6789b7f86ebb260ea5038474d1d1bdec4a8e23604e68e53faa4c62b67656b687a2fd8e9a582bc77cd4ac580dad86957b487c65a84f648e0639ce0cdf811dae45ad951d1890fcbec4d29938be6d8473556b125d9ddce2fbed0bf

# ================================================================================
