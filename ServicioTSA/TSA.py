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

		self.timestamp_request = request

		if request.version != 1:
			return False, classes.PKIFailureInfo("badDataFormat")

		if not isinstance(request.messageImprint, classes.MessageImprint):
			return False, classes.PKIFailureInfo("badDataFormat")

		if request.messageImprint.hash_algorithm not in constants.availableHashOIDS:
			return False, classes.PKIFailureInfo("badAlg")

		# TODO: Completar verificaciones
		# if request.extensions != NULL:#   podemos no aceptar extensiones
			# return False, PKIFailureInfo("unacceptedExtension")

		# if reqPolicy  in aceptedPolicies:
			#return PKIFailureInfo(unacceptedPolicy)

		return True, None


	def timestamp_response(self):
		verified, failureInfo = self.verify()
		if not verified:
			return self.error_response(failureInfo)

		# TODO: Completar generación del token completando cada campo faltante a continuación

		tst_info = TSTInfo()
		tst_info['version'] = 1
		tst_info['policy'] = 
		tst_info['messageImprint'] = self.timestamp_request.messageImprint
		tst_info['serialNumber'] = 12345
		tst_info['genTime'] = 

		# Opcionales
		# tst_info['accuracy'] =
		# tst_info['ordering'] =
		# tst_info['nonce'] =
		# tst_info['tsa'] =
		# tst_info['extensions'] =

		# Mas info sobre esto en https://stackoverflow.com/questions/28408047/message-digest-of-pdf-in-digital-signature/28429984#28429984
		contentInfo = ContentInfo()
		contentInfo['contentType'] = constants.id_ct_TSTInfo
		contentInfo['content'] = self.der_encode(tst_info)
		# Este content es el que hay que firmar casteandolo a OctetString usando el certificado

		# Completar mirando:
		# https://tools.ietf.org/html/rfc3852#section-5
		# https://github.com/coruus/pyasn1-modules/blob/master/pyasn1_modules/rfc2315.py
		# https://github.com/coruus/pyasn1-modules/blob/master/pyasn1_modules/rfc2459.py
		digestAlgorithms =
		signerInfos =

		signedContent = SignedData()
		signedContent['version'] = 3
		signedContent['digestAlgorithms'] = digestAlgorithms
		signedContent['contentInfo'] = contentInfo
		signedContent['signerInfos'] = signerInfos

		if self.timestamp_request.certReq == True:
			# Crear certificado auto-firmado usando módulo criptography.x509
			# https://cryptography.io/en/latest/x509/
			certificates = ExtendedCertificatesAndCertificates()
			signedContent['certificates'] = certificates

		# Buscar cuando hay que completar las crls
		# signedContent['crls'] = CertificateRevocationLists()

		token = classes.TimeStampToken()
		token['content'] = signedContent
		# token['contentType'] creo que no hace falta completarlo

		statusInfo = classes.PKIStatusInfo()
		statusInfo['status'] = classes.PKIStatus('granted')

		response = classes.TimeStampResp()
		response['status'] = statusInfo
		response['timeStampToken'] = token

		return self.der_encode(response)

	def error_response(self, failureInfo):
		status = classes.PKIStatus('rejection')

		statusInfo = classes.PKIStatusInfo()
		statusInfo['status'] = status
		statusInfo['failInfo'] = failureInfo

		response = classes.TimeStampResp()
		response['status'] = statusInfo

		return self.der_encode(response)

	def decode_timestamp_request(self, request):
		try:
			tsq, substrate = decoder.decode(request, asn1Spec=classes.TimeStampReq())
			if substrate:
				return False
			pass
		except:
			return False
		return True, tsq

	def der_encode(self, data):
		try:
			return encoder.encode(data)
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

# CONTENT INFO

#    contentInfo=ContentInfo:
#     contentType=1.2.840.113549.1.9.16.1.4
#     content=0x0482017f3082017b02010106042a030401302f300b06096086480165030402010420bca2837a7b5d7116ef6d466629654e135f012c6ab3b383e04b47080e2aee7cda020305b86e181632303137313132343032303334332e3531313337315a300a020101800201f48101640101ffa0820111a482010d308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726e

# CERTIFICATES

#    certificates=ExtendedCertificatesAndCertificates:
#      ExtendedCertificateOrCertificate:
#       certificate=Certificate:
#        tbsCertificate=TBSCertificate:
#         version=v3
#         serialNumber=13972846748170250626
#         signature=AlgorithmIdentifier:
#          algorithm=1.2.840.113549.1.1.13
#          parameters=0x0500

#         issuer=Name:
#          =RDNSequence:
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.10
#             value=0x13084672656520545341
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.11
#             value=0x1307526f6f74204341
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.3
#             value=0x130f7777772e667265657473612e6f7267
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=1.2.840.113549.1.9.1
#             value=0x1613627573696c657a617340676d61696c2e636f6d
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.7
#             value=0x1309577565727a62757267
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.8
#             value=0x130642617965726e
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.6
#             value=0x13024445

#         validity=Validity:
#          notBefore=Time:
#           utcTime=160313015739Z

#          notAfter=Time:
#           utcTime=260311015739Z

#         subject=Name:
#          =RDNSequence:
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.10
#             value=0x13084672656520545341
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.11
#             value=0x1303545341
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.13
#             value=0x136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.3
#             value=0x130f7777772e667265657473612e6f7267
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=1.2.840.113549.1.9.1
#             value=0x1613627573696c657a617340676d61696c2e636f6d
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.7
#             value=0x1309577565727a62757267
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.6
#             value=0x13024445
#           RelativeDistinguishedName:
#            AttributeTypeAndValue:
#             type=2.5.4.8
#             value=0x130642617965726e

#         subjectPublicKeyInfo=SubjectPublicKeyInfo:
#          algorithm=AlgorithmIdentifier:
#           algorithm=1.2.840.113549.1.1.1
#           parameters=0x0500

#          subjectPublicKey=1027528218406287093987025062799654245587892696207566969132852840099925751335752515456718821660642541192845801899200413819270052020035559060429772399801841297312143224060934514128695782403532650747515999262641855445046998748889529934748485790487729819270229981046435445340321090234128089914369170064679315329369027117308414680875851109978722672279855354980158450315124419076589878645952797611818420905529652795249286077849459733622367170824611321136193429344161564570734976799801168874392643997005261680370905714727564056305778847547295634100429924661665355814963440610195640635826149734645976546626757051822121685655735027321132939718906664502345838148726389934471264410900807950173559956823395144361887760819281549735377593821514263917251817491881265443623664947188224674769446563912808770713166384918489100615866368936162966829156774358639607603464451025956141595080334826731478265154483179146119976412363857047967404648405790683020807241539648286152837557806401859221653217698994254642390407845082103136421774696054523674092321649222412589458749192601685907750634250853848675792751367672548471727754674550559026822166464758493001342438286743669207155980213639529965443912087122701353488278363008896269998955916542889164673347976478930295482423235424510871815127041

#         extensions=Extensions:
#          Extension:
#           extnID=2.5.29.19
#           extnValue=0x04023000
#          Extension:
#           extnID=2.5.29.14
#           extnValue=0x041604146e760b7b4e4f9ce160ca6d2ce927a2a294b37737
#          Extension:
#           extnID=2.5.29.35
#           extnValue=0x041830168014fa550d8c346651434cf7e7b3a76c95af7ae6a497
#          Extension:
#           extnID=2.5.29.15
#           extnValue=0x0404030206c0
#          Extension:
#           extnID=2.5.29.37
#           critical=True
#           extnValue=0x040c300a06082b06010505070308
#          Extension:
#           extnID=1.3.6.1.5.5.7.1.1
#           extnValue=0x04573055302a06082b06010505073002861e687474703a2f2f7777772e667265657473612e6f72672f7473612e637274302706082b06010505073001861b687474703a2f2f7777772e667265657473612e6f72673a32353630
#          Extension:
#           extnID=2.5.29.31
#           extnValue=0x0430302e302ca02aa0288626687474703a2f2f7777772e667265657473612e6f72672f63726c2f726f6f745f63612e63726c
#          Extension:
#           extnID=2.5.29.32
#           extnValue=0x0481be3081bb3081b80601003081b2303306082b060105050702011627687474703a2f2f7777772e667265657473612e6f72672f667265657473615f6370732e68746d6c303206082b060105050702011626687474703a2f2f7777772e667265657473612e6f72672f667265657473615f6370732e706466304706082b06010505070202303b1a394672656554534120747275737465642074696d657374616d70696e6720536f6674776172652061732061205365727669636520285361615329

#        signatureAlgorithm=AlgorithmIdentifier:
#         algorithm=1.2.840.113549.1.1.13
#         parameters=0x0500

#        signatureValue=676348717434685804917345234586853252720544260355843439747925707201812127291791491980223356945413076871552126865554921837170343743576504511340514221705114532133341671137757051804436198396371888906849682033284204882691352407857844623439403707465673996959711266502512458055357365453542484396949211733410504478015308610828065429592048893324516539542357041096853150898957656688909435071035395382716326572760569092541457994349323249356981171741123652533981304247985884659677679409840041588789068611083483888842227038080165445280391484552990167801843727302469020860607445185899753615172539723669416804790868354917152100859169431716606980270623296712666895681576041754466522866328278745728664100140977155845995588066268618702866311343947566325842222799149805794930359119323958753206419537020277201818946053289581530076457145623619220894977224845022325786551475656313911544834401612052548918929558370746630788267400453325565771693979607300365957393217001278551825597826343354052123183204558247297777345537154280579812644330928354802759279692487930164670943177273927345101562993231525180923143209926901678294968706578977485632469647876644757756710648940852621027790578813825385940908817154051505696345981003587417185806131048954872250275582432


# SIGNER INFOS

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
