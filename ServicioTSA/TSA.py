import classes
import constants

from pyasn1.codec.der import encoder, decoder

# obtener el hash
# con el hash generar TSTInfo (timestamp token info)
# codificar TSTINFO con DER
# agregarle a la TSTINFO codificada, eContentType (ver documentacion). 
# firmar
# Ahora tenemos el TST
# generar response: agregar el status al TST

class TSA(object):
	def __init__(self, timestamp_request):
		self.timestamp_request = timestamp_request
		# self.certificate = certificate

	def verify(self):
		verified, request = self.decode_timestamp_request(self.timestamp_request)
		if not verified:
			return False, classes.PKIFailureInfo("badDataFormat")

		# if not isinstance(request, TimeStampReq()):
			# return False, PKIFailureInfo("badDataFormat")

		# if request.version != 1:
		# 	return False, PKIFailureInfo("badDataFormat")

		# if not isinstance(request.messageImprint, MessageImprint):
		# 	return False, PKIFailureInfo("badDataFormat")

		# if request.messageImprint.hash_algorithm != univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1)):
		# 	#fijarse en constants.py
		# 	return False, PKIFailureInfo("badAlg")

		# if request.messageImprint.hashed_message.lenth != 256:
		# 	return False, PKIFailureInfo("badAlg")

		# if request.extensions != NULL:  #podemos no aceptar extensiones
			# return False, PKIFailureInfo("unacceptedExtension")

		#if reqPolicy  in aceptedPolicies:
		#	return PKIFailureInfo(unacceptedPolicy)

		return True, None

	def timestamp_response(self):
		verified, failureInfo = self.verify()
		if not verified:
			return self.error_response(failureInfo)

		# TODO: Armar TimeStampResponse
		response = classes.TimeStampResp()

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
