import ../ServicioAPP/classes

# obtener el hash
# con el hash generar TSTInfo (timestamp token info)
# codificar TSTINFO con DER
# agregarle a la TSTINFO codificada, eContentType (ver documentacion). 
# firmar
# Ahora tenemos el TST
# generar response: agregar el status al TST


class TSA(object):
	def __init__(self, certificate, request):
		self.certificate
		self.request = request
		self.failure = verify(request)
		if failure != NULL:
			return createResponse()
		else:
			return PKStatusInfo('status' = PKStatus(2), 'failInfo' = failure)

	def verify(self,request):
		if not isinstance(request, TimeStampReq):
	        return PKFailureInfo("badDataFormat")
		if request.version != 1:
	        return PKFailureInfo("badDataFormat")
	    if not isinstance(request.messageImprint, MessageImprint):
	        return PKFailureInfo("badDataFormat")
	    if request.messageImprint.hash_algorithm != univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))   #fijarse en constants.py
	        return PKFailureInfo("badAlg")
	    if request.messageImprint.hashed_message.lenth != 256:
	        return PKFailureInfo("badAlg")
	    if request.extensions != NULL:  #podemos no aceptar extenciones
	        return PKIFailureInfo("unacceptedExtension")
	    #if reqPolicy  in aceptedPolicies:
	    #   return PKFailureInfo(unacceptedPolicy)

	def createResponse(certificate, request):
		#info = TSTInfo('messageImprint' = request.messageImprint)	#check nonce
		return TimeStampToken()