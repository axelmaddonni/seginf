# Request

class MessageImprint(object):
	def __init__(self, hashAlgorithm, hashedMessage):
		self.hashAlgorithm = hashAlgorithm
		self.hashedMessage = hashedMessage
	def getHashAlgorithm(self):
		return self.hashAlgorithm
	def getHashedMessage(self):
		return self.hashedMessage

class TimeStampReq(object):
	def __init__(self, version=version, msg=messageImprint):
		self.version = version
		self.messageImprint = messageImprint
	def getVersion(self):
		return self.version
	def getMessageImprint(self):
		return self.messageImprint


# Reponse

class TimeStampResp(object):
	def __init__(self, status=status, timeStampToken=timeStampToken):
		self.status = status
		self.timeStampToken = timeStampToken
	def getStatus(self):
		return self.status
	def getTimeStampToken(self):
		return self timeStampToken

class TimeStampToken(object):
	def __init__(self, contentType=contentType, content=None):
		self.contentType = contentType
		self.content = content
	def getContentType(self):
		return self.contentType
	def getContent(self):
		return self.content

class PKIStatusInfo(object):
	def __init__(self, status=status, statusString=None, failInfo=None):
		self.status = status
		self.statusString = statusString
		self.failInfo = failInfo
	def getStatus(self):
		return self.status
	def getStatusString(self):
		return self.statusString
	def getFailInfo(self):
		return self.failInfo

# class PKIStatus(univ.Integer):
#     namedValues = namedval.NamedValues(
#         ('granted', 0),
#         # -- when the PKIStatus contains the value zero a TimeStampToken, as
#         #   requested, is present.
#         ('grantedWithMods', 1),
#         # -- when the PKIStatus contains the value one a TimeStampToken,
#         #   with modifications, is present.
#         ('rejection', 2), ('waiting', 3), ('revocationWarning', 4),
#         # -- this message contains a warning that a revocation is
#         # -- imminent
#         ('revocationNotification', 5),
#     )


# class PKIFailureInfo(univ.BitString):
#     namedValues = namedval.NamedValues(
#         ('badAlg', 0),
#         # -- unrecognized or unsupported Algorithm Identifier
#         ('badRequest', 2),
#         # -- transaction not permitted or supported
#         ('badDataFormat', 5),
#         # -- the data submitted has the wrong format
#         ('timeNotAvailable', 14),
#         # -- the TSA's time source is not available
#         ('unacceptedPolicy', 15),
#         # -- the requested TSA policy is not supported by the TSA
#         ('unacceptedExtension', 16),
#         # -- the requested extension is not supported by the TSA
#         ('addInfoNotAvailable', 17),
#         # -- the additional information requested could not be understood
#         # -- or is not available
#         ('systemFailure', 25),
#         # -- the request cannot be handled due to system failure  }
#     )

# class PKIFreeText(univ.SequenceOf):
#     componentType = char.UTF8String()
#     sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)
