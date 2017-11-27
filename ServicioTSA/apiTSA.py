from flask import Flask, request
from flask_restful import Resource, Api
from OpenSSL import SSL

from TSA import *

app = Flask(__name__)

from pyasn1.codec.der import decoder

@app.route('/tsr', methods=['POST'])
def tsr():

	# Para corroborar que el request sea correcto usando openssl
	file_out = open('request.tsq', 'w')
	file_out.write(request.data)
	file_out.close()

	tsa = TSA(timestamp_request=request.data)
	response = tsa.timestamp_response()

	# Para corroborar que el response sea correcto usando openssl
	file_out = open('response.tsr', 'w')
	file_out.write(response)
	file_out.close()

	return response, 200

if __name__ == '__main__':
	app.run(host='0.0.0.0', port = 12346, debug=True, ssl_context=('cert/certificate.pem', 'cert/key.pem'))