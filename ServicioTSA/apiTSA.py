from flask import Flask, request
from flask_restful import Resource, Api

from TSA import *

app = Flask(__name__)

from pyasn1.codec.der import decoder

@app.route('/tsr', methods=['POST'])
def tsr():

	tsa = TSA(timestamp_request=request.data)
	response = tsa.timestamp_response()

	# Para testear:
	# tsq = decoder.decode(response, asn1Spec=classes.TimeStampResp())
	# print(tsq)

	return response, 200

if __name__ == '__main__':
	app.run(host='0.0.0.0', port = 12346, debug=True)