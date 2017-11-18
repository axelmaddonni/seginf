from flask import Flask, render_template, request, make_response
import pdfkit
import hashlib
from werkzeug.serving import run_simple
import requests
import classes

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error

app = Flask(__name__)

id_attribute_messageDigest = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 4))

def make_timestamp_request(digest, include_tsa_certificate=False, nonce=None):
    algorithm_identifier = rfc2459.AlgorithmIdentifier()
    algorithm_identifier.setComponentByPosition(0, '2.16.840.1.101.3.4.2.1')
    # OID del hash de sha256 http://oid-info.com/get/2.16.840.1.101.3.4.2.1

    message_imprint = classes.MessageImprint()
    message_imprint.setComponentByPosition(0, algorithm_identifier)
    message_imprint.setComponentByPosition(1, digest)

    request = classes.TimeStampReq()
    request.setComponentByPosition(0, 'v1')
    request.setComponentByPosition(1, message_imprint)

    if nonce is not None:
        request.setComponentByPosition(3, int(nonce))
    request.setComponentByPosition(4, include_tsa_certificate)

    return request

def check_timestamp(tst, certificate=None, data=None, digest=None, hashname=None, nonce=None):
    hashobj = hashlib.new('sha256')
    if digest is None:
        if not data:
            raise ValueError("check_timestamp requires data or digest argument")
        hashobj.update(data)
        digest = hashobj.digest()

    if not isinstance(tst, classes.TimeStampToken):
        tst, substrate = decoder.decode(tst, asn1Spec=classes.TimeStampToken())
        if substrate:
            raise ValueError("extra data after tst")
    signed_data = tst.content
    # certificate = load_certificate(signed_data, certificate)
    if nonce is not None and int(tst.tst_info['nonce']) != int(nonce):
        raise ValueError('nonce is different or missing')
    # check message imprint with respect to locally computed digest
    message_imprint = tst.tst_info.message_imprint
    if message_imprint.hash_algorithm[0] != univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1)) or bytes(message_imprint.hashed_message) != digest:
        raise ValueError('Message imprint mismatch')
    if not len(signed_data['signerInfos']):
        raise ValueError('No signature')
    # We validate only one signature
    signer_info = signed_data['signerInfos'][0]
    # check content type
    if tst.content['contentInfo']['contentType'] != univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 4)):
        raise ValueError("Signed content type is wrong: %s != %s" % (
            tst.content['contentInfo']['contentType'], univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 4))
        ))

    # check signed data digest
    content = bytes(decoder.decode(bytes(tst.content['contentInfo']['content']), asn1Spec=univ.OctetString())[0])
    # if there is authenticated attributes, they must contain the message
    # digest and they are the signed data otherwise the content is the
    # signed data
    if len(signer_info['authenticatedAttributes']):
        authenticated_attributes = signer_info['authenticatedAttributes']
        signer_digest_algorithm = signer_info['digestAlgorithm']['algorithm']
        # signer_hash_class = get_hash_class_from_oid(signer_digest_algorithm)
        signer_hash_class = hashlib.sha256
        # signer_hash_name = get_hash_from_oid(signer_digest_algorithm)
        content_digest = signer_hash_class(content).digest()
        for authenticated_attribute in authenticated_attributes:
            if authenticated_attribute[0] == id_attribute_messageDigest:
                try:
                    signed_digest = bytes(decoder.decode(bytes(authenticated_attribute[1][0]), asn1Spec=univ.OctetString())[0])
                    print("asbdkabsdkjasd")
                    print(signed_digest)
                    print("asbdkabsdkjasd")
                    print(content_digest)
                    # ESTO NO ANDA, POR ALGUNA RAZON ESTOS DIGEST DAN DISTINTO, DEBUGGEAR Y ENCONTRAR LA RAZON
                    if signed_digest != content_digest:
                        raise ValueError('Content digest != signed digest')
                    s = univ.SetOf()
                    for i, x in enumerate(authenticated_attributes):
                        s.setComponentByPosition(i, x)
                    signed_data = encoder.encode(s)
                    break
                except PyAsn1Error:
                    raise
        else:
            raise ValueError('No signed digest')
    else:
        signed_data = content
    # check signature
    signature = signer_info['encryptedDigest']
    # public_key = certificate.public_key()
    # hash_family = getattr(hashes, signer_hash_name.upper())
    # public_key.verify(
    #     bytes(signature),
    #     signed_data,
    #     padding.PKCS1v15(),
    #     hash_family(),
    # )
    return True

@app.route("/")
def main():
	return render_template('index.html')

def showPdf(pdfBinary, fileName):
	response = make_response(pdfBinary)
	response.headers['Content-Type'] = 'application/pdf'
	response.headers['Content-Disposition'] = 'inline; filename=%s.pdf' % fileName
	return response

@app.route('/submit', methods=['POST'])
def submit():
	# Agarro los datos que completo el usuario
	first_name = request.form['nombre']
	webSite = request.form['webSite']
	# Genero el PDF de la pagina y lo hasheo 
	pdf = pdfkit.from_url(webSite, False)

	hashPdfDigest = (hashlib.sha256(pdf)).digest()
	tsq = make_timestamp_request(hashPdfDigest)
	tsq = encoder.encode(tsq)

	print(tsq)

	# file_out = open('request.tsq', 'w')
	# file_out.write(tsq)
	# file_out.close()

	print(1)

	# Set up the parameters we want to pass to the API.
	# Make a get request with the parameters.
	headers = {'Content-type': 'application/timestamp-query'}

	print(2)

	http_response = requests.post("https://freetsa.org/tsr", headers=headers, data=tsq)
	# response = requests.post("http://0.0.0.0:12346/", headers=headers, data=parameters)

	print(3)

	tsr = http_response.content
	print(4)

	print(tsr)

	tsr, caca = decoder.decode(tsr, asn1Spec=classes.TimeStampResp())

	token = tsr.time_stamp_token
	print(check_timestamp(token, digest=hashPdfDigest, hashname='sha256'))

	print("token")
	print(token)

	print(5)

	# Print the content of the response (the data the server returned)

	# resultadoAFirmar = response.content


	return "hola"
	#Firmar lo que devuelve la tsa con paddes
	#Hacer que se pueda descargar

	#descarga(pdf) o error(pdf)

#@app.route('/descarga')
#def descarga():

#@app.route('/error')
#def error():

if __name__ == "__main__":
	app.run(host='0.0.0.0', port = 12345, debug=True)
	#run_simple('localhost', 5000, app, use_reloader=True, use_debugger=True, use_evalex=True)

