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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from pyasn1_modules.rfc2315 import ContentInfo, signedData, SignedData

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
	return encoder.encode(request)

def get_hash_oid(hashname):
    return classes.__dict__['id_' + hashname]

def get_hash_from_oid(oid):
    h = classes.oid_to_hash.get(oid)
    if h is None:
        raise ValueError('unsupported hash algorithm', oid)
    return h

def get_hash_class_from_oid(oid):
    h = get_hash_from_oid(oid)
    return getattr(hashlib, h)

def check_timestamp(tst, certificate=None, digest=None, hashname=None, nonce=None):
    hashobj = hashlib.new('sha256')
    # if digest is None:
    #     if not data:
    #         raise ValueError("check_timestamp requires data or digest argument")
    #     hashobj.update(data)
    #     digest = hashobj.digest()

    # if not isinstance(tst, classes.TimeStampToken):
    #     tst, substrate = decoder.decode(tst, asn1Spec=classes.TimeStampToken())
    #     if substrate:
    #         raise ValueError("extra data after tst")

    signed_data = tst.content

    if nonce is not None and int(tst.tst_info['nonce']) != int(nonce):
        raise ValueError('nonce is different or missing')


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
        signer_hash_class = get_hash_class_from_oid(signer_digest_algorithm)
        # signer_hash_class = hashlib.sha256
        signer_hash_name = get_hash_from_oid(signer_digest_algorithm)
        content_digest = signer_hash_class(content).digest()
        for authenticated_attribute in authenticated_attributes:
            if authenticated_attribute[0] == id_attribute_messageDigest:
                try:
                    signed_digest = bytes(decoder.decode(bytes(authenticated_attribute[1][0]), asn1Spec=univ.OctetString())[0])
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

    backend = default_backend()
    with open('tsa.crt', 'rb') as f:
        crt_data = f.read()
        certificate = x509.load_pem_x509_certificate(crt_data, backend)

    # certificate = x509.load_der_x509_certificate(data_certificate, default_backend())

    public_key = certificate.public_key()
    hash_family = getattr(hashes, signer_hash_name.upper())
    public_key.verify(
        bytes(signature),
        signed_data,
        padding.PKCS1v15(),
        hash_family(),
    )
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

	# file_out = open('request.tsq', 'w')
	# file_out.write(tsq)
	# file_out.close()

	# Set up the parameters we want to pass to the API.
	# Make a get request with the parameters.
	headers = {'Content-type': 'application/timestamp-query'}
	http_response = requests.post("https://freetsa.org/tsr", headers=headers, data=tsq)

	tsr = http_response.content
	tsr, substrate = decoder.decode(tsr, asn1Spec=classes.TimeStampResp())

	print(tsr)
	token = tsr.time_stamp_token

	# UNIR TOKEN A PDF Y FIRMAR CON PADES
	# DESCARGAR EL ARCHIVO ???

	return "Alto pdf"

#@app.route('/descarga')
#def descarga():

#@app.route('/error')
#def error():

if __name__ == "__main__":
	app.run(host='0.0.0.0', port = 12345, debug=True)
