from flask import Flask, render_template, request, make_response
import pdfkit
import mypdfsigner
import datetime
import random
import os
from OpenSSL import SSL

app = Flask(__name__)

def showPdf(pdfBinary, fileName):
	response = make_response(pdfBinary)
	response.headers['Content-Type'] = 'application/pdf'
	response.headers['Content-Disposition'] = 'inline; filename=%s.pdf' % fileName
	return response

@app.route("/")
def main():
	return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():

	# Agarro los datos que completo el usuario
	first_name = request.form['nombre']
	webSite = request.form['webSite']
 
	fileID = ""
	d = datetime.datetime.now()
	for attr in [ 'year', 'month', 'day', 'hour', 'minute', 'second', 'microsecond']:
		fileID = fileID + str(getattr(d, attr)) + str(random.randint(0, 9999999))

	try: 
		pdf = pdfkit.from_url(webSite, "tmp/screenshot" + fileID + ".pdf")
	except: 
		return error("URL invalida. No se pudo obtener el screenshot.")

	inputPath = "tmp/screenshot" + fileID + ".pdf"
	outputPath = "tmp/signed" + fileID + ".pdf"
	password = "" # if non empty document will also be encrypted
	location = "Buenos Aires"
	reason = "TSA Timestamping"
	visible = True
	certify = False
	timestamp = True
	title = "Signed Screenshot"
	author = first_name
	subject = "TimeStamping"
	keywords = "tsa"
	confFile = "/home/tpseginf/.mypdfsigner"

	signResult = mypdfsigner.add_metadata_sign(inputPath, outputPath, password, location, reason, visible, certify, timestamp, title, author, subject, keywords, confFile)

	os.remove(inputPath)

	if(signResult[0] != str(0)):
		print("signResult")
		print(signResult)
		return error("Error al firmar el PDF.")


	verifyResult = mypdfsigner.verify(outputPath, confFile)

	if(verifyResult[0] != str(0)):
		print("verifyResult")
		print(verifyResult)
		return error("Error al firmar el PDF.")

	signedPdf = open(outputPath, 'r').read()

	os.remove(outputPath)

	return showPdf(signedPdf, 'SignedPDF.pdf')

@app.route('/error')
def error(descripcion=None):
	return render_template('error.html', descripcion=descripcion)

if __name__ == "__main__":
	app.run(host='0.0.0.0', port = 12345, debug=True, ssl_context=('cert/certificate.pem', 'cert/key.pem'))