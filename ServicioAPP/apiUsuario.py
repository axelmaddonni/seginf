from flask import Flask, render_template, request, make_response
import pdfkit
import mypdfsigner
import datetime
import random
import os

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

	# Genero el PDF de la pagina y lo hasheo 
	fileID = ""
	d = datetime.datetime.now()
	for attr in [ 'year', 'month', 'day', 'hour', 'minute', 'second', 'microsecond']:
		fileID = fileID + str(getattr(d, attr)) + str(random.randint(0, 9999999))

	pdf = pdfkit.from_url(webSite, "tmp/screenshot" + fileID + ".pdf")

	inputPath = "tmp/screenshot" + fileID + ".pdf"
	outputPath = "tmp/signed" + fileID + ".pdf"
	password = "" # if non empty document will also be encrypted
	location = "Buenos Aires"
	reason = "TSA Timestamping"
	visible = True
	certify = True
	timestamp = True
	title = "Signed Screenshot"
	author = first_name
	subject = "TimeStamping"
	keywords = "tsa"
	confFile = "/home/axel/.mypdfsigner"

	print("signing")
	signResult = mypdfsigner.add_metadata_sign(inputPath, outputPath, password, location, reason, visible, certify, timestamp, title, author, subject, keywords, confFile)

	#Elimino el pdf de la screenshot para no llenar el servidor de temporales
	#os.remove(inputPath)

	print("signResult")
	print(signResult)

	verifyResult = mypdfsigner.verify(outputPath, confFile)

	print("verifyResult")
	print(verifyResult)

	signedPdf = open(outputPath, 'r').read()
	return showPdf(signedPdf, 'altopdf.pdf')

	#Elimino el pdf de output para no llenar el servidor de temporales
	#os.remove(outputPath)

# TO DO
#@app.route('/error')
#def error():

if __name__ == "__main__":
	app.run(host='0.0.0.0', port = 12345, debug=True)