from flask import Flask, render_template, request, make_response
import pdfkit
import mypdfsigner

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
	pdf = pdfkit.from_url(webSite, "tmp/output.pdf")

	inputPath = "tmp/output.pdf"
	outputPath = "tmp/signed.pdf"
	password = "" # if non empty document will also be encrypted
	location = "Buenos Aires"
	reason = "TSA Timestamping"
	visible = True
	certify = True
	timestamp = True
	title = "Python Title"
	author = "Python Author"
	subject = "Python subject"
	keywords = "Python keywords"
	confFile = "/home/axel/.mypdfsigner"

	signResult = mypdfsigner.add_metadata_sign(inputPath, outputPath, password, location, reason, visible, certify, timestamp, title, author, subject, keywords, confFile)

	verifyResult = mypdfsigner.verify(outputPath, confFile)

	signedPdf = open("tmp/signed.pdf", 'r').read()
	return showPdf(signedPdf, 'altopdf.pdf')

#@app.route('/descarga')
#def descarga():

#@app.route('/error')
#def error():

if __name__ == "__main__":
	app.run(host='0.0.0.0', port = 12345, debug=True)