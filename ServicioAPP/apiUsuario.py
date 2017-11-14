from flask import Flask, render_template, request, make_response
import pdfkit
import hashlib
from werkzeug.serving import run_simple
import requests

app = Flask(__name__)

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

	hashPdf = hashlib.sha256(pdf).hexdigest()
	#return hashPdf

	#Mandar el hash a la API rest de la tsa:

	# Set up the parameters we want to pass to the API.
	parameters = {"hash": hashPdf}
	# Make a get request with the parameters.
	response = requests.get("http://0.0.0.0:12346/", params=parameters)
	print(response)
	# Print the content of the response (the data the server returned)
	resultadoAFirmar = response.content
	return resultadoAFirmar
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