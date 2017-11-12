from flask import Flask, render_template, request
import pdfkit
import hashlib

app = Flask(__name__)

@app.route("/")
def main():
	return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
	# Agarro los datos que completo el usuario
	first_name = request.form['nombre']
	webSite = request.form['webSite']

	# Genero el PDF de la pagina y lo hasheo 
	pdf = pdfkit.from_url(webSite, False)
	hashPdf = hashlib.sha256(pdf).hexdigest()
	

	#Mandar el hash a la API rest de la tsa:
	
	## Set up the parameters we want to pass to the API.
	#parameters = {"hash": hashPdf}
	## Make a get request with the parameters.
	#response = requests.get("URL de la API", params=parameters)
	## Print the content of the response (the data the server returned)
	#resultadoAFirmar = response.content

	#Firmar lo que devuelve la tsa con paddes
	#Hacer que se pueda descargar

	#descarga(pdf) o error(pdf)
	#return 'submit %s %s <br/> <a href="/">Back Home</a>' % (first_name, webSite)

#@app.route('/descarga')
#def descarga():

#@app.route('/error')
#def error():

if __name__ == "__main__":
    app.run()
