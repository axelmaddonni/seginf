from flask import Flask, render_template, request
import pdfkit
import hashlib

app = Flask(__name__)

@app.route("/")
def main():
	return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
	first_name = request.form['nombre']
	webSite = request.form['webSite']

	#pdfkit.from_url(webSite, 'out.pdf')
	#return hashlib.sha256('EL pdf').hexdigest()

	#Hay que mandar el hash a la API rest de la tsa
	#Firmar lo que devuelve la tsa con paddes
	# Hacer que se pueda descargar

	#descarga(pdf) o error(pdf)
	return 'submit %s %s <br/> <a href="/">Back Home</a>' % (first_name, webSite)

#@app.route('/descarga')
#def descarga():

#@app.route('/error')
#def error():

if __name__ == "__main__":
    app.run()
