from flask import Flask, request
from flask import jsonify
from flask_restful import Resource, Api
from werkzeug.serving import run_simple
from flask_restful import reqparse
import string

app = Flask(__name__)
api = Api(app)

# class HelloWorld(Resource):
#     def get(self):
#         return {'hello': 'world'}

class entrada(Resource):
	def get(self):
		# # print(self)
		# parser = reqparse.RequestParser()
		# parser.add_argument('hash', type=string, required=True)
		# args = parser.parse_args()
		# print("################################################################################")
		# print(args['hash'])
		args = request.args
		print (args) # For debugging
		no1 = args['hash']
		# no2 = args['MessageImprint']
		return jsonify(dict(data=[no1])) # or whatever is required

api.add_resource(entrada, '/')

if __name__ == '__main__':

	app.run(host='0.0.0.0', port = 12346, debug=True)