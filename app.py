from flask import Flask, jsonify, request, make_response
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import time

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'HOSTNAME'
app.config['MYSQL_USER'] = 'USER_NAME'
app.config['MYSQL_PASSWORD'] = 'PASSWORD'
app.config['MYSQL_DB'] = 'DB_NAME'
app.config['MYSQL_PORT'] = 3306
mysql = MySQL(app)

app.config['SECRET_KEY'] = 'SECRET_KEY'



class JWTManager(object):

	__secret_key = app.config['SECRET_KEY']


	def __init__(self, **kwargs):
		for k,v in kwargs.items():
			setattr(self, k, v)


	
	def login_jwt_encode(self):
		return jwt.encode({'user_id': self.user_id, 'exp': self.exp_time}, self.__secret_key, algorithm=self.algorithm)



@app.route('/register', methods=['POST'])
def register():
	data = request.get_json()
	name = data['name']
	email = data['email']
	hashed_password = generate_password_hash(data['password'], method='sha256')
	create_user_query = f"INSERT INTO users (name, email, password) VALUES ('{name}', '{email}', '{hashed_password}');"
	cur = mysql.connection.cursor()
	cur.execute(create_user_query)
	mysql.connection.commit()
	cur.close()
	return make_response('successfully registered', 200)



def field_validation(fun):
	def wrapper():
		auth = request.authorization
		if not auth or not auth.username or not auth.password:
			return make_response('could not verify', 401, {'Authentication': 'login required'})
		return fun()

	return wrapper


@app.route('/login', methods=['POST'])
@field_validation
def login():
	auth = request.authorization
	get_user_query = f"SELECT id, name, email, password from users where email= '{auth.username}';"
	cur = mysql.connection.cursor()
	cur.execute(get_user_query) # execute returns the number of rows effected during the query
	user = cur.fetchone() # returns tuple example ( 'Manan Chakma', '*****@gmail.com', 'the password')

	if user is None:
		return make_response('no user found', 401, {'Authentication': "login required"})

	user_id = user[0]
	user_password = user[3]
	if check_password_hash(user_password, auth.password):
		token_manager = JWTManager(user_id = user_id, exp_time = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=120), algorithm = "HS256")
		token = token_manager.login_jwt_encode()
		return make_response('successlly logged in', 200, {'token': token})
	return make_response('password no not match', 401, {'Authentication': "login required"})
	app.run(debug = True)
