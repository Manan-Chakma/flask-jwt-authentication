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


@app.route('/login', methods=['POST'])
def login():
	auth = request.authorization
	if not auth or not auth.username or not auth.password:
		return make_response('could not verify', 401, {'Authentication': 'login required'})

	get_user_query = f"SELECT id, name, email, password from users where email= '{auth.username}';"
	cur = mysql.connection.cursor()
	cur.execute(get_user_query) # execute returns the number of rows effected during the query
	user = cur.fetchone() # returns tuple example ( 'Manan Chakma', '*****@gmail.com', 'the password')

	if user is None:
		return make_response('no user found', 401, {'Authentication': "login required"})

	user_id = user[0]
	user_password = user[3]
	if check_password_hash(user_password, auth.password):
		token = jwt.encode({'user_id': user_id, 'exp': datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=120)}, app.config['SECRET_KEY'], algorithm="HS256")
		return make_response('successlly logged in', 200, {'token': token})
	return make_response('password no not match', 401, {'Authentication': "login required"})


if __name__ == "__main__":
	app.run(debug = True)
