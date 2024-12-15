from functools import wraps

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import jwt
import time

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cd_collection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Country(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    alpha2 = db.Column(db.String(2), nullable=False, unique=True)
    alpha3 = db.Column(db.String(3), nullable=False, unique=True)
    region = db.Column(db.String(8), nullable=False, unique=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(), nullable=False)
    countryCode = db.Column(db.String(3), db.ForeignKey('countries.alpha2'), nullable=False)
    isPublic = db.Column(db.Boolean(), nullable=False)
    phone = db.Column(db.String(50), unique=True)
    image = db.Column(db.String(200))

with app.app_context():
    db.create_all()

@app.route('/api/ping', methods=['GET'])
def send():
    return jsonify({"status": "ok"}), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if data is None:
        return jsonify({'reason': 'Invalid JSON format'}), 400

    login = data.get('login', '')
    email = data.get('email', '')
    password = data.get('password', '')
    country_code = data.get('countryCode', '')
    is_public = data.get('isPublic', True)
    phone = data.get('phone', '')
    image = data.get('image', '')

    if not login or not email or not password or not country_code:
      return jsonify({'reason': 'missing data'}), 400

    if User.query.filter_by(login=login).first():
        return jsonify({'reason': 'User already exists'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'reason': 'User already exists'}), 400

    if len(password) >= 8:
        a = 0
        b = 0
        for i in range(len(password)):
            if password[i] == '#' or password[i] == '*' or password[i] == '%' or password[i] == '&' or password[i] == '!' or password[i] == '@' or password[i] == '$' or password[i] == '^' or password[i] == '(' or password[i] == ')' or password[i] == '-' or password[i] == '+':
                a = 1
            elif password[i] == '0' or password[i] == '1' or password[i] == '2' or password[i] == '3' or password[i] == '4' or password[i] == '5' or password[i] == '6' or password[i] == '7' or password[i] == '8' or password[i] == '9':
                b = 1
        if a != 1 or b != 1:
            return jsonify({'reason': 'Password is too bad'}), 400
    else:
        return jsonify({'reason': 'Password is too short'}), 400

    if not Country.query.filter_by(alpha2=country_code).first():
        return jsonify({'reason': 'No such country'}), 400

    if len(image) > 200:
        return jsonify({'reason': 'Image is too long'}), 400

    if phone[0] != '+':
        return jsonify({'reason': 'Invalid phone number'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(login=login,
                    email=email,
                    password=hashed_password,
                    country_code=country_code,
                    is_public=is_public,
                    phone=phone,
                    image=image
                )
    db.session.add(user)
    db.session.commit()
    return jsonify({'profile': user.to_dict()}), 200

def present_country(country):
    return {
        'id': country.id,
        'name': country.name
    }

def present_profile(user):
  return {
    'login': user.login,
    'email': user.email,
    'countryCode': user.countryCode,
    'is_public': user.is_Public,
    'phone': user.phone,
    'image': user.image
  }

@app.route('/api/countries', methods=['GET'])
def get_all_countries():
    regions = request.args.getlist('region')
    if not regions:
        countries = Country.query.all()
    else:
        countries = Country.query.filter(Country.region.in_(regions)).all()
    country_descriptions = [present_country(country) for country in countries]
    return jsonify(country_descriptions), 200

@app.route('/api/countries/<alpha2>', methods=['GET'])
def get_country_by_alpha2(alpha2):
    country = Country.query.filter_by(alpha2=alpha2).first()
    if not country:
        return jsonify({'reason': 'Country not found'}), 400
    return jsonify(present_country(country)), 200

@app.route('/api/countries', methods=['POST'])
def add_country():
    data = request.get_json()
    if data is None:
        return jsonify({'reason': 'Invalid JSON format'}), 400
    name = data.get('name')
    if not name:
        return jsonify({'reason': 'Missing name'}), 400
    if Country.query.filter_by(name=name).first():
        return jsonify({'reason': 'Country already exists'}), 400
    country = Country(name=name)
    db.session.add(country)
    db.session.commit()
    return jsonify(present_country(country)), 200

@app.route('/api/auth/sign-in', methods=['POST'])
def sign_in():
    data = request.get_json()

    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'error': 'Missing data'}), 400

    user = User.query.filter_by(login=login).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({'user_id': user.id, 'created_at': int(time.time())}, app.config['SECRET_KEY'],
                       algorithm='HS256')

    return jsonify({'token': token}), 200

def check_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return jsonify({'error': 'Missing token'}), 401

        try:
          payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401

        user_id = payload.get('user_id')
        created_at = payload.get('created_at')

        if not user_id or not created_at:
            return jsonify({'error': 'Invalid token'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 401

        if created_at + 60 * 60 * 24 < int(time.time()):
            return jsonify({'error': 'Token expired'}), 401

        return func(user, *args, **kwargs)
    return wrapper

@app.route('/api/me/profile', methods=['GET'])
@check_token
def get_profile(user):
    return jsonify(present_profile(user)), 200

@app.route('/api/me/profile', methods=['PATCH'])
@check_token
def edit_profile(user):
    data = request.get_json()

    if not Country.query.filter_by(alpha2=data.countryCode).first():
        return jsonify({'reason': 'No such country'}), 400

    if User.query.filter_by(phone=data.phone).first():
        return jsonify({'reason': 'Phone number is already used'}), 409

    if len(data.image) > 200:
        return jsonify({'reason': 'Image is too long'}), 400

    user.countryCode = data.countryCode
    user.isPublic = data.isPublic
    user.phone = data.phone
    user.image = data.image
    return jsonify(user), 200

@app.route('/api/profiles/<login>', methods=['GET'])
@check_token
def get_profile_by_login(user, login):
    if not login:
        return jsonify({'reason': 'Missing login'}), 403

    elif not User.query.filter_by(login=login).first():
        return jsonify({'reason': 'No such user'}), 403

    user_target = User.query.filter_by(login=login).first()

    # Еще должна быть проверка на друга, но мы не дошли до пункта с добавлением в друзья
    if not user_target.isPublic:
        return jsonify({'reason': 'You do not have permission to get this profile'}), 403

    return jsonify(present_profile(user_target)), 200

@app.route('/api/me/updatePassword', methods=['POST'])
@check_token
def change_password(user):
    data = request.get_json()
    if len(data.newPassword) >= 8:
        a = 0
        b = 0
        for i in range(len(data.newPassword)):
            if data.newPassword[i] == '#' or data.newPassword[i] == '*' or data.newPassword[i] == '%' or data.newPassword[i] == '&' or data.newPassword[i] == '!' or data.newPassword[i] == '@' or data.newPassword[i] == '$' or data.newPassword[i] == '^' or data.newPassword[i] == '(' or data.newPassword[i] == ')' or data.newPassword[i] == '-' or data.newPassword[i] == '+':
                a = 1
            elif data.newPassword[i] == '0' or data.newPassword[i] == '1' or data.newPassword[i] == '2' or data.newPassword[i] == '3' or data.newPassword[i] == '4' or data.newPassword[i] == '5' or data.newPassword[i] == '6' or data.newPassword[i] == '7' or data.newPassword[i] == '8' or data.newPassword[i] == '9':
              b = 1
        if a != 1 or b != 1:
            return jsonify({'reason': 'Password is too bad'}), 400
    else:
        return jsonify({'reason': 'Password is too short'}), 400

    if user.password != data.oldPassword:
        return jsonify({'reason': 'Old password does not match with current'}), 403

    user.password = data.newPassword
    return jsonify(present_profile(user), {'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(debug=True)
