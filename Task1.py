from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt
import datetime
from functools import wraps
import os
import base64
import pyotp
import qrcode
from io import BytesIO

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  
app.config['MYSQL_DB'] = 'infosec_api'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  
app.config['SECRET_KEY'] = 'your_secret_key'

mysql = MySQL(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = pyjwt.decode(token.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = data['id']
        except:
            return jsonify({'message': 'Invalid token!'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/signup', methods=['POST'])
def signup():
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        print("Received Data:", data) 

        if not data or 'name' not in data or 'username' not in data or 'password' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        
        # Generate a secret key for Google Authenticator
        secret = pyotp.random_base32()
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (name, username, password, totp_secret) VALUES (%s, %s, %s, %s)",
                    (data['name'], data['username'], hashed_password, secret))
        mysql.connection.commit()
        user_id = cur.lastrowid
        cur.close()

        # Generate provisioning URI for QR code
        totp = pyotp.totp.TOTP(secret).provisioning_uri(name=data['username'], issuer_name="Infosec API")
        
        # Generate QR code
        img = qrcode.make(totp)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({
            'message': 'User registered successfully',
            'qr_code': img_str,
            'secret': secret  # In production, you might not want to return the secret
        }), 201

    except Exception as e:
        print("Error:", str(e))  
        return jsonify({'error': str(e)}), 500

@app.route('/setup-2fa', methods=['GET'])
@token_required
def setup_2fa():
    try:
        user_id = request.user_id
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT username, totp_secret FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()

        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        if not user['totp_secret']:
            # Generate new secret if not exists
            secret = pyotp.random_base32()
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET totp_secret = %s WHERE id = %s", (secret, user_id))
            mysql.connection.commit()
            cur.close()
        else:
            secret = user['totp_secret']
        
        # Generate provisioning URI for QR code
        totp = pyotp.totp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name="Infosec API")
        
        # Generate QR code
        img = qrcode.make(totp)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({
            'qr_code': img_str,
            'secret': secret  # In production, consider not returning the secret
        }), 200

    except Exception as e:
        print("Error:", str(e))  
        return jsonify({'error': str(e)}), 500

@app.route('/verify-2fa', methods=['POST'])
@token_required
def verify_2fa():
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        if not data or 'code' not in data:
            return jsonify({'message': 'Missing verification code'}), 400

        user_id = request.user_id
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT totp_secret FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()

        if not user or not user['totp_secret']:
            return jsonify({'message': '2FA not setup for this user'}), 400

        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(data['code']):
            # Generate a token that indicates 2FA was completed
            token = pyjwt.encode(
                {
                    'id': user_id, 
                    '2fa_verified': True,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                },
                app.config['SECRET_KEY'], 
                algorithm='HS256'
            )
            return jsonify({'token': token, 'message': '2FA verification successful'})
        else:
            return jsonify({'message': 'Invalid verification code'}), 401

    except Exception as e:
        print("Error:", str(e))  
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        print("Received Data:", data)  

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
        user = cur.fetchone()
        cur.close()

        if not user:
            return jsonify({'message': 'Invalid username or password'}), 401

        if not check_password_hash(user['password'], data['password']):
            return jsonify({'message': 'Invalid username or password'}), 401

        # Check if user has 2FA enabled
        if user['totp_secret']:
            # Return a temporary token that requires 2FA verification
            token = pyjwt.encode(
                {'id': user['id'], '2fa_required': True, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)},
                app.config['SECRET_KEY'], 
                algorithm='HS256'
            )
            return jsonify({
                'token': token,
                'message': '2FA required',
                '2fa_required': True
            })
        else:
            # No 2FA required, return normal token
            token = pyjwt.encode(
                {'id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                app.config['SECRET_KEY'], 
                algorithm='HS256'
            )
            return jsonify({'token': token, '2fa_required': False})

    except Exception as e:
        print("Error:", str(e))  
        return jsonify({'error': str(e)}), 500

# Protected routes with 2FA verification check
def twofa_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = pyjwt.decode(token.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
            if '2fa_verified' not in data or not data['2fa_verified']:
                return jsonify({'message': '2FA verification required!'}), 403
            request.user_id = data['id']
        except:
            return jsonify({'message': 'Invalid token!'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/users/<int:id>', methods=['PUT'])
@token_required
@twofa_required
def update_user(id):
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400

        data = request.get_json()
        print("Received Data:", data)  

        if not data or 'name' not in data or 'username' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET name=%s, username=%s WHERE id=%s", 
                    (data['name'], data['username'], id))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'User updated successfully'}), 200

    except Exception as e:
        print("Error:", str(e)) 
        return jsonify({'error': str(e)}), 500

# Other product routes with 2FA protection
@app.route('/products', methods=['POST'])
@token_required
@twofa_required
def add_product():
    data = request.json
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO products (pname, description, price, stock, created_at) VALUES (%s, %s, %s, %s, NOW())", (data['pname'], data['description'], data['price'], data['stock']))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Product added successfully'})

@app.route('/products', methods=['GET'])
@token_required
@twofa_required
def get_products():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    cur.close()
    return jsonify(products)

@app.route('/products/<int:pid>', methods=['GET'])
@token_required
@twofa_required
def get_product(pid):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products WHERE pid = %s", (pid,))
    product = cur.fetchone()
    cur.close()
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    return jsonify(product)

@app.route('/products/<int:pid>', methods=['PUT'])
@token_required
@twofa_required
def update_product(pid):
    data = request.json
    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET pname=%s, description=%s, price=%s, stock=%s WHERE pid=%s", (data['pname'], data['description'], data['price'], data['stock'], pid))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Product updated successfully'})

@app.route('/products/<int:pid>', methods=['DELETE'])
@token_required
@twofa_required
def delete_product(pid):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM products WHERE pid = %s", (pid,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Product deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)
