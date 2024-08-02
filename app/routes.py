from flask import Blueprint, request, jsonify, Flask
import logging
from flask_bcrypt import Bcrypt
from app.models import init_db, mysql
from app.config import Config
import MySQLdb.cursors
import jwt
import datetime

app = Flask(__name__)
# Configure logging 
logging.basicConfig(level=logging.INFO) 
logger = logging.getLogger(__name__)
bcrypt = Bcrypt(app)
app.config.from_object(Config)
init_db(app)
routes = Blueprint('routes', __name__)

def token_required(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(current_user, *args, **kwargs)
    return wrapper

@routes.route('/register', methods=['POST'])
def register():
    logger.info('API endpoint /register was called.')
    data = request.get_json()
    username = data['username']
    password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    role = data.get('role', 'regular')
    cursor = mysql.connection.cursor()
    cursor.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)', (username, password, role))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'User registered successfully!'})

@routes.route('/login', methods=['POST'])
def login():
    logger.info('API endpoint /login was called.')
    data = request.get_json()
    username = data['username']
    password = data['password']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    cursor.close()
    if user and bcrypt.check_password_hash(user['password'], password):
        token = jwt.encode({'user': user['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
        return jsonify({'token': token, 'role': user['role']})
    return jsonify({'message': 'Invalid credentials!'}), 401

@routes.route('/books', methods=['GET'])
def get_books():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM books')
    books = cursor.fetchall()
    cursor.close()
    return jsonify(books)

@routes.route('/books/<int:book_id>', methods=['GET'], endpoint='get_book')
def get_book(book_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM books WHERE id = %s', (book_id,))
    book = cursor.fetchone()
    cursor.execute('SELECT reviews.*, users.username FROM reviews JOIN users ON reviews.user_id = users.id WHERE book_id = %s', (book_id,))
    reviews = cursor.fetchall()
    cursor.close()
    return jsonify({'book': book, 'reviews': reviews})


@routes.route('/admin/books', methods=['POST'])
@token_required
def add_book(current_user):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT role FROM users WHERE username = %s', (current_user,))
    user = cursor.fetchone()
    if user['role'] != 'admin':
        return jsonify({'message': 'Permission denied!'}), 403
    data = request.get_json()
    title = data['title']
    author = data['author']
    description = data.get('description', '')
    image = data['image']
    cursor.execute('INSERT INTO books (title, author, description, image_link) VALUES (%s, %s, %s, %s)', (title, author, description, image))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'Book added successfully!'})

@routes.route('/admin/books/<int:book_id>', methods=['DELETE'], endpoint='delete_book')
@token_required
def delete_book(current_user, book_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT role FROM users WHERE username = %s', (current_user,))
    user = cursor.fetchone()
    if user['role'] != 'admin':
        return jsonify({'message': 'Permission denied!'}), 403
    cursor.execute('DELETE FROM books WHERE id = %s', (book_id,))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'Book deleted successfully!'})

@routes.route('/admin/books/<int:book_id>', methods=['PUT'], endpoint='update_book')
@token_required
def update_book(current_user, book_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT role FROM users WHERE username = %s', (current_user,))
    user = cursor.fetchone()
    if user['role'] != 'admin':
        return jsonify({'message': 'Permission denied!'}), 403
    data = request.get_json()
    title = data['title']
    author = data['author']
    image = data['image']
    description = data.get('description', '')
    cursor.execute('UPDATE books SET title = %s, author = %s, description = %s, image_link = %s WHERE id = %s', (title, author, description, image, book_id))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'Book updated successfully!'})

@routes.route('/reviews', methods=['POST'], endpoint='review_book')
@token_required
def add_review(current_user):
    data = request.get_json()
    book_id = data['book_id']
    review = data['review']
    logger.info('API endpoint /review was called.', review)
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT id FROM users WHERE username = %s', (current_user,))
    user = cursor.fetchone()
    cursor.execute('INSERT INTO reviews (book_id, user_id, review) VALUES (%s, %s, %s)', (book_id, user[0], review))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'Review added successfully!'})


app.register_blueprint(routes)

if __name__ == '__main__':
    app.run(debug=True)
