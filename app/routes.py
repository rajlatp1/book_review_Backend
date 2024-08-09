from flask import Blueprint, request, jsonify
from app import db, bcrypt
from app.models import User, Book, Review
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import logging

bp = Blueprint('routes', __name__)

logger = logging.getLogger(__name__)

@bp.route('/register', methods=['POST'])
def register():
    logger.info('API endpoint /register was called.')
    try:
        data = request.get_json()
        username = data['username']
        password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        role = data.get('role', 'regular')
        user = User(username=username, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        logger.info(f'User {username} registered successfully.')
        return jsonify({'message': 'User registered successfully!'})
    except Exception as e:
        logger.error(f'Error registering user: {e}')
        return jsonify({'message': 'Error registering user.'}), 500

@bp.route('/login', methods=['POST'])
def login():
    logger.info('API endpoint /login was called.')
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            token = create_access_token(identity={'username': user.username, 'role': user.role})
            logger.info(f'User {username} logged in successfully.')
            return jsonify({'token': token, 'role': user.role, 'user': user.username})
        logger.warning(f'Invalid login attempt for username: {username}')
        return jsonify({'message': 'Invalid credentials!'}), 401
    except Exception as e:
        logger.error(f'Error during login: {e}')
        return jsonify({'message': 'Error during login.'}), 500

@bp.route('/books', methods=['GET'])
def get_books():
    logger.info('API endpoint /books was called.')
    try:
        books = Book.query.all()
        result = [{'id': book.id, 'title': book.title, 'author': book.author, 'description': book.description, 'image_link': book.image_link} for book in books]
        logger.info('Books retrieved successfully.')
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error retrieving books: {e}')
        return jsonify({'message': 'Error retrieving books.'}), 500

@bp.route('/books/<int:book_id>', methods=['GET'])
def get_book(book_id):
    logger.info(f'API endpoint /books/{book_id} was called.')
    try:
        book = Book.query.get_or_404(book_id)
        reviews = Review.query.filter_by(book_id=book.id).all()
        review_list = [{'id': review.id, 'review': review.review, 'user': review.user.username} for review in reviews]
        logger.info(f'Book {book_id} retrieved successfully.')
        return jsonify({'book': {'id': book.id, 'title': book.title, 'author': book.author, 'description': book.description, 'image_link': book.image_link}, 'reviews': review_list})
    except Exception as e:
        logger.error(f'Error retrieving book {book_id}: {e}')
        return jsonify({'message': f'Error retrieving book {book_id}.'}), 500

@bp.route('/admin/books', methods=['POST'])
@jwt_required()
def add_book():
    logger.info('API endpoint /admin/books (POST) was called.')
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        logger.warning(f'Permission denied for user {current_user["username"]} to add book.')
        return jsonify({'message': 'Permission denied!'}), 403
    try:
        data = request.get_json()
        title = data['title']
        author = data['author']
        description = data.get('description', '')
        image_link = data['image']
        book = Book(title=title, author=author, description=description, image_link=image_link)
        db.session.add(book)
        db.session.commit()
        logger.info(f'Book {title} added successfully by {current_user["username"]}.')
        return jsonify({'message': 'Book added successfully!'})
    except Exception as e:
        logger.error(f'Error adding book: {e}')
        return jsonify({'message': 'Error adding book.'}), 500

@bp.route('/admin/books/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    logger.info(f'API endpoint /admin/books/{book_id} (DELETE) was called.')
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        logger.warning(f'Permission denied for user {current_user["username"]} to delete book {book_id}.')
        return jsonify({'message': 'Permission denied!'}), 403
    try:
        book = Book.query.get_or_404(book_id)
        db.session.delete(book)
        db.session.commit()
        logger.info(f'Book {book_id} deleted successfully by {current_user["username"]}.')
        return jsonify({'message': 'Book deleted successfully!'})
    except Exception as e:
        logger.error(f'Error deleting book {book_id}: {e}')
        return jsonify({'message': f'Error deleting book {book_id}.'}), 500

@bp.route('/admin/books/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    logger.info(f'API endpoint /admin/books/{book_id} (PUT) was called.')
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        logger.warning(f'Permission denied for user {current_user["username"]} to update book {book_id}.')
        return jsonify({'message': 'Permission denied!'}), 403
    try:
        book = Book.query.get_or_404(book_id)
        data = request.get_json()
        book.title = data['title']
        book.author = data['author']
        book.description = data.get('description', book.description)
        book.image_link = data['image']
        db.session.commit()
        logger.info(f'Book {book_id} updated successfully by {current_user["username"]}.')
        return jsonify({'message': 'Book updated successfully!'})
    except Exception as e:
        logger.error(f'Error updating book {book_id}: {e}')
        return jsonify({'message': f'Error updating book {book_id}.'}), 500

@bp.route('/reviews', methods=['POST'])
@jwt_required()
def add_review():
    logger.info('API endpoint /reviews (POST) was called.')
    current_user = get_jwt_identity()
    try:
        data = request.get_json()
        book_id = data['book_id']
        review_text = data['review']
        user = User.query.filter_by(username=current_user['username']).first()
        review = Review(book_id=book_id, user_id=user.id, review=review_text)
        db.session.add(review)
        db.session.commit()
        logger.info(f'Review added for book {book_id} by {current_user["username"]}.')
        return jsonify({'message': 'Review added successfully!'})
    except Exception as e:
        logger.error(f'Error adding review for book {book_id}: {e}')
        return jsonify({'message': 'Error adding review.'}), 500
