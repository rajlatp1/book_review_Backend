from flask import Blueprint, request, jsonify
from app import db, bcrypt
from app.models import User, Book, Review, Cart, Order, OrderItem
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
        result = [{'id': book.id, 'title': book.title, 'author': book.author, 'description': book.description, 'price': str(book.price), 'stock': book.stock, 'image_link': book.image_link} for book in books]
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
        return jsonify({'book': {'id': book.id, 'title': book.title, 'author': book.author, 'description': book.description, 'price': str(book.price), 'stock': book.stock, 'image_link': book.image_link}, 'reviews': review_list})
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
        price = data['price']
        stock = data.get('stock', 0)
        image_link = data['image']
        book = Book(title=title, author=author, description=description, price=price, stock=stock, image_link=image_link)
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
        book.price = data['price']
        book.stock = data['stock']
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

@bp.route('/cart', methods=['GET'])
@jwt_required()
def get_cart():
    logger.info('API endpoint /cart (GET) was called.')
    current_user = get_jwt_identity()
    try:
        user = User.query.filter_by(username=current_user['username']).first()
        cart_items = Cart.query.filter_by(user_id=user.id).all()
        result = [{'id':item.id, 'book_id': item.book_id, 'title': item.book.title, 'quantity': item.quantity, 'price': str(item.book.price),'image_link':item.book.image_link} for item in cart_items]
        logger.info(f'Cart items retrieved successfully for user {current_user["username"]}.')
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error retrieving cart items for user {current_user["username"]}: {e}')
        return jsonify({'message': 'Error retrieving cart items.'}), 500

@bp.route('/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    logger.info('API endpoint /cart (POST) was called.')
    current_user = get_jwt_identity()
    try:
        data = request.get_json()
        book_id = data['book_id']
        quantity = data['quantity']
        
        # Check if the book exists and has enough stock
        book = Book.query.get_or_404(book_id)
        if book.stock < quantity:
            return jsonify({'message': 'Not enough stock available!'}), 400
        
        user = User.query.filter_by(username=current_user['username']).first()
        cart_item = Cart.query.filter_by(user_id=user.id, book_id=book_id).first()
        
        if cart_item:
            # Update the quantity if the item is already in the cart
            cart_item.quantity += quantity
        else:
            cart_item = Cart(user_id=user.id, book_id=book_id, quantity=quantity)
            db.session.add(cart_item)
        
        db.session.commit()
        logger.info(f'Book {book_id} added to cart for user {current_user["username"]}.')
        return jsonify({'message': 'Book added to cart successfully!'})
    except Exception as e:
        logger.error(f'Error adding book {book_id} to cart for user {current_user["username"]}: {e}')
        return jsonify({'message': 'Error adding to cart.'}), 500

@bp.route('/cart/<int:cart_id>', methods=['DELETE'])
@jwt_required()
def remove_from_cart(cart_id):
    logger.info(f'API endpoint /cart/{cart_id} (DELETE) was called.')
    current_user = get_jwt_identity()
    try:
        cart_item = Cart.query.get_or_404(cart_id)
        if cart_item.user.username != current_user['username']:
            logger.warning(f'Permission denied for user {current_user["username"]} to remove cart item {cart_id}.')
            return jsonify({'message': 'Permission denied!'}), 403

        db.session.delete(cart_item)
        db.session.commit()
        logger.info(f'Cart item {cart_id} removed successfully for user {current_user["username"]}.')
        return jsonify({'message': 'Cart item removed successfully!'})
    except Exception as e:
        logger.error(f'Error removing cart item {cart_id} for user {current_user["username"]}: {e}')
        return jsonify({'message': 'Error removing cart item.'}), 500

@bp.route('/checkout', methods=['POST'])
@jwt_required()
def checkout():
    logger.info('API endpoint /checkout (POST) was called.')
    current_user = get_jwt_identity()
    try:
        user = User.query.filter_by(username=current_user['username']).first()
        cart_items = Cart.query.filter_by(user_id=user.id).all()
        
        if not cart_items:
            return jsonify({'message': 'Cart is empty!'}), 400
        
        total_amount = sum([item.book.price * item.quantity for item in cart_items])
        
        # Create a new order
        order = Order(user_id=user.id, total_amount=total_amount)
        db.session.add(order)
        db.session.commit()
        
        # Add items to the order and update stock
        for item in cart_items:
            order_item = OrderItem(order_id=order.id, book_id=item.book_id, quantity=item.quantity, price=item.book.price)
            db.session.add(order_item)
            item.book.stock -= item.quantity
        
        # Clear the cart
        Cart.query.filter_by(user_id=user.id).delete()
        
        db.session.commit()
        logger.info(f'Order {order.id} created successfully for user {current_user["username"]}.')
        return jsonify({'message': 'Order placed successfully!'})
    except Exception as e:
        logger.error(f'Error during checkout for user {current_user["username"]}: {e}')
        return jsonify({'message': 'Error during checkout.'}), 500
