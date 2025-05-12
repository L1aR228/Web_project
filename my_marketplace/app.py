import os
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask import send_from_directory

# Инициализация приложения
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Инициализация базы данных
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Модели данных
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    # Связи
    products = db.relationship('Product', backref='owner', lazy=True)
    reviews = db.relationship('Review', backref='author', lazy=True)
    cart_items = db.relationship('Cart', backref='user', lazy=True)
    favorites = db.relationship('Favorite', backref='user', lazy=True)
    orders = db.relationship('Order', backref='customer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Product(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    images = db.relationship('ProductImage', backref='product', lazy=True, cascade='all, delete-orphan')

    categories = db.relationship('ProductCategory', backref='product', lazy=True, cascade='all, delete-orphan')
    reviews = db.relationship('Review', backref='product', lazy=True, cascade='all, delete-orphan')
    cart_items = db.relationship('Cart', backref='product', lazy=True, cascade='all, delete-orphan')
    favorites = db.relationship('Favorite', backref='product', lazy=True, cascade='all, delete-orphan')
    order_items = db.relationship('OrderItem', backref='product', lazy=True)

    def average_rating(self):
        avg = db.session.query(db.func.avg(Review.rating)).filter(
            Review.product_id == self.id
        ).scalar()
        return round(avg, 1) if avg else 0


class Category(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(80), unique=True, nullable=False)
    slug = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text)

    # Связи
    products = db.relationship('ProductCategory', backref='category', lazy=True, cascade='all, delete-orphan')


class ProductCategory(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    product_id = db.Column(db.String(36), db.ForeignKey('product.id'), nullable=False)
    category_id = db.Column(db.String(36), db.ForeignKey('category.id'), nullable=False)


class ProductImage(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    product_id = db.Column(db.String(36), db.ForeignKey('product.id'), nullable=False)
    is_main = db.Column(db.Boolean, default=False)  # Корректное определение
    image_path = db.Column(db.String(255), nullable=False)

class Review(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    product_id = db.Column(db.String(36), db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Cart(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.String(36), db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Favorite(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.String(36), db.ForeignKey('product.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Order(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, paid, shipped, delivered, cancelled
    shipping_address = db.Column(db.Text)
    payment_method = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Связи
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')


class OrderItem(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    order_id = db.Column(db.String(36), db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.String(36), db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)


# Вспомогательные функции
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        os.makedirs(os.path.dirname(upload_path), exist_ok=True)
        file.save(upload_path)
        return unique_filename  # Возвращаем только имя файла
    return None

def get_cart_data(user_id):
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    total_items = sum(item.quantity for item in cart_items)
    total_price = sum(item.product.price * item.quantity for item in cart_items)
    return {
        'cart_items': cart_items,  # Изменили с 'items' на 'cart_items'
        'total_items': total_items,
        'total_price': total_price
    }


# Маршруты аутентификации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Это имя пользователя уже занято', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Этот email уже зарегистрирован', 'error')
            return redirect(url_for('register'))

        user = User(
            username=username,
            email=email,
            phone=phone
        )
        user.set_password(password)

        # Первый пользователь - админ
        if User.query.count() == 0:
            user.is_admin = True

        db.session.add(user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('email_or_username')
        password = request.form.get('password')

        user = User.query.filter(
            (User.email == identifier) | (User.username == identifier)
        ).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('home'))

        flash('Неверный email/username или пароль', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


# Основные маршруты
@app.route('/')
def index():
    newest_products = Product.query.order_by(Product.created_at.desc()).limit(8).all()
    popular_categories = Category.query.limit(4).all()
    return render_template('index.html',
                         newest_products=newest_products,
                         popular_categories=popular_categories)


@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    products = Product.query.order_by(Product.created_at.desc()).all()
    cart_data = get_cart_data(session['user_id'])
    return render_template('home.html',
                           products=products,
                           cart_data=cart_data)


@app.route('/search')
def search():
    query = request.args.get('q', '')
    category_id = request.args.get('category', '')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    page = request.args.get('page', 1, type=int)
    per_page = 12

    products_query = Product.query

    if query:
        products_query = products_query.filter(
            (Product.name.ilike(f'%{query}%')) |
            (Product.description.ilike(f'%{query}%'))
        )

    if category_id:
        products_query = products_query.join(ProductCategory).filter(
            ProductCategory.category_id == category_id
        )

    if min_price is not None:
        products_query = products_query.filter(Product.price >= min_price)

    if max_price is not None:
        products_query = products_query.filter(Product.price <= max_price)

    products = products_query.paginate(page=page, per_page=per_page)

    categories = Category.query.all()
    cart_data = get_cart_data(session.get('user_id', ''))

    return render_template('search.html',
                           products=products,
                           categories=categories,
                           query=query,
                           selected_category=category_id,
                           min_price=min_price,
                           max_price=max_price,
                           cart_data=cart_data)


# Маршруты для работы с товарами
@app.route('/product/<product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    images = product.images
    reviews = product.reviews
    categories = [pc.category for pc in product.categories]

    # Проверка, есть ли товар в избранном
    is_favorite = False
    if 'user_id' in session:
        is_favorite = Favorite.query.filter_by(
            user_id=session['user_id'],
            product_id=product.id
        ).first() is not None

    # Похожие товары (из тех же категорий)
    similar_products = Product.query.join(ProductCategory).filter(
        ProductCategory.category_id.in_([c.id for c in categories]),
        Product.id != product.id
    ).distinct().limit(4).all()

    cart_data = get_cart_data(session.get('user_id', ''))

    return render_template('product_detail.html',
                           product=product,
                           images=images,
                           reviews=reviews,
                           categories=categories,
                           is_favorite=is_favorite,
                           similar_products=similar_products,
                           cart_data=cart_data)


@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # Получаем данные с проверкой на None
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            price_str = request.form.get('price', '')
            stock_str = request.form.get('stock', '1')

            # Проверка обязательных полей
            if not name or not description or not price_str:
                flash('Заполните все обязательные поля', 'error')
                return redirect(url_for('add_product'))

            try:
                price = float(price_str)
                stock = int(stock_str)
            except ValueError:
                flash('Некорректные числовые значения', 'error')
                return redirect(url_for('add_product'))

            if price <= 0:
                flash('Цена должна быть положительной', 'error')
                return redirect(url_for('add_product'))

            if stock <= 0:
                flash('Количество должно быть положительным', 'error')
                return redirect(url_for('add_product'))

            category_ids = request.form.getlist('categories')

            # Создаем продукт
            product = Product(
                name=name,
                description=description,
                price=price,
                stock=stock,
                owner_id=session['user_id']
            )

            db.session.add(product)
            db.session.flush()  # Получаем ID продукта

            # Добавляем категории
            for cat_id in category_ids:
                pc = ProductCategory(
                    product_id=product.id,
                    category_id=cat_id
                )
                db.session.add(pc)

            # Обработка изображений
            files = request.files.getlist('images')
            if not files or all(not file.filename for file in files):
                flash('Добавьте хотя бы одно изображение', 'error')
                return redirect(url_for('add_product'))

            for i, file in enumerate(files):
                if file and allowed_file(file.filename):
                    image_path = save_uploaded_file(file)
                    if image_path:
                        img = ProductImage(
                            product_id=product.id,
                            image_path=image_path,
                            is_main=(i == 0)
                        )
                        db.session.add(img)

            db.session.commit()
            flash('Товар успешно добавлен!', 'success')
            return redirect(url_for('product_detail', product_id=product.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при добавлении товара: {str(e)}', 'error')
            return redirect(url_for('add_product'))

    categories = Category.query.all()
    return render_template('add_product.html', categories=categories)


@app.route('/edit_product/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if 'user_id' not in session or (session['user_id'] != product.owner_id and not session.get('is_admin')):
        abort(403)

    if request.method == 'POST':
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = float(request.form.get('price'))
        product.stock = int(request.form.get('stock', 1))

        # Обновляем категории
        ProductCategory.query.filter_by(product_id=product.id).delete()
        for cat_id in request.form.getlist('categories'):
            pc = ProductCategory(
                product_id=product.id,
                category_id=cat_id
            )
            db.session.add(pc)

        # Добавляем новые изображения
        files = request.files.getlist('images')
        for file in files:
            if file and allowed_file(file.filename):
                image_path = save_uploaded_file(file)
                if image_path:
                    img = ProductImage(
                        product_id=product.id,
                        image_path=image_path
                    )
                    db.session.add(img)

        db.session.commit()
        flash('Товар успешно обновлен!', 'success')
        return redirect(url_for('product_detail', product_id=product.id))

    categories = Category.query.all()
    selected_categories = [pc.category_id for pc in product.categories]
    return render_template('edit_product.html',
                           product=product,
                           categories=categories,
                           selected_categories=selected_categories)


@app.route('/delete_product/<product_id>', methods=['POST'])
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    if 'user_id' not in session or (session['user_id'] != product.owner_id and not session.get('is_admin')):
        abort(403)

    db.session.delete(product)
    db.session.commit()
    flash('Товар успешно удален', 'success')
    return redirect(url_for('home'))


# Маршруты для корзины
@app.route('/cart')
def view_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cart_data = get_cart_data(session['user_id'])
    return render_template('cart.html', cart_data=cart_data)


@app.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)
    quantity = request.form.get('quantity', 1, type=int)

    if quantity > product.stock:
        flash('Недостаточно товара в наличии', 'error')
        return redirect(url_for('product_detail', product_id=product.id))

    cart_item = Cart.query.filter_by(
        user_id=session['user_id'],
        product_id=product.id
    ).first()

    if cart_item:
        if cart_item.quantity + quantity > product.stock:
            flash('Недостаточно товара в наличии', 'error')
        else:
            cart_item.quantity += quantity
            flash('Товар добавлен в корзину', 'success')
    else:
        cart_item = Cart(
            user_id=session['user_id'],
            product_id=product.id,
            quantity=quantity
        )
        db.session.add(cart_item)
        flash('Товар добавлен в корзину', 'success')

    db.session.commit()
    return redirect(url_for('product_detail', product_id=product.id))


@app.route('/update_cart/<cart_id>', methods=['POST'])
def update_cart(cart_id):
    cart_item = Cart.query.get_or_404(cart_id)

    if 'user_id' not in session or str(cart_item.user_id) != session['user_id']:
        abort(403)

    new_quantity = request.form.get('quantity', type=int)

    if new_quantity <= 0:
        db.session.delete(cart_item)
        flash('Товар удален из корзины', 'info')
    elif new_quantity > cart_item.product.stock:
        flash('Недостаточно товара в наличии', 'error')
    else:
        cart_item.quantity = new_quantity
        flash('Количество обновлено', 'success')

    db.session.commit()
    return redirect(url_for('view_cart'))


@app.route('/remove_from_cart/<cart_id>', methods=['POST'])
def remove_from_cart(cart_id):
    cart_item = Cart.query.get_or_404(cart_id)

    if 'user_id' not in session or str(cart_item.user_id) != session['user_id']:
        abort(403)

    db.session.delete(cart_item)
    db.session.commit()
    flash('Товар удален из корзины', 'info')
    return redirect(url_for('view_cart'))


# Маршруты для заказов
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    cart_data = get_cart_data(session['user_id'])

    # Исправленная проверка на пустую корзину
    if not cart_data['cart_items']:
        flash('Ваша корзина пуста', 'warning')
        return redirect(url_for('view_cart'))

    if request.method == 'POST':
        # Проверка наличия товаров
        for item in cart_data['cart_items']:
            if item.quantity > item.product.stock:
                flash(f'Товара "{item.product.name}" недостаточно в наличии', 'error')
                return redirect(url_for('view_cart'))

        # Создание заказа
        order = Order(
            user_id=session['user_id'],
            total_amount=cart_data['total_price'],
            shipping_address=request.form.get('shipping_address'),
            payment_method=request.form.get('payment_method')
        )
        db.session.add(order)
        db.session.flush()  # Получаем ID заказа

        # Добавление товаров в заказ
        for item in cart_data['cart_items']:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item.product_id,
                quantity=item.quantity,
                price=item.product.price
            )
            db.session.add(order_item)
            item.product.stock -= item.quantity  # Уменьшение количества на складе

        # Очистка корзины
        Cart.query.filter_by(user_id=session['user_id']).delete()

        db.session.commit()
        return redirect(url_for('order_confirmation', order_id=order.id))

    return render_template('checkout.html', cart_data=cart_data, user=user)

@app.route('/order_confirmation/<order_id>')
def order_confirmation(order_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    order = Order.query.get_or_404(order_id)

    if str(order.user_id) != session['user_id'] and not session.get('is_admin'):
        abort(403)

    return render_template('order_confirmation.html', order=order)


@app.route('/orders')
def view_orders():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    orders = Order.query.filter_by(user_id=session['user_id']).order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=orders)


# Маршруты для избранного
@app.route('/favorites')
def view_favorites():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    favorites = Favorite.query.filter_by(user_id=session['user_id']).all()
    products = [fav.product for fav in favorites]
    return render_template('favorites.html', products=products)


@app.route('/toggle_favorite/<product_id>', methods=['POST'])
def toggle_favorite(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    favorite = Favorite.query.filter_by(
        user_id=session['user_id'],
        product_id=product_id
    ).first()

    if favorite:
        db.session.delete(favorite)
        message = 'Товар удален из избранного'
    else:
        favorite = Favorite(
            user_id=session['user_id'],
            product_id=product_id
        )
        db.session.add(favorite)
        message = 'Товар добавлен в избранное'

    db.session.commit()
    return jsonify({'success': True, 'message': message})


# Маршруты для отзывов
@app.route('/add_review/<product_id>', methods=['POST'])
def add_review(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)
    rating = request.form.get('rating', type=int)
    text = request.form.get('text', '').strip()

    if not (1 <= rating <= 5):
        flash('Некорректная оценка', 'error')
        return redirect(url_for('product_detail', product_id=product.id))

    # Проверяем, не оставлял ли пользователь уже отзыв
    existing_review = Review.query.filter_by(
        user_id=session['user_id'],
        product_id=product.id
    ).first()

    if existing_review:
        flash('Вы уже оставляли отзыв на этот товар', 'error')
        return redirect(url_for('product_detail', product_id=product.id))

    review = Review(
        product_id=product.id,
        user_id=session['user_id'],
        rating=rating,
        text=text
    )

    db.session.add(review)
    db.session.commit()
    flash('Спасибо за ваш отзыв!', 'success')
    return redirect(url_for('product_detail', product_id=product.id))


# Админ-маршруты
@app.route('/admin/categories')
def admin_categories():
    if not session.get('is_admin'):
        abort(403)

    categories = Category.query.order_by(Category.name).all()
    return render_template('admin_categories.html', categories=categories)


@app.route('/admin/add_category', methods=['POST'])
def add_category():
    if not session.get('is_admin'):
        abort(403)

    name = request.form.get('name')
    description = request.form.get('description')

    if not name:
        flash('Название категории обязательно', 'error')
        return redirect(url_for('admin_categories'))

    slug = name.lower().replace(' ', '-')

    if Category.query.filter_by(slug=slug).first():
        flash('Категория с таким названием уже существует', 'error')
        return redirect(url_for('admin_categories'))

    category = Category(
        name=name,
        slug=slug,
        description=description
    )

    db.session.add(category)
    db.session.commit()
    flash('Категория успешно добавлена', 'success')
    return redirect(url_for('admin_categories'))


@app.route('/admin/delete_category/<category_id>', methods=['POST'])
def delete_category(category_id):
    if not session.get('is_admin'):
        abort(403)

    category = Category.query.get_or_404(category_id)

    # Проверяем, есть ли товары в этой категории
    if ProductCategory.query.filter_by(category_id=category.id).count() > 0:
        flash('Нельзя удалить категорию, в которой есть товары', 'error')
        return redirect(url_for('admin_categories'))

    db.session.delete(category)
    db.session.commit()
    flash('Категория успешно удалена', 'success')
    return redirect(url_for('admin_categories'))


# Обработчики ошибок
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500
@app.route('/test_images')
def test_images():
    return """
    <form method=post enctype=multipart/form-data action="/add_product">
        <input type=file name=images multiple>
        <input type=submit>
    </form>
    """
@app.route('/test_upload')
def test_upload():
    return """
    <form method=post enctype=multipart/form-data action="/add_product">
        <input type=file name=images>
        <input type=submit>
    </form>
    <img src="/uploads/test.jpg">  <!-- Проверочное изображение -->
    """
@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# Запуск приложения
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)