import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'ваш секретный ключ'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.String, primary_key=True)
    username = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    contact_info = db.Column(db.String)


class Product(db.Model):
    id = db.Column(db.String, primary_key=True)
    name = db.Column(db.String)
    description = db.Column(db.String)
    price = db.Column(db.Float)
    owner_id = db.Column(db.String, db.ForeignKey('user.id'))


class ProductImage(db.Model):
    id = db.Column(db.String, primary_key=True)
    product_id = db.Column(db.String, db.ForeignKey('product.id'))
    image_path = db.Column(db.String)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        contact = request.form['contact']
        password = request.form['password']
        user_id = str(uuid.uuid4())
        user = User(id=user_id, username=contact, contact_info=contact, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        contact = request.form['contact']
        password = request.form['password']
        user = User.query.filter_by(contact_info=contact).first()
        if user and user.password == password:
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('home'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        product_id = str(uuid.uuid4())
        product = Product(id=product_id, name=name, description=description, price=price, owner_id=session['user_id'])
        db.session.add(product)
        db.session.commit()
        files = request.files.getlist('images')
        for file in files:
            if file:
                filename = secure_filename(file.filename)
                if filename:
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    file.save(filepath)
                    relative_path = os.path.join('uploads', filename)
                    img = ProductImage(id=str(uuid.uuid4()), product_id=product_id, image_path=relative_path)
                    db.session.add(img)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add_product.html')


@app.route('/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    product = Product.query.get(product_id)
    if product:
        ProductImage.query.filter_by(product_id=product_id).delete()
        db.session.delete(product)
        db.session.commit()
    return redirect(url_for('home'))


@app.route('/')
def home():
    products = Product.query.all()
    products_with_owner = []
    for p in products:
        owner = User.query.get(p.owner_id)
        images = ProductImage.query.filter_by(product_id=p.id).all()
        products_with_owner.append({'product': p, 'owner': owner, 'images': images})
    return render_template('home.html', products=products_with_owner)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
