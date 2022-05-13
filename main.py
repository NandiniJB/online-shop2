import requests.sessions
from flask import Flask, render_template, request, jsonify, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms.validators import DataRequired, Email, Length
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
# Set your secret key. Remember to switch to your live secret key in production.
# See your keys here: https://dashboard.stripe.com/apikeys
import stripe
stripe.api_key = "sk_test_51KprqHSCSbRylHqlC0Qghn29yhOXJRvOwwD4toZsqMXtclzh9WRYJF9AJymS4xsqacBgh5gWRgQvZ4bBe99Q6IMW00a0yZNXHi"

stripe.Customer.create(description="My First Test Customer")

app = Flask(__name__)
login_manager = LoginManager()

# Connect to Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.secret_key = "online-shopping-store-secret-key"
login_manager.init_app(app)


class RegistrationForm(FlaskForm):
    name = StringField(label='Name', validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    phone = StringField(label='Phone Number', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired(),
            Length(min=8, message='Password must have at least 8 characters')])
    submit = SubmitField(label="Register")


class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label="Login")


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    image_url = db.Column(db.String(120))
    price = db.Column(db.Integer)
    description = db.Column(db.String(500))

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.Integer, unique=True, nullable=False)


class OrderDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False)


class PaymentDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order_details.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    unique_id = db.Column(db.String(20), nullable=False)


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order_details.id'), nullable=True)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    user = db.relationship("User", backref="cart_item")
    product = db.relationship("Product", backref="cart_item")
    order_details = db.relationship("OrderDetails", backref="cart_item")


class ShippingAddress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    street = db.Column(db.String, nullable=False)
    city = db.Column(db.String, nullable=False)
    state = db.Column(db.String, nullable=False)
    country = db.Column(db.String, nullable=False)
    pincode = db.Column(db.String, nullable=False)


db.create_all()
all_products = Product.query.all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))


@app.route("/")
def home():
    form = LoginForm()
    # return jsonify(products=[product.to_dict() for product in all_products])
    name = ''
    if current_user.is_authenticated:
        user = User.query.get(current_user.get_id())
        name = user.name

    return render_template("index.html", products=all_products, form=form, logged_in=current_user.is_authenticated, username=name)


@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    loginForm = LoginForm()
    if form.validate_on_submit():
        data = request.form
        name = data['name']
        email = data['email']
        phone = data['phone']
        password = data['password']
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        user = User(name=name, email=email, password=hashed_password, phone=phone)
        db.session.add(user)
        db.session.commit()
        return render_template("index.html", products=all_products)
    name = ''
    if current_user.is_authenticated:
        user = User.query.get(current_user.get_id())
        name = user.name
    return render_template("register.html", form=form, loginForm=loginForm, logged_in=current_user.is_authenticated, username=name)


@app.route("/login", methods=["POST", "GET"])
def login():
    form = RegistrationForm()
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        data = request.form
        email = data['email']
        password = data['password']
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email doesn't exist")
            return redirect(url_for('login'))
        else:
            # Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Password incorrect")
                return redirect(url_for('login'))
    return render_template("login.html", loginForm=loginForm, form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/details/<int:id>")
@login_required
def details(id):
    product = Product.query.get(id)
    name = ''
    if current_user.is_authenticated:
        user = User.query.get(current_user.get_id())
        name = user.name
    return render_template("details.html", product=product, logged_in=current_user.is_authenticated, username=name)


@app.route("/cart", methods=["GET"])
@login_required
def cart():
    product_id = request.args.get('product_id')
    if product_id:
        cart_item = CartItem.query.filter_by(user_id=current_user.get_id(), product_id=product_id).first()
        if cart_item:
            cart_item.quantity += 1
            db.session.commit()
        else:
            cart_item = CartItem(user_id=current_user.get_id(), product_id=product_id, quantity=1, status='PROCESSING')
            db.session.add(cart_item)
            db.session.commit()
    cart_items = db.session.query(CartItem).join(Product, CartItem.product).\
        filter(CartItem.user_id == current_user.get_id()).filter(CartItem.status == 'PROCESSING').all()
    name = ''
    if current_user.is_authenticated:
        user = User.query.get(current_user.get_id())
        name = user.name
    return render_template("basket.html", cart_items=cart_items, logged_in=current_user.is_authenticated, username=name)


@app.route("/checkout_address", methods=["POST", "GET"])
@login_required
def checkout_address():
    cart_items = db.session.query(CartItem).join(Product, CartItem.product).filter(
        CartItem.user_id == current_user.get_id()).all()
    checkout_address = ShippingAddress.query.filter_by(user_id=current_user.get_id()).one_or_none()
    if request.method == 'POST':
        for cart_item in cart_items:
            cart_item.quantity = request.form[f'quantity-{cart_item.id}']
            db.session.commit()
    name = ''
    if current_user.is_authenticated:
        user = User.query.get(current_user.get_id())
        name = user.name
    return render_template("checkout-address.html", logged_in=current_user.is_authenticated, username=name, checkout_address=checkout_address)


@app.route("/checkout", methods=['POST'])
@login_required
def checkout():
    if request.method == 'POST':
        shipping_address = ShippingAddress.query.filter_by(user_id=current_user.get_id()).one_or_none()
        if shipping_address:
            shipping_address.firstname = request.form['firstname']
            shipping_address.lastname = request.form['lastname']
            shipping_address.street = request.form['street']
            shipping_address.city = request.form['city']
            shipping_address.state = request.form['state']
            shipping_address.country = request.form['country']
            shipping_address.pincode = request.form['pincode']
        else:
            firstname = request.form['firstname']
            lastname = request.form['lastname']
            street = request.form['street']
            city = request.form['city']
            state = request.form['state']
            country = request.form['country']
            pincode = request.form['pincode']
            shipping_address = ShippingAddress(user_id=current_user.get_id(), first_name=firstname, last_name=lastname, street=street, city=city, state=state, country=country, pincode=pincode)
            db.session.add(shipping_address)
        db.session.commit()

        cart_items = db.session.query(CartItem).join(Product, CartItem.product).filter(
            CartItem.user_id == current_user.get_id()).all()
        intent = stripe.PaymentIntent.create(
            currency="inr",
            amount=2000,
            payment_method_types=["card"],
            setup_future_usage="on_session",
        )
        name = ''
        if current_user.is_authenticated:
            user = User.query.get(current_user.get_id())
            name = user.name
    return render_template('checkout.html', client_secret=intent.client_secret, cart_items=cart_items, logged_in=current_user.is_authenticated, username=name)


# Backend APIs
@app.route("/users", methods=["POST"])
def add_user():
    data = request.form
    name = data['name']
    email = data['email']
    phone = data['phone']
    password = data['password']
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
    user = User(name=name, email=email, password=hashed_password, phone=phone)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Added User Successfully"})


@app.route("/products", methods=["POST"])
def add_product():
    data = request.form
    name = data['name']
    image_url = data['image_url']
    price = data['price']
    description = data['description']
    product = Product(name=name, image_url=image_url, price=price, description=description)
    db.session.add(product)
    db.session.commit()
    return jsonify({"message": "Product added successfully"})


@app.route('/create_checkout_session', methods=['POST'])
def create_checkout_session():
    amount = request.form['amount']
    user = User.query.get(current_user.get_id())
    order = OrderDetails(user_id=current_user.get_id(), amount=amount, status='PROCESSING')
    db.session.add(order)
    db.session.commit()
    cart_items = db.session.query(CartItem).join(Product, CartItem.product).filter(
        CartItem.user_id == current_user.get_id()).all()
    for cart_item in cart_items:
        cart_item.order_id = order.id
    db.session.commit()
    session = stripe.checkout.Session.create(
        line_items=[{
            'price_data': {
                'currency': 'inr',
                'product_data': {
                    'name': 'T-shirt',
                },
                'unit_amount': f"{amount}00",
            },
            'quantity': 1,
        }],
        mode='payment',
        customer_email=user.email,
        metadata={
            'order_id': order.id
        },
        success_url='http://localhost:5000/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url='http://localhost:5000/cancel.html',

    )

    # payment_details = PaymentDetails(order_id= )

    return redirect(session.url, code=303)


@app.route("/success", methods=['GET'])
@login_required
def success():
    session = stripe.checkout.Session.retrieve(request.args.get('session_id'))
    status = session.status
    order_id = session.metadata.order_id
    order = OrderDetails.query.get(order_id)
    order.status = status
    db.session.commit()
    cart_items = db.session.query(CartItem).filter(
        CartItem.order_id == order.id).all()
    for cart_item in cart_items:
        cart_item.status = status
    db.session.commit()
    payment_details = PaymentDetails(order_id=order_id, status=status, unique_id=session.payment_intent)
    db.session.add(payment_details)
    db.session.commit()
    name = ''
    if current_user.is_authenticated:
        user = User.query.get(current_user.get_id())
        name = user.name
    return render_template("success.html", logged_in=current_user.is_authenticated, username=name)


@app.route("/cart_item_delete/<int:id>")
def cart_item_delete(id):
    CartItem.query.filter_by(id=id).delete()
    db.session.commit()
    cart_items = db.session.query(CartItem).join(Product, CartItem.product).filter(
        CartItem.user_id == current_user.get_id()).all()

    name = ''
    if current_user.is_authenticated:
        user = User.query.get(current_user.get_id())
        name = user.name

    return render_template("basket.html", cart_items=cart_items, logged_in=current_user.is_authenticated,
                           username=name)



if __name__ == '__main__':
    app.run(debug=True)
