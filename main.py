import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_wtf import FlaskForm
from wtforms import TextAreaField
from wtforms.widgets import TextArea
from wtforms import StringField, SubmitField, PasswordField,URLField
from wtforms.validators import DataRequired, URL, Email
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
import stripe

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://mkqhuuyggdrsud:2cba679f94881aafac2caabc63ba69a4120b705237733a825fc7df7b7499c93d@ec2-44-199-143-43.compute-1.amazonaws.com:5432/ddlta6lgpatec0'

##CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shopping.db'


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin123@bookstore3.c0pa5dbxh2kl.us-east-1.rds.amazonaws.com:5432/yangpu2007360'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

b_list = []


def convert(original_list):
    unique_list = []
    num_list = []
    for item in original_list:
        if item not in unique_list:
            unique_list.append(item)

    for item in unique_list:
        num = 0

        for original in original_list:
            if item == original:
                num = num + 1

        num_list.append(num)

    return unique_list, num_list


# print(unique_list)
# print(num_list)

stripe.api_key = 'sk_test_51KJ5ImHZFCVh4WS7b6iQnnGBGISAyFcUp7Hh2HjB7LAESCRYuEoHFJcs5utfttumT0KCmRmKFHWRZUkMQO8v0ItH00ey40dBYm'


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("SIGN ME UP")

class UploadForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    summary = TextAreaField("Summary", validators=[DataRequired()], widget=TextArea())
    image = URLField("ImageURL", validators=[DataRequired()])
    submit = SubmitField("Add this book")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("LOG IN NOW")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))


class Book(db.Model):
    __tablename__ = "books"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), unique=False)
    summary = db.Column(db.String(100), unique=False)
    image = db.Column(db.String(100), unique=False)



class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    buyer = db.Column(db.String(100))
    title = db.Column(db.String(100), unique=False)
    created_at = db.Column(db.String(100),
                           # db.DateTime,
                           # default=datetime.datetime.now,
                           nullable=False)


db.create_all()

number_of_books = 0
@app.route('/')
def get_all_items():
    book_data = Book.query.all()
    global number_of_books
    number_of_books= len(book_data)
    print(book_data)
    return render_template("index.html", data=book_data)

@app.route('/admin', methods=["GET", "POST"])
def admin():
    form = UploadForm()
    if form.validate_on_submit():
        new_book = Book(
            id=number_of_books + 1,
            title=form.title.data,
            summary=form.summary.data,
            image=form.image.data,
        )
        db.session.add(new_book)
        db.session.commit()
        return redirect(url_for("get_all_items"))
    return render_template("addbook.html", form=form)



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            # Send flash messsage
            flash("You've already signed up with that email, log in instead!")
            # Redirect to /login route.
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_items"))
    return render_template("register.html", form=form)


login_manager = LoginManager()
login_manager.init_app(app)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email does not exist, please register.")
            return redirect(url_for('register'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_items'))
    return render_template("login.html", form=form)


@app.route('/contact')
def contact():
    return render_template("contact.html")


@app.route('/singlepage/<name>', methods=["GET", "POST"])
def singlepage(name):
    print(name)
    selected_book = Book.query.filter_by(title=name).one()

    print(selected_book)
    return render_template("singlepage.html", name=name, summary=selected_book)


@app.route("/cart/<name>", methods=["GET", "POST"])
def cart(name):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    else:

        b_list.append(name)
        print(f"Here is the current b_list: {b_list}")
        unique_list, num_list = convert(b_list)
        length = len(unique_list)
        return render_template("cart.html", list=unique_list, num_list=num_list, length=length,
                               numberofbooks=len(b_list))


@app.route("/delete/<name>", methods=["GET", "POST"])
def delete(name):
    b_list.remove(name)
    unique_list, num_list = convert(b_list)
    length = len(unique_list)
    return render_template("cart.html", list=unique_list, num_list=num_list, length=length,
                           numberofbooks=len(b_list))


@app.route("/see_cart")
def see_cart():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    else:
        unique_list, num_list = convert(b_list)
        length = len(unique_list)
        return render_template("cart.html", list=unique_list, num_list=num_list, length=length,
                               numberofbooks=len(b_list))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_items'))


@app.route('/history')
def history():
    # get the orders table and pass to template.
    order_history = Order.query.filter_by(buyer=current_user.name)
    #
    # stmt = sqlalchemy.select(orders).where(
    #     orders_table.c.user_id == id).where(likes_table.c.tweet_id == tid)

    return render_template("purchase_history.html", order_history=order_history)


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    books_to_purchase = ' '.join([str(book) for book in b_list])
    session = stripe.checkout.Session.create(
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'product_data': {
                    'name': books_to_purchase,
                },
                'unit_amount': 1000,
            },
            'quantity': len(b_list),
        }],
        mode='payment',
        success_url='https://pysimplebookstore.herokuapp.com/',
        cancel_url='https://example.com/cancel',
    )
    now = datetime.datetime.now()
    new_order = Order(
        buyer=current_user.name,
        title=books_to_purchase,
        created_at=now.strftime("%Y-%m-%d")
    )

    # new_order = {"buyer": current_user.name, "title": books_to_purchase}
    # insert_orders_query = orders_table.insert().values(new_order)

    db.session.add(new_order)
    # db.session.execute(insert_orders_query)
    db.session.commit()

    return redirect(session.url, code=303)


if __name__ == "__main__":
    # app.run(debug=True)
    app.run(host=os.getenv('IP', '0.0.0.0'),
            port=int(os.getenv('PORT', 4444)))
