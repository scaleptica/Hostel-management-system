from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_cachecontrol import (
    cache,
    cache_for,
    dont_cache,
    Always, 
    ResponseIsSuccessfulOrRedirect)


app = Flask(__name__)
bcrypt = Bcrypt(app)
db  = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS'] = {
    'hostel': 'sqlite:///hostel_data.db',
}
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Hostel(db.Model):
    __bind_key__ = 'hostel'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(2), nullable=False, unique=True)
    warden = db.Column(db.String(20), nullable=False)
    caretaker_name = db.Column(db.String(20), nullable=False)
    caretaker_email = db.Column(db.String(20), nullable=False, unique=True)
    caretaker_no = db.Column(db.String(20), nullable=False, unique=True)
    ni_caretaker = db.Column(db.String(20), nullable=False)
    ni_caretaker_no = db.Column(db.String(20), nullable=False, unique=True)
    ambulance = db.Column(db.String(20), nullable=False)
    dispensary = db.Column(db.String(20), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), nullable=False, unique=True)
    name = db.Column(db.String(30), nullable=False) ##
    phno = db.Column(db.String(11), nullable=False, unique=True) ##
    email = db.Column(db.String(50), nullable=False, unique=True) ##
    hostel = db.Column(db.String(1), nullable=False) ##
    room = db.Column(db.String(5), nullable=False) ##
    branch = db.Column(db.String(10), nullable=False) ##
    year = db.Column(db.String(2), nullable=False) ##
    password = db.Column(db.String(80), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=9, max=10)], render_kw={"placeholder":"Roll Number"})
    name = StringField(validators=[InputRequired(), Length(min=5, max=30)], render_kw={"placeholder": "Full Name"}) #
    phno = StringField(validators=[InputRequired(), Length(min=10, max=11)], render_kw={"placeholder": "Mobile Number"}) #
    email = StringField(validators=[InputRequired(), Length(min=15, max=50)], render_kw={"placeholder": "Email Id"}) #
    hostel = StringField(validators=[InputRequired(), Length(min=1, max=2)], render_kw={"placeholder": "Hostel"}) #
    room = StringField(validators=[InputRequired(), Length(min=4, max=5)], render_kw={"placeholder": "Room"}) #
    branch = StringField(validators=[InputRequired(), Length(min=4, max=10)], render_kw={"placeholder": "Branch"}) #
    year = StringField(validators=[InputRequired(), Length(min=1, max=2)], render_kw={"placeholder": "Year"}) #
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username = username.data).first()

        if existing_user_username:
            raise ValidationError(message="This username already exists")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=9, max=10)], render_kw={"placeholder":"Roll number"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")

@app.route('/{{current_user}}/home')
@dont_cache()
@login_required
def home():
    # get hostel data from database
    hostel = Hostel.query.filter_by(name=current_user.hostel).first()
    return render_template('firstpage.html',hostel=hostel)

@app.route('/', methods=['GET','POST'])
@app.route('/login', methods=['GET','POST'])
@dont_cache()
def login(): 
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        print(type(user))
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))

    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET','POST'])
@dont_cache()
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
@dont_cache()
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, name=form.name.data, phno=form.phno.data, email=form.email.data, hostel=form.hostel.data, room=form.room.data, branch=form.branch.data, year=form.year.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/{{current_user}}/hostel/')
@login_required
@dont_cache()
def hostel():
    return render_template('hostel.html')


if __name__ == '__main__':
    app.run(debug=True)