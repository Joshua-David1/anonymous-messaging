from flask import Flask, redirect, url_for, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, InputRequired, Regexp
from os import environ

app = Flask(__name__)
app.config['SECRET_KEY'] = environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get("SQLALCHEMY_URI")
db = SQLAlchemy(app)


current_user = ""
logged_in = False


##DATABASE MODELS

##USER TABLE
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable = False)
    password = db.Column(db.String(25), nullable=False)


##MESSAGES TABLE
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable = False)
    user_message = db.Column(db.String(500), nullable = False)


db.create_all()
                    ###########################


def min_char_check(form, field):
    if len(field.data) < 6:
        raise ValidationError('Minimum 6 characters required')


class User_check(object):
    def __init__(self, register = False):
        self.register = register
        self.login_message = "user unavailable"
        self.register_message = "user already exists"

    def __call__(self, form, field):
        if self.register:
            user = User.query.filter_by(username = field.data).first()
            if user:
                raise ValidationError(self.register_message)
        else:
            user = User.query.filter_by(username = field.data).first()
            if user == None:
                    raise ValidationError(self.login_message)


user_check = User_check


class Pass_check(object):
    def __init__(self):
        self.error_message = "Incorrect Password"

    def __call__(self, form, field):
        user = User.query.filter_by(username = form.username.data).first()
        if user is None or user.password != field.data:
            raise ValidationError('Password Incorrect')
                    

pass_check = Pass_check

##Forms##
class LoginForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username","maxlength":25},validators=[InputRequired(),  user_check()])
    password = PasswordField('password',render_kw={"placeholder":"Password","maxlength":20},validators=[InputRequired(message="Please enter password"),min_char_check,pass_check()])


class RegisterForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username","maxlength":25},validators=[InputRequired(message="Enter username"), min_char_check,user_check(register = True), Regexp("^[\w\.]*$", message="Only letter, numbers, underscores and periods(.)"),Regexp("^[a-z\_]+$", message="Only small letters") ])
    password = PasswordField('password',render_kw={"placeholder":"Password","maxlength":20},validators=[InputRequired(message="Enter password"),min_char_check])


class SendMsgForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username to send msg","maxlength":25},validators=[InputRequired(message="Enter username"), user_check()])
    sent_msg = TextAreaField('sent_msg', render_kw={"placeholder":"type your message here...","maxlength":350},validators=[InputRequired()])

##########

@app.route("/")
def home():
    return redirect(url_for('login_page'))


@app.route("/login",methods=["POST", "GET"])
def login_page():
    global current_user
    global logged_in
    form = LoginForm()
    if form.validate_on_submit():
        current_user = form.username.data
        logged_in = True
        return redirect(url_for('messages_page'))
    return render_template('login.html', form  = form)

@app.route("/register", methods=["POST", "GET"])
def register_page():
    global logged_in
    global current_user
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        new_user = User(username = username, password = password)
        db.session.add(new_user)
        db.session.commit()
        current_user = form.username.data
        logged_in = True
        return redirect(url_for('messages_page'))
    return render_template('register.html', form = form)

@app.route("/user-messages")
def messages_page():
    global logged_in
    print(logged_in)
    if logged_in:
        username = User.query.filter_by(username = current_user).first()
        user_messages = Message.query.filter_by(username = current_user).all()
        return render_template('user-msgs.html',username=username.username, user_messages = [user.user_message for user in user_messages][::-1])
    else:
        return redirect(url_for('home'))

@app.route('/send-message', methods=["POST", "GET"])
def send_message_page():
    form = SendMsgForm()
    if form.validate_on_submit():
        username = form.username.data
        message = request.form['sent_msg']
        new_message = Message(username = username, user_message = message)
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('messages_page'))
    return render_template('send-msgs.html',form = form)

@app.route('/logout',methods=["POST"])
def logout_page():
    if request.method == "POST":
        logged_in = False
        current_user = ""
        return redirect(url_for('login_page'))

if __name__ == "__main__":
    app.run(debug=True)