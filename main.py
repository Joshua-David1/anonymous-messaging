from flask import Flask, flash, redirect, url_for, render_template, request, session, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, InputRequired, Regexp, EqualTo
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import pyperclip
import os
import urllib.parse
import psycopg2
from os import environ
from decouple import config

app = Flask(__name__)
app.config['SECRET_KEY'] = config("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = config("SQLALCHEMY_DATABASE_URI","sqlite:///user-data-collection.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = "OFF"
db = SQLAlchemy(app)




login_manager = LoginManager()
login_manager.init_app(app)


redirect_url = 'messages_page'
global_username = None
current_tab = "available-users"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##DATABASE MODELS

##USER TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable = False)
    password = db.Column(db.String(25), nullable=False)


##MESSAGES TABLE
class Message(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable = False)
    user_message = db.Column(db.String(10000), nullable = False)


db.create_all()
                    ###########################


def min_char_check(form, field):
    if len(field.data) < 6:
        raise ValidationError('Minimum 6 characters required')


class Same_user_check(object):
    def __init__(self):
        self.error_message = "You cannot send message to yourself"

    def __call__(self, form, field):
        entered_username = field.data
        current_username = current_user.username
        print(current_username)
        print(entered_username)
        if entered_username == current_username:
            raise ValidationError(self.error_message)


same_user_check = Same_user_check

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
        if user is None or field.data != user.password:
            raise ValidationError('Password Incorrect')
                    

pass_check = Pass_check

##Forms##
class LoginForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username","maxlength":25},validators=[InputRequired(message="Enter username"),  user_check()])
    password = PasswordField('password',render_kw={"placeholder":"Password","maxlength":20},validators=[InputRequired(message="Please enter password"),min_char_check,pass_check()])


class RegisterForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username","maxlength":25},validators=[InputRequired(message="Enter username"), min_char_check,user_check(register = True), Regexp("^[\w]*$", message="Only letter, numbers and underscore."),Regexp("^[a-z\_0-9]*$", message="Only small letters"), Regexp("^[a-z\_]+[a-z\_0-9]*$", message="Cannot begin with numbers") ])
    password = PasswordField('password',render_kw={"placeholder":"Password","maxlength":20},validators=[InputRequired(message="Enter password"),min_char_check])


class SendMsgForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username to send msg","maxlength":25},validators=[InputRequired(message="Enter username"), user_check(), same_user_check()])
    sent_msg = TextAreaField('sent_msg', render_kw={"placeholder":"type your message here...","maxlength":350},validators=[InputRequired()])


class ChangeUsernameForm(FlaskForm):
    new_username = StringField('new_username', render_kw={"placeholder":"New username", "maxlength" :25}, validators=[InputRequired(message="Enter new username"), min_char_check,user_check(register=True),  Regexp("^[\w]*$", message="Only letter, numbers and underscore."),Regexp("^[a-z\_0-9]*$", message="Only small letters"), Regexp("^[a-z\_]+[a-z\_0-9]*$", message="Cannot begin with numbers") ])

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('new_password', render_kw={"placeholder":"Enter new password","maxlength":20}, validators = [InputRequired(message="Enter new password"), min_char_check, EqualTo('confirm_password', message="Passwords must match")])
    confirm_password = PasswordField('confirm_password', render_kw={"placeholder":"Re-type password"})
##########

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=10)
    session.modified = True
    g.user = current_user


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for(redirect_url))
    return render_template('home.html')


@app.route('/about')
def about_page():
    return render_template('about.html')

@app.route("/login",methods=["POST", "GET"])
def login_page():
    global redirect_url
    if not current_user.is_authenticated:
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            login_user(user)
            return redirect(url_for(redirect_url))
        return render_template('login.html', form=form)
    return redirect(url_for(redirect_url))

@app.route("/register", methods=["POST", "GET"])
def register_page():
    global redirect_url
    if not current_user.is_authenticated:
        form = RegisterForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            # password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=1)
            new_user = User(username = username, password = password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for(redirect_url))
        return render_template('register.html', form=form)
    return redirect(url_for(redirect_url))

@app.route("/user-messages")
def messages_page():
    global redirect_url
    if current_user.is_authenticated:
        redirect_url = 'messages_page'
        username = User.query.filter_by(username = current_user.username).first()
        user_messages = Message.query.filter_by(username = current_user.username).all()
        return render_template('user-msgs.html',username=username.username, user_messages = [user for user in user_messages][::-1])
    else:
        return redirect(url_for('home'))


@app.route("/send-message/<username>")
@app.route('/send-message', methods=["POST", "GET"])
def send_message_page(username=None):
    global global_username
    global redirect_url
    if current_user.is_authenticated:
        if global_username is not None:
            username = global_username
            global_username = None
        redirect_url = 'send_message_page'
        user = User.query.filter_by(username = username).first()
        if user is not None:
            form = SendMsgForm(username=username)
        elif username is not None and user is None:
            flash("User not found")
            redirect_url = 'messages_page'
            return redirect(url_for(redirect_url))
        else:
            form = SendMsgForm()
        if form.validate_on_submit():
            username = form.username.data
            message = request.form['sent_msg']
            new_message = Message(username = username, user_message = message)
            db.session.add(new_message)
            db.session.commit()
            flash("Message sent successfully")
            return redirect(url_for('messages_page'))
        return render_template('send-msgs.html',form = form)

    if username is not None:
        global_username = username
    redirect_url = 'send_message_page'
    return redirect(url_for('home'))


@app.route('/user/<username>')
def copy_username(username):
    if current_user.is_authenticated:
        current_page_url = request.base_url
        parsed_url = urllib.parse.urlparse(current_page_url)
        root_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        username_to_share = f"{root_url}send-message/{current_user.username}"
        flash(f"{username_to_share}")
        return redirect(url_for('messages_page'))
    else:
        return redirect(url_for('home'))



#### Deletion ####
@app.route('/delete-msg')
def delete_message():
    if current_user.is_authenticated:
        try:
            msg_id = request.args.get("msg_id")
            print(msg_id)
            id_user = Message.query.filter_by(id=msg_id).first().username
            print(id_user)
            if(id_user == current_user.username):
                msg_to_be_deleted = Message.query.filter_by(id = msg_id).first()
                db.session.delete(msg_to_be_deleted)
                db.session.commit()
            return redirect(url_for('messages_page'))
        except:
            return redirect(url_for('messages_page'))
    else:
        return redirect(url_for('home'))

#################


########## Settings ###############


@app.route('/settings', methods=["POST","GET"])
def settings_page():
    global current_tab
    global redirect_url
    if current_user.is_authenticated:
        changeUsernameForm = ChangeUsernameForm()
        changePasswordForm = ChangePasswordForm()
        users = User.query.all()
        if request.method == "POST":
            try:
                form = request.form['new_username']
                field = 'new_username'
            except:
                form = request.form['new_password']
                field = 'new_password'
            if field == 'new_username':
                current_tab = "change-username"
                if changeUsernameForm.validate_on_submit():
                    new_username = changeUsernameForm.new_username.data
                    current_username = current_user.username
                    user = User.query.filter_by(username=current_user.username).first()
                    messages = Message.query.filter_by(username = current_username).all()
                    for message in messages:
                        message.username = new_username
                        db.session.commit()
                    user.username = new_username
                    db.session.commit()
                    flash("Username changed!")
                return render_template('settings.html', user_list = users[::-1], changeUsernameForm=changeUsernameForm, changePasswordForm=changePasswordForm, current_tab = current_tab)
            elif field == 'new_password':
                current_tab = "change-password"
                if changePasswordForm.validate_on_submit():
                    new_password = changePasswordForm.new_password.data
                    user = User.query.filter_by(username = current_user.username).first()
                    user.password = new_password
                    db.session.commit()
                    flash("Password Changed")
                return render_template('settings.html', user_list = users[::-1], changeUsernameForm=changeUsernameForm, changePasswordForm=changePasswordForm, current_tab = current_tab) 
        return render_template('settings.html', user_list = users[::-1], changeUsernameForm=changeUsernameForm, changePasswordForm=changePasswordForm, current_tab = current_tab)
    redirect_url = "settings_page"
    return redirect(url_for('home'))
#####################################


##### logout page ######
@app.route('/logout',methods=["POST","GET"])
def logout_page():
    global global_username
    global redirect_url
    global current_tab
    if current_user.is_authenticated:
        if request.method == "POST":
            global_username = None
            redirect_url = 'messages_page'
            logout_user()
            current_tab = "available-users"
            return redirect(url_for('login_page'))
        return redirect(url_for('home'))
    return redirect(url_for('home'))

####### delete page ################
@app.route('/delete', methods=["POST","GET"])
def delete_page():
    global global_username
    global redirect_url
    global current_tab
    if current_user.is_authenticated:
        if request.method == "POST":
            temp_user = current_user.username
            global_username = None
            redirect_url = 'messages_page'
            current_tab = "available-users"
            user_msgs_list = Message.query.filter_by(username=temp_user).all()
            for user in user_msgs_list:
                db.session.delete(user)
                db.session.commit()
            user = User.query.filter_by(username=temp_user).first()
            db.session.delete(user)
            db.session.commit()
            flash('Deleted your account...')
            logout_user()
            return redirect(url_for('login_page'))
        return redirect(url_for('home'))
    return redirect(url_for('home'))


@app.route("/usernames")
def usernames_page():
    users_list = []
    users = User.query.all()
    for user in users:
        users_list.append(user.username)
    return jsonify({"Users":users_list})

if __name__ == "__main__":
    port = config("PORT",5000)
    app.run(debug=True, port=port)