from flask import Flask, redirect, url_for, render_template, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, InputRequired, Regexp
from os import environ

usernames=[
]
current_user = [''];
logged_in = False

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
            for user_data in usernames:
                if user_data['username'] == field.data:
                    raise ValidationError(self.register_message)
        else:
            user_available = False 
            for user_data in usernames:
                if user_data['username'] == field.data:
                    user_available = True
                    break
            if user_available == False:
                raise ValidationError(self.login_message)

user_check = User_check
# def user_check(register=False):
#     login_message = "user unavailable"
#     register_message = "user already exists"
#     def _user_check(form, field):
#         if register:
#             if field.data in usernames:
#                 raise ValidationError(register_message)
#         else:
#             if field.data not in usernames:
#                 raise ValidationError(login_message)
#     return _user_check


class Pass_check(object):
    def __init__(self):
        self.error_message = "Incorrect Password"

    def __call__(self, form, field):
        for user_data in usernames:
            if user_data['username'] == form.username.data:
                if user_data['password'] != field.data:
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

app = Flask(__name__)
app.config['SECRET_KEY'] = environ['SECRET_KEY']




@app.route("/")
def home():
    if logged_in:
        return redirect(url_for('messages_page'))
    return redirect(url_for('login_page'))


@app.route("/login",methods=["POST", "GET"])
def login_page():
    global logged_in
    if not logged_in:
        form = LoginForm()
        if form.validate_on_submit():
            # username[0] = request.form['username'].split('@')[0]
            logged_in = True
            for user_data in usernames:
                if user_data['username'] == form.username.data:
                    current_user[0] = user_data
                    break
            return redirect(url_for('messages_page'))
        return render_template('login.html',form=form)
    return redirect(url_for('messages_page'))

@app.route("/register", methods=["POST", "GET"])
def register_page():
    global logged_in
    form = RegisterForm()
    if not logged_in:
        if form.validate_on_submit():
            data = {'username':form.username.data,'messages':[],'password':form.password.data}
            usernames.append(data)
            logged_in = True
            current_user[0] = usernames[-1]
            return redirect(url_for('messages_page'))
        return render_template('register.html', form=form)
    return redirect(url_for('messages_page'))

@app.route("/user-messages")
def messages_page():
    if logged_in:
        return render_template('user-msgs.html',username=current_user[0]['username'], user_messages = current_user[0]['messages'][::-1])
    else:
        return redirect(url_for('home'))

@app.route('/send-message', methods=["POST", "GET"])
def send_message_page():
    global logged_in
    form = SendMsgForm()
    if not logged_in:
        return redirect(url_for('login_page'))
    else:
        if form.validate_on_submit():
            username = form.username.data
            message = request.form['sent_msg']
            for user_data in usernames:
                if user_data['username'] == username:
                    user_data['messages'].append(message)
                    print(user_data)
                    break
            return redirect(url_for('messages_page'))
    return render_template('send-msgs.html',form = form)

@app.route('/logout',methods=["POST"])
def logout_page():
    global logged_in
    if request.method == "POST":
        logged_in = False
        current_user[0] = ''
        return redirect(url_for('login_page'))

if __name__ == "__main__":
    app.run(debug=True)