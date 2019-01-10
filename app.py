import os

from bokeh.client import pull_session
from bokeh.util import session_id
from flask import Flask, render_template, redirect, url_for, flash, session, \
    abort, send_file, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user
from flask_bootstrap import Bootstrap
from flask_wtf import Form
from flask_wtf.csrf import CsrfProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
import onetimepass
from mylogger import mylogger
import pyotp
import qrcode
from bokeh.embed import server_document, server_session
logger = mylogger(__file__)

# create application instance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://admin:T1K1t#K#@localhost/analytics_aaa'
app.config.from_object('config')
csrf = CsrfProtect(app)
track_modifications = app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', True)
app.config['SECRET_KEY'] = 'SUPERSECRET'
#qrcode = QRcode(app)

# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)


class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:

            # generate a random secret
            self.otp_secret = pyotp.random_base32()
            logger.warning("otp secret:%s",self.otp_secret)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        try:
            logger.warning("username:%s",self.username)
            logger.warning("secret:%s",self.otp_secret)

            auth_uri = pyotp.totp.TOTP(self.otp_secret)\
                .provisioning_uri(self.username,issuer_name="aion-analytics")
            session.pop('username')
            logger.warning("2fa url:%s",auth_uri)
            return auth_uri
        except Exception:
            logger.error('get topt uri:',exc_info=True)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(Form):
    """Registration form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(Form):
    """Login form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    token = StringField('Token', validators=[Required(), Length(6, 6)])
    submit = SubmitField('Login')




@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        """User registration route."""
        if current_user.is_authenticated:
            # if user is logged in we get out of here
            return redirect(url_for('index'))
        form = RegisterForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user is not None:
                flash('Username already exists.')
                return redirect(url_for('register'))
            # add new user to the database
            user = User(username=form.username.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()

            # redirect to the two-factor auth page, passing username in session
            session['username'] = user.username

            return set_qrcode()

        else:
            return render_template('register.html', form=form)
    except Exception:
        logger.error("register",exc_info=True)

'''

@app.route('/twofactor')
def two_factor_setup():
    try:
        if 'username' not in session:
            return redirect(url_for('index'))
        user = User.query.filter_by(username=session['username']).first()
        if user is None:
            return redirect(url_for('index'))
        # since this page contains the sensitive qrcode, make sure the browser
        # does not cache it
        return render_template('two-factor-setup.html'), 200, {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}

    except Exception:
        logger.error("two factor",exc_info=True)
'''

#@app.route('/qrcode', methods=['GET'])
def set_qrcode():
    try:
        if 'username' not in session:
            abort(404)
        user = User.query.filter_by(username=session['username']).first()
        if user is None:
            abort(404)

        auth_uri = user.get_totp_uri()

        logger.warning("auth_uri:%s",auth_uri)

        # for added security, remove username from session
        del session['username']
        # save
        tmp_location = '/tmp/qr_code.png'

        # Save the qr image in a temp location
        # Create qr code instance
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(auth_uri)
        qr.make(fit=True)
        img = qr.make_image()
        img.save(tmp_location)
        img.save("static/images/qr_code.png")
        logger.warning("FILE WRITTEN")

        return render_template('two-factor-setup.html', qr_code='/static/images/qr_code.png')

    except Exception:
        logger.error("qrcode",exc_info=True)



@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Invalid username, password or token.')
            return redirect(url_for('login'))

        # log user in
        login_user(user)
        flash('You are now logged in!')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """User logout route."""
    logout_user()
    return redirect(url_for('index'))

@app.route('/', methods=['GET'])
def index():
    # pull a new session from a running Bokeh server
    bokeh_server_url = 'http://localhost:5006/aion-analytics'
    bokeh_session= pull_session(url=bokeh_server_url)
    script = "{}?bokeh-session-id={}".format(bokeh_server_url, bokeh_session.id)
    logger.warning("bokeh url:%s", script)

    return render_template('index.html', script=script, template="Flask")

# create database tables if they don't exist yet
db.create_all()


if __name__ == '__main__':
    app.run(host='localhost',port=8080, debug=True)