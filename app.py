from bokeh.client import pull_session

from utils.mylogger import mylogger
from flask import Flask, render_template
from flask_security import Security, login_required, \
    SQLAlchemySessionUserDatastore
from utils.database import db_session
from utils.models import User, Role
from flask_bootstrap import Bootstrap
from bokeh.util.session_id import generate_session_id
#from customizations.restricted_register_form import RestrictedRegisterForm


from flask_mail import Mail

logger = mylogger(__file__)
# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'
# After 'Create app'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'mayersandre@gmail.com'
app.config['MAIL_PASSWORD'] = 'w@rAngel12'
app.config['SECURITY_RECOVERABLE'] = True
app.config['SECURITY_PASSWORD_SALT'] = 'secret*12'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://admin:T1K1t#K#@localhost/analytics_aaa'
app.config['SECURITY_CHANGEABLE'] = True
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_CONFIRMABLE'] = True
app.config['SECURITY_CONFIRM_SALT'] = 'secret*12'
app.config['SECURITY_RESET_SALT'] = 'secret*12'
app.config['SECURITY_LOGIN_SALT'] = 'secret*12'
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'

Bootstrap(app)
mail = Mail(app)


# Setup Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db_session,User, Role)
security = Security(app, user_datastore)


# Views
@app.route('/')
@login_required
def home():
    # pull a new session from a running Bokeh server
    bokeh_server_url = 'http://192.168.1.15:5006/aion-analytics'
    #bokeh_session = pull_session(url=bokeh_server_url)
    bokeh_session = generate_session_id()
    script = "{}?bokeh-session-id={}".format(bokeh_server_url, bokeh_session)
    logger.warning("bokeh url:%s", script)
    return render_template('index.html', script=script, template="Flask")


@app.route('/tree', methods=['GET', 'POST'])
def tree():
    return render_template('tree.html')



if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000)