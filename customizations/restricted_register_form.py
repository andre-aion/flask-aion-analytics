from flask_security.forms import RegisterForm, PasswordField, Required, Length
from wtforms import ValidationError, StringField
from wtforms.validators import InputRequired, regexp, Email

from utils.mylogger import mylogger

password_required = Required(message='PASSWORD_NOT_PROVIDED')
password_length = Length(min=8, max=128, message='PASSWORD_INVALID_LENGTH')

logger = mylogger(__file__)

# Extend Forms
class RestrictedRegisterForm(RegisterForm):
    email = StringField('email', validators=[InputRequired(),
                                             Email("email must be of proper format"),
                                             regexp("^*@aion.network$",
                                                    message="Sorry you must be an aion employee")])

