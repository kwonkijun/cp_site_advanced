from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from .models import User

class SignupForm(FlaskForm):
    username = StringField('사용자 이름', validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    password2 = PasswordField('비밀번호 확인', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('회원가입')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('이미 사용 중인 사용자 이름입니다.')

class LoginForm(FlaskForm):
    username = StringField('사용자 이름', validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    submit = SubmitField('로그인')

class CommentForm(FlaskForm):
    content = TextAreaField('댓글 내용', validators=[DataRequired()])
    submit = SubmitField('작성')

class DeleteForm(FlaskForm):
    pass
