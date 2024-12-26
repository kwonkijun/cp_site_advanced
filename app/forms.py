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

# forms.py

from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length

class CommentForm(FlaskForm):
    class Meta:
        csrf = False  # CSRF 보호 비활성화
        
    content = TextAreaField(
        '댓글',
        validators=[
            DataRequired(message='댓글 내용을 입력해주세요.'),
            Length(min=1, max=1000, message='댓글은 1자 이상, 1000자 이하로 입력해주세요.')
        ],
        render_kw={"placeholder": "댓글을 입력하세요"}
    )
    submit = SubmitField('등록하기')

class EditCommentForm(FlaskForm):
    content = TextAreaField(
        '댓글 수정',
        validators=[
            DataRequired(message='댓글 내용을 입력해주세요.'),
            Length(min=1, max=1000, message='댓글은 1자 이상, 1000자 이하로 입력해주세요.')
        ],
        render_kw={"placeholder": "댓글을 수정하세요"}
    )
    submit = SubmitField('수정')

class DeleteForm(FlaskForm):
    submit = SubmitField('삭제')

