from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import current_user, login_user, logout_user, login_required
from . import db
from .models import User, Comment
from .forms import SignupForm, LoginForm, CommentForm, DeleteForm
from flask import current_app as app

@app.route('/')
def index():
    return redirect(url_for('comments'))

## 회원가입
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('comments'))
    
    form = SignupForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

## 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('comments'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('사용자 이름 또는 비밀번호가 잘못되었습니다.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        flash('로그인에 성공했습니다.', 'success')
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('comments'))
    return render_template('login.html', form=form)

## 로그아웃
@app.route('/logout')
def logout():
    logout_user()
    flash('로그아웃 되었습니다.', 'info')
    return redirect(url_for('login'))

## 댓글 목록
@app.route('/comments')
def comments():
    comments = Comment.query.all()
    delete_form = DeleteForm()  # DeleteForm 인스턴스 생성
    return render_template('comments.html', comments=comments, delete_form=delete_form)

## 댓글 작성
@app.route('/comment/new', methods=['GET', 'POST'])
@login_required
def new_comment():
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(content=form.content.data, author=current_user)
        db.session.add(comment)
        db.session.commit()
        flash('댓글이 작성되었습니다.', 'success')
        return redirect(url_for('comments'))
    return render_template('comment_form.html', form=form)

## 댓글 수정
@app.route('/comment/<int:comment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user:
        abort(403)  # Forbidden
    form = CommentForm(obj=comment)
    if form.validate_on_submit():
        comment.content = form.content.data
        db.session.commit()
        flash('댓글이 수정되었습니다.')
        return redirect(url_for('comments'))
    return render_template('comment_form.html', form=form, edit=True)

## 댓글 삭제
@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user:
        abort(403)  # Forbidden
    db.session.delete(comment)
    db.session.commit()
    flash('댓글이 삭제되었습니다.')
    return redirect(url_for('comments'))