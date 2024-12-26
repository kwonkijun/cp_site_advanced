# routes.py
import secrets
import hashlib
from flask import render_template, redirect, url_for, flash, request, abort, jsonify, session
from flask_login import current_user, login_user, logout_user, login_required
from . import db
from .models import User, Comment, RealEstate
from .forms import SignupForm, LoginForm, CommentForm, EditCommentForm, DeleteForm
from flask import current_app as app

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/level1')
def level1():
    # 목록 페이지 템플릿
    return render_template('level1.html')

@app.route('/api/articles')
def api_articles():
    page = int(request.args.get('page', 1))        # 기본값 1
    pageSize = int(request.args.get('pageSize', 20))  # 기본값 20
    
    # 페이지 계산
    offset = (page - 1) * pageSize
    query = RealEstate.query.order_by(RealEstate.id.asc()).offset(offset).limit(pageSize).all()

    data = []
    for a in query:
        data.append({
            "article_no": a.article_no,
            "article_name": a.article_name,
            "article_deal_or_warrant_price": a.article_deal_or_warrant_price,
            "article_type_name": a.article_type_name,
            "article_area_name": a.article_area_name,
            "article_area_size": a.article_area_size,
            "article_floor": a.article_floor,
            "article_direction": a.article_direction,
            "article_desc": a.article_desc,
            "article_expandable": a.article_expandable,
            "article_detail_desc": a.article_detail_desc,
            "article_deal_price": a.article_deal_price,
            "article_price_by_space": a.article_price_by_space,
            "article_realtor_name": a.article_realtor_name,
            "article_realtor_address": a.article_realtor_address,
            "article_supply_space": a.article_supply_space,
            "article_exclusive_space": a.article_exclusive_space,
            "article_exclusive_rate": a.article_exclusive_rate
        })
    return jsonify(data)

@app.route('/level1/<article_no>')
def level1_detail(article_no):
    article = RealEstate.query.filter_by(article_no=article_no).first()
    if not article:
        return "Not Found", 404
    article_data = {
        "article_no": article.article_no,
        "article_name": article.article_name,
        "article_deal_or_warrant_price": article.article_deal_or_warrant_price,
        "article_type_name": article.article_type_name,
        "article_area_name": article.article_area_name,
        "article_area_size": article.article_area_size,
        "article_floor": article.article_floor,
        "article_direction": article.article_direction,
        "article_desc": article.article_desc,
        "article_expandable": article.article_expandable,
        "article_detail_desc": article.article_detail_desc,
        "article_deal_price": article.article_deal_price,
        "article_price_by_space": article.article_price_by_space,
        "article_realtor_name": article.article_realtor_name,
        "article_realtor_address": article.article_realtor_address,
        "article_supply_space": article.article_supply_space,
        "article_exclusive_space": article.article_exclusive_space,
        "article_exclusive_rate": article.article_exclusive_rate
    }

    return render_template('level1_detail.html', article_data=article_data)

@app.route('/level2')
def level2():
    page = request.args.get('page', 1, type=int)
    comments_query = Comment.query.order_by(Comment.created_at.asc())
    comments = comments_query.paginate(page=page, per_page=20)
    comment_form = CommentForm()
    edit_form = EditCommentForm()
    delete_form = DeleteForm()
    return render_template('level2.html', comments=comments, form=comment_form, edit_form=edit_form, delete_form=delete_form)

## 회원가입
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('level2'))
        
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
        return redirect(url_for('level2'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('사용자 이름 또는 비밀번호가 잘못되었습니다.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        flash('로그인에 성공했습니다.', 'success')
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('level2'))
    return render_template('login.html', form=form)

## 로그아웃
@app.route('/logout')
def logout():
    logout_user()
    flash('로그아웃 되었습니다.', 'info')
    return redirect(url_for('login'))

## 댓글 작성
@app.route('/level2/comment/new', methods=['POST'])
@login_required
def new_comment():
    form = CommentForm(request.form)
    if form.validate():  # CSRF 검증 없이 폼 검증
        content = form.content.data.strip()
        if not content:
            flash('댓글 내용을 입력해주세요.', 'danger')
            return redirect(url_for('level2', page=1, _anchor='blog-comments'))

        # 새로운 댓글 저장
        comment = Comment(content=content, author=current_user)
        db.session.add(comment)
        db.session.commit()
        flash('댓글이 작성되었습니다.', 'success')

        # 댓글 수 기반으로 페이지 계산
        total_comments = Comment.query.count()
        comments_per_page = 20  # 페이지당 댓글 수
        target_page = (total_comments - 1) // comments_per_page + 1

        # 작성된 댓글이 있는 페이지로 이동
        return redirect(url_for('level2', page=target_page, _anchor='blog-comments'))
    else:
        # Form did not validate
        flash('댓글 작성에 실패했습니다.', 'danger')
        return redirect(url_for('level2', _anchor='blog-comments'))

## 댓글 수정
@app.route('/level2/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user:
        abort(403, description="권한이 없습니다.")

    form = EditCommentForm()
    if form.validate_on_submit():
        updated_content = form.content.data.strip()
        if not updated_content:
            flash('댓글 내용을 입력해주세요.', 'danger')
            page = request.args.get('page', 1, type=int)
            return redirect(url_for('level2', page=page, _anchor='blog-comments'))
        comment.content = updated_content
        db.session.commit()
        flash('댓글이 수정되었습니다.', 'success')

        # 현재 페이지 번호 가져오기
        page = request.args.get('page', 1, type=int)

        # 수정 후 해당 페이지로 리다이렉트
        return redirect(url_for('level2', page=page, _anchor='blog-comments'))
    else:
        flash('댓글 수정에 실패했습니다.', 'danger')
        return redirect(url_for('level2', _anchor='blog-comments'))

## 댓글 삭제
@app.route('/level2/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user:
        abort(403)
    form = DeleteForm()
    if form.validate_on_submit():
        db.session.delete(comment)
        db.session.commit()
        flash('댓글이 삭제되었습니다.', 'success')
    else:
        flash('댓글 삭제에 실패했습니다.', 'danger')
    # 현재 페이지 번호 가져오기
    page = request.args.get('page', 1, type=int)
    # 댓글 목록 확인 및 페이지 번호 조정
    remaining_comments = Comment.query.paginate(page=page, per_page=20)
    if not remaining_comments.items and page > 1:
        page -= 1  # 이전 페이지로 이동
    return redirect(url_for('level2', page=page, _anchor='blog-comments'))

@app.route('/level3')
def level3():
    # 5번 자바스크립트 검증을 위해 세션에 토큰 저장
    # (해당 토큰을 level3.html에서 자바스크립트로 fetch 요청 시 전달)
    session['js_token'] = secrets.token_hex(16)
    return render_template('level3.html')

@app.route('/protected_api/articles')
def protected_api_articles():
    """
    1) User-Agent 검사
    2) Referer 검사
    5) 자바스크립트 검증(세션 토큰 확인)
    """
    # 1. User-Agent 검사
    user_agent = request.headers.get('User-Agent', '')
    # 예시로 python-requests나 curl 등이 포함되어 있으면 차단
    lower_ua = user_agent.lower()
    if ("python-requests" in lower_ua) or ("curl" in lower_ua) or not user_agent.strip():
        return "Forbidden: User-Agent invalid", 403

    # 2. Referer 검사
    referer = request.headers.get('Referer', '')
    # 예시로 referer에 'level3' 문자열이 없으면 거절
    # (실제로는 특정 도메인 검증 등을 할 수 있습니다)
    if "level3" not in referer:
        return "Forbidden: Referer invalid", 403

    # 5. 자바스크립트 검증을 위한 세션 토큰 확인
    # level3.html에서 자바스크립트로 ?token=xxx 형태로 전송한다고 가정
    client_token = request.args.get('token', '')
    server_token = session.get('js_token', '')

    if not client_token or (client_token != server_token):
        return "Forbidden: JS token invalid", 403

    # ----- 정상 통과 시 기존 로직 실행 -----
    page = int(request.args.get('page', 1))
    pageSize = int(request.args.get('pageSize', 20))
    offset = (page - 1) * pageSize
    query = RealEstate.query.order_by(RealEstate.id.asc()).offset(offset).limit(pageSize).all()

    data = []
    for a in query:
        data.append({
            "article_no": a.article_no,
            "article_name": a.article_name,
            "article_deal_or_warrant_price": a.article_deal_or_warrant_price,
            "article_type_name": a.article_type_name,
            "article_area_name": a.article_area_name,
            "article_area_size": a.article_area_size,
            "article_floor": a.article_floor,
            "article_direction": a.article_direction,
            "article_desc": a.article_desc,
            "article_expandable": a.article_expandable,
            "article_detail_desc": a.article_detail_desc,
            "article_deal_price": a.article_deal_price,
            "article_price_by_space": a.article_price_by_space,
            "article_realtor_name": a.article_realtor_name,
            "article_realtor_address": a.article_realtor_address,
            "article_supply_space": a.article_supply_space,
            "article_exclusive_space": a.article_exclusive_space,
            "article_exclusive_rate": a.article_exclusive_rate
        })
    return jsonify(data)


@app.route('/level3/<article_no>')
def level3_detail(article_no):
    article = RealEstate.query.filter_by(article_no=article_no).first()
    if not article:
        return "Not Found", 404
    article_data = {
        "article_no": article.article_no,
        "article_name": article.article_name,
        "article_deal_or_warrant_price": article.article_deal_or_warrant_price,
        "article_type_name": article.article_type_name,
        "article_area_name": article.article_area_name,
        "article_area_size": article.article_area_size,
        "article_floor": article.article_floor,
        "article_direction": article.article_direction,
        "article_desc": article.article_desc,
        "article_expandable": article.article_expandable,
        "article_detail_desc": article.article_detail_desc,
        "article_deal_price": article.article_deal_price,
        "article_price_by_space": article.article_price_by_space,
        "article_realtor_name": article.article_realtor_name,
        "article_realtor_address": article.article_realtor_address,
        "article_supply_space": article.article_supply_space,
        "article_exclusive_space": article.article_exclusive_space,
        "article_exclusive_rate": article.article_exclusive_rate
    }

    return render_template('level3_detail.html', article_data=article_data)

@app.route('/level4')
def level4():
    return render_template('level4.html')