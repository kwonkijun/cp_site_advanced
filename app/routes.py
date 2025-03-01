# routes.py
import json
from flask import render_template, redirect, url_for, flash, request, abort, jsonify, session
from flask_login import current_user, login_user, logout_user, login_required
from . import db
from .models import User, Comment, RealEstate
from .forms import SignupForm, LoginForm, CommentForm, EditCommentForm, DeleteForm
from flask import current_app as app
from flask import Response
from markupsafe import Markup


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
            "article_desc": a.article_desc
        })

    json_str = json.dumps(data, ensure_ascii=False)
    return Response(json_str, content_type='application/json')

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

    # ensure_ascii=False 옵션을 사용하여 한글이 그대로 나오도록 함
    json_data = json.dumps(article_data, ensure_ascii=False)
    return render_template('level1_detail.html', article_data=Markup(json_data))

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
        color = request.form.get('color', '#000000')  # 기본값 검정색
        user = User(username=form.username.data, color=color)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/check_username')
def check_username():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({"available": False}), 400

    user = User.query.filter_by(username=username).first()
    return jsonify({"available": user is None})

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
    flash("레벨 3은 곧 오픈됩니다!", "info")
    return redirect(url_for('coming_soon'))  # 오픈 예정 페이지로 이동

@app.route('/level4')
def level4():
    flash("레벨 4는 곧 오픈됩니다!", "info")
    return redirect(url_for('coming_soon'))  # 오픈 예정 페이지로 이동

@app.route('/coming-soon')
def coming_soon():
    return render_template('coming_soon.html')


@app.route('/set_js_enabled', methods=['POST'])
def set_js_enabled():
    session['js_enabled'] = True
    session['user_agent'] = request.headers.get('User-Agent', '')
    session['ip_address'] = request.remote_addr
    return jsonify({'status': 'success'})

@app.route('/protected_api/articles')
def api_protected_articles():
    # 헤더 검증
    user_agent = request.headers.get('User-Agent', '')
    referer = request.headers.get('Referer', '')
    accept = request.headers.get('Accept', '')

    # 1. User-Agent 검증: 일반적인 브라우저의 User-Agent 패턴 확인
    if not user_agent or "Mozilla" not in user_agent:
        abort(403, description="허용되지 않은 User-Agent 입니다.")

    # JavaScript 실행 여부 확인: 세션 변수 확인 및 추가 정보 검증
    if not session.get('js_enabled', False):
        abort(403, description="자바스크립트가 활성화되어 있지 않습니다.")

    # 사용자 에이전트와 IP 주소 검증
    if session.get('user_agent', '') != user_agent:
        print(session.get('user_agent', ''), user_agent)
        abort(403, description="User-Agent 불일치.")
    
    if session.get('ip_address', '') != request.remote_addr:
        abort(403, description="IP 주소 불일치.")

    # 페이지 및 페이지 사이즈 가져오기
    try:
        page = int(request.args.get('page', 1))
        pageSize = int(request.args.get('pageSize', 20))
    except ValueError:
        abort(400, description="유효하지 않은 페이지 번호 또는 페이지 사이즈.")

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
    json_str = json.dumps(data, ensure_ascii=False)
    return Response(json_str, content_type='application/json')



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

    # ensure_ascii=False 옵션을 사용하여 한글이 그대로 나오도록 함
    json_data = json.dumps(article_data, ensure_ascii=False)
    return render_template('level1_detail.html', article_data=Markup(json_data))