from . import db, login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from zoneinfo import ZoneInfo

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    color = db.Column(db.String(7), default="#000000")
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("Asia/Seoul")))  # 한국 시간 기준

class RealEstate(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    article_no = db.Column(db.String(50))
    article_name = db.Column(db.String(100))
    article_deal_or_warrant_price = db.Column(db.String(50))
    article_type_name = db.Column(db.String(50))
    article_area_name = db.Column(db.String(50))
    article_area_size = db.Column(db.Integer)
    article_floor = db.Column(db.String(50))
    article_direction = db.Column(db.String(50))
    article_desc = db.Column(db.Text)
    article_expandable = db.Column(db.Boolean)
    article_detail_desc = db.Column(db.Text)
    article_deal_price = db.Column(db.Integer)
    article_price_by_space = db.Column(db.Float)
    article_realtor_name = db.Column(db.String(100))
    article_realtor_address = db.Column(db.String(200))
    article_supply_space = db.Column(db.Float)
    article_exclusive_space = db.Column(db.Float)
    article_exclusive_rate = db.Column(db.String(10))
