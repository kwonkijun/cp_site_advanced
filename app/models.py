from . import db, login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
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


class RealEstate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    deal_price = db.Column(db.String(50))
    real_estate_type_name = db.Column(db.String(50))
    area_name = db.Column(db.String(100))
    area_size = db.Column(db.String(50))
    floor_info = db.Column(db.String(50))
    direction = db.Column(db.String(50))
    feature_desc = db.Column(db.Text)
    supply_space = db.Column(db.String(50))
    exclusive_space = db.Column(db.String(50))
    exclusive_rate = db.Column(db.String(50))
    detail_desc = db.Column(db.Text)
    deal_or_warrant_prc = db.Column(db.String(50))
    expandable = db.Column(db.Boolean, default=False)
