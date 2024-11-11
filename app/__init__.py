from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from instance.config import Config

db = SQLAlchemy()
migrate = Migrate()
login = LoginManager()
login.login_view = 'login'  # 로그인 필요 시 리다이렉트할 엔드포인트

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    login.init_app(app)

    with app.app_context():
        from . import routes, models
        db.create_all()

    return app
