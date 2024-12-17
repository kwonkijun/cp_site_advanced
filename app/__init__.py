from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from instance.config import Config
import json

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

        # # JSON 파일 로딩
        # with open('real_estate_data.json', 'r', encoding='utf-8') as f:
        #     data = json.load(f)
        
        # # data는 리스트 형태라고 가정 ([ { ... }, { ... }, ... ])
        # for item in data:
        #     article = models.RealEstate(
        #         article_no=item.get("article_no"),
        #         article_name=item.get("article_name"),
        #         article_deal_or_warrant_price=item.get("article_deal_or_warrant_price"),
        #         article_type_name=item.get("article_type_name"),
        #         article_area_name=item.get("article_area_name"),
        #         article_area_size=item.get("article_area_size"),
        #         article_floor=item.get("article_floor"),
        #         article_direction=item.get("article_direction"),
        #         article_desc=item.get("article_desc"),
        #         article_expandable=item.get("article_expandable"),
        #         article_detail_desc=item.get("article_detail_desc"),
        #         article_deal_price=item.get("article_deal_price"),
        #         article_price_by_space=item.get("article_price_by_space"),
        #         article_realtor_name=item.get("article_realtor_name"),
        #         article_realtor_address=item.get("article_realtor_address"),
        #         article_supply_space=item.get("article_supply_space"),
        #         article_exclusive_space=item.get("article_exclusive_space"),
        #         article_exclusive_rate=item.get("article_exclusive_rate")
        #     )
        #     db.session.add(article)
        
        # db.session.commit()  # 데이터베이스에 커밋

    return app
