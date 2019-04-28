from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager
from config import Config


app = Flask(__name__)
app.config.from_object(Config)
api = Api(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)
jwt = JWTManager(app)

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedToken.is_jti_blacklisted(jti)

from app.resources import \
    Register, \
    Login, \
    TokenRefresh, \
    LogoutAccess, \
    LogoutRefresh, \
    List


api.add_resource(Register, '/api/register')
api.add_resource(Login, '/api/login')
api.add_resource(TokenRefresh, '/api/token')
api.add_resource(LogoutAccess, '/api/logout/access')
api.add_resource(LogoutRefresh, '/api/logout/refresh')
api.add_resource(List, '/api/list')