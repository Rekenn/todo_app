from flask import request, jsonify
from flask_restful import Resource
from flask_jwt_extended import create_access_token, create_refresh_token, \
    jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
from app.schemas import UserSchema
from werkzeug.security import check_password_hash
from app.models import User, RevokedToken
from app.services import add_to_db


class Register(Resource):
    pass


class Login(Resource):
    def post(self):
        try:
            user_schema = UserSchema()
            user = user_schema.load(request.get_json()).data
            existing_user = User.query.filter_by(username=user.username).first()

            if not existing_user:
                return {
                    'message': 'User does not exists',
                    'code': 404
                }
            
            password_does_match = check_password_hash(existing_user.password, user.password)
            
            if user.username == existing_user.username and password_does_match:
                access_token = create_access_token(identity=user.username)
                refresh_token = create_refresh_token(identity=user.username)
                return {
                    'message': 'Log in properly',
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'code': 200
                }
            else:
                return {
                    'message': 'Wrong credentials',
                    'code': 403
                }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }


class LogoutAccess(Resource):
    @jwt_required
    def delete(self):
        try:
            jti = get_raw_jwt()['jti']
            revoked_token = RevokedToken(jti=jti)
            add_to_db(revoked_token)
            return {
                'message': 'Revoked access token',
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }


class LogoutRefresh(Resource):
    @jwt_refresh_token_required
    def delete(self):
        try:
            jti = get_raw_jwt()['jti']
            revoked_token = RevokedToken(jti=jti)
            add_to_db(revoked_token)
            return {
                'message': 'Revoked access token',
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }


class List(Resource):
    @jwt_required
    def get(self):
        return {'message': 'Accessed secret resource!'}


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        username = get_jwt_identity()
        access_token = create_access_token(identity=username)
        return {
            'access_token': access_token,
            'code': 200
            }