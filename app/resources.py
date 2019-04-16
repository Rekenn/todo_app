from flask import request, jsonify
from flask_restful import Resource
from flask_jwt_extended import create_access_token, create_refresh_token, \
    jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
from app.schemas import UserSchema
from werkzeug.security import check_password_hash
from app.models import User
from app.services import find_user_by_username
from app import db


class UserApi(Resource):
    def post(self):
        pass
    def get(self):
        pass
    def get(self):
        pass
    def put(self):
        pass


class Login(Resource):
    def post(self):
        user_schema = UserSchema()
        try:
            user = user_schema.load(request.get_json()).data
            existing_user = find_user_by_username(user.username)

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


class List(Resource):
    def post(self):
        pass