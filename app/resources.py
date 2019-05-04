from flask import request, jsonify
from flask_restful import Resource
from flask_jwt_extended import create_access_token, create_refresh_token, \
    jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
from app.schemas import login_schema, register_schema, new_list_schema, delete_list_schema, update_list_schema
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User, TodoList, RevokedToken
from jsonschema import validate
from app import db


class Register(Resource):
    def post(self):
        try:
            register_request = request.get_json()
            validate(instance=register_request, schema=register_schema)
            existing_user = User.query.filter_by(username=register_request['username']).first()

            if existing_user:
                return {
                    'message': 'User already exists',
                    'code': 409
                }

            if register_request['password'] != register_request['password2']:
                return {
                    'message': 'Password does not match',
                    'code': 400
                }

            new_user = User(
                username=register_request['username'],
                password=generate_password_hash(register_request['password'])
            )

            db.session.add(new_user)
            db.session.commit()

            return {
                'message': 'User registered properly',
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }

class Login(Resource):
    def post(self):
        try:
            login_request = request.get_json()
            validate(instance=login_request, schema=login_schema)
            user = User(**login_request)
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
            db.session.add(revoked_token)
            db.session.commit()

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
            db.session.add(revoked_token)
            db.session.commit()

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
        try:
            username = get_jwt_identity()
            user_todo_lists = User.query.filter_by(username=username).first().todo_lists

            return {
                'todo_lists': {todo_list.id: todo_list.name for todo_list in user_todo_lists},
                'code': 200
            }
        except Exception as err:
            return {
                'message': 'Internal server error',
                'code': 500
            }


    @jwt_required
    def post(self):
        try:
            new_list_request = request.get_json()
            validate(schema=new_list_schema, instance=new_list_request)
            username = get_jwt_identity()
            
            new_todo_list = TodoList(name=new_list_request['listname'])

            existing_user = User.query.filter_by(username=username).first()
            existing_user.todo_lists.append(new_todo_list)

            db.session.add(new_todo_list)
            db.session.commit()

            return {
                'message': 'Added new todo list',
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }
    

    @jwt_required
    def put(self):
        try:
            update_list_request = request.get_json()
            validate(schema=update_list_schema, instance=update_list_request)

            todo_list = TodoList.query.get(update_list_request['id'])
            todo_list.name = update_list_request['listname']

            db.session.commit()

            return {
                'message': 'Updated todo list name',
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }

    @jwt_required
    def delete(self):
        try:
            delete_list_request = request.get_json()
            validate(schema=delete_list_schema, instance=delete_list_request)
            username = get_jwt_identity()

            todo_list = TodoList.query.get(delete_list_request['id'])

            db.session.delete(todo_list)
            db.session.commit()

            return {
                'message': 'Deleted todo list',
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        username = get_jwt_identity()
        access_token = create_access_token(identity=username)
        return {
            'access_token': access_token,
            'code': 200
            }