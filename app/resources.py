from flask import request, jsonify
from flask_restful import Resource
from flask_jwt_extended import create_access_token, create_refresh_token, \
    jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User, TodoList, Task, RevokedToken
from jsonschema import validate
from app import db
from app.schemas import login_schema, register_schema, new_list_schema, \
    update_list_schema, new_task_schema, update_task_schema, search_user_schema


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
            user = User(
                username=login_request['username'],
                password=login_request['password']
            )
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


class TodoLists(Resource):
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


class SingleTodoList(Resource):
    @jwt_required
    def put(self, list_id):
        try:
            update_list_request = request.get_json()
            validate(schema=update_list_schema, instance=update_list_request)
            username = get_jwt_identity()

            if not User.contains_todo_list(username, list_id):
                return {
                    'message': 'List not found',
                    'code': 404
                }

            todo_list = TodoList.query.get(list_id)
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
    def delete(self, list_id):
        try:
            username = get_jwt_identity()

            if not User.contains_todo_list(username, list_id):
                return {
                    'message': 'List not found',
                    'code': 404
                }

            todo_list = TodoList.query.get(list_id)

            if todo_list.users:
                todo_list.users.remove(User.query.filter_by(username=username).first())
            else:
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


class Tasks(Resource):
    @jwt_required
    def get(self, list_id):
        try:
            username = get_jwt_identity()

            if not User.contains_todo_list(username, list_id):
                return {
                    'message': 'List not found',
                    'code': 404
                }

            todo_list = TodoList.query.get(list_id)
            return {
                'tasks': [
                    {
                        'id': task.id,
                        'text': task.text,
                        'active': task.active
                    }
                    for task in todo_list.tasks
                ],
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }

    @jwt_required
    def post(self, list_id):
        try:
            new_task_request = request.get_json()
            validate(schema=new_task_schema, instance=new_task_request)
            username = get_jwt_identity()

            if not User.contains_todo_list(username, list_id):
                return {
                    'message': 'List not found',
                    'code': 404
                }

            todo_list = TodoList.query.get(list_id)
            new_task = Task(text=new_task_request['text'])
            todo_list.tasks.append(new_task)

            db.session.add(new_task)
            db.session.commit()

            return {
                'message': 'Added new task',
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }


class SingleTask(Resource):
    @jwt_required
    def put(self, list_id, task_id):
        try:
            update_task_request = request.get_json()
            validate(schema=update_task_schema, instance=update_task_request)
            username = get_jwt_identity()

            if not User.contains_todo_list(username, list_id):
                return {
                    'message': 'List not found',
                    'code': 404
                }

            task = Task.query.get(task_id)
            task.text = update_task_request['text']
            task.active = update_task_request['active']

            db.session.commit()

            return {
                'message': 'Task updated',
                'code': 200
            }

        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }

    @jwt_required
    def delete(self, list_id, task_id):
        try:
            username = get_jwt_identity()

            if not User.contains_todo_list(username, list_id):
                return {
                    'message': 'List not found',
                    'code': 404
                }

            task = Task.query.get(task_id)

            db.session.delete(task)
            db.session.commit()

            return {
                'message': 'Deleted task',
                'code': 200
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }


class InviteUser(Resource):
    @jwt_required
    def post(self, list_id, user_id):
        try:
            username = get_jwt_identity()

            if not User.contains_todo_list(username, list_id):
                return {
                    'message': 'List not found',
                    'code': 404
                }

            invited_user = User.query.get(user_id)

            if not invited_user:
                return {
                    'message': 'User not found',
                    'code': 404
                }

            todo_list = TodoList.query.get(list_id)

            if invited_user not in todo_list.users:
                todo_list.users.append(invited_user)
                db.session.commit()
                return {
                    'message': 'User invited',
                    'code': 200
                }

            return {
                'message': 'User already in todo list',
                'code': 409
            }
        except Exception as err:
            print(err)
            return {
                'message': 'Internal server error',
                'code': 500
            }


class SearchUser(Resource):
    @jwt_required
    def post(self):
        try:
            search_user_request = request.get_json()
            validate(schema=search_user_schema, instance=search_user_request)

            expression = search_user_request['username']
            found_users = User.query.filter(User.username.like(f'%{expression}%')).limit(10).all()

            if not found_users:
                return {
                    'message': 'User not found',
                    'code': 404
                }

            return {
                'users': [
                    {
                        'id': user.id,
                        'username': user.username
                    }
                    for user in found_users
                ],
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
