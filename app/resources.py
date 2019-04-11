from flask_restful import Resource
from flask import request, jsonify
from app.schemas import UserSchema
from app.models import User
from app import db
from marshmallow.exceptions import ValidationError


class UserApi(Resource):
    def post(self):
        pass
    def get(self):
        pass
    def get(self):
        pass
    def put(self):
        pass


class Register(Resource):
    def post(self):
        user_schema = UserSchema()
        try:
            result = user_schema.load(request.get_json())
        except ValidationError:
            return {'message': 'validation error'}, 500
        db.session.add(result.data)
        db.session.commit()
        #return result.data