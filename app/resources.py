from flask_restful import Resource
from app.schemas import UserSchema
from app.models import User

class UserResource(Resource):
    def post(self):
        user_schema = UserSchema()
        user = User(username='Faker', password='default')
        user_schema.dump(user).data

    def get(self):
        pass
    def get(self, user_id):
        pass
    def put(self):
        pass