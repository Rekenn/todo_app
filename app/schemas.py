from app.models import User
from app import ma

class UserSchema(ma.ModelSchema):
    class Meta:
        model = User
