from app.models import User, Task
from app import ma
from marshmallow import fields, validate, post_load


class UserSchema(ma.ModelSchema):
    username = fields.Str(validate=validate.Length(min=4, max=32), required=True)
    password = fields.Str(validate=validate.Length(min=6, max=32), required=True)

    class Meta:
        model = User
        strict = True

class TaskSchema(ma.ModelSchema):
    text = fields.Str(validate=validate.Length(min=2, max=64), required=True)

    class Meta:
        model = Task
        strict = True