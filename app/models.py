from app import db
from werkzeug.security import generate_password_hash


groups = db.Table('groups',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

tasks = db.Table('tasks',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True),
    db.Column('task_id', db.Integer, db.ForeignKey('task.id'), primary_key=True)
)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    username = db.Column(db.String(32), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)
    groups = db.relationship('Group', secondary=groups)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return '<User {}>'.format(self.username)


class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    name = db.Column(db.String(32), nullable=False)
    tasks = db.relationship('Task', secondary=tasks)


class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    text = db.Column(db.String(64), nullable=False)
    active = db.Column(db.Boolean, default=True)


class RevokedToken(db.Model):
    __tablename__ = 'revoked_token'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    # jti - unique token identifer
    jti = db.Column(db.String(120), nullable=False, index=True)

    @classmethod
    def is_jti_blacklisted(cls, jti):
        return cls.query.filter_by(jti=jti).first()