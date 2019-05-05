from app import db


todo_lists = db.Table('todo_lists',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('todo_list_id', db.Integer, db.ForeignKey('todo_list.id'), primary_key=True)
)

tasks = db.Table('tasks',
    db.Column('todo_list_id', db.Integer, db.ForeignKey('todo_list.id'), primary_key=True),
    db.Column('task_id', db.Integer, db.ForeignKey('task.id'), primary_key=True)
)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    username = db.Column(db.String(32), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    todo_lists = db.relationship('TodoList', secondary=todo_lists)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return f'<User {self.username}>'


class TodoList(db.Model):
    __tablename__ = 'todo_list'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    name = db.Column(db.String(32), nullable=False)
    users = db.relationship('User', secondary=todo_lists)
    tasks = db.relationship('Task', secondary=tasks)

    def __init__(self, name):
        self.name = name


class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    text = db.Column(db.String(64), nullable=False)
    active = db.Column(db.Boolean, default=True)
    todo_lists = db.relationship('TodoList', secondary=tasks)

    def __init__(self, text):
        self.text = text


class RevokedToken(db.Model):
    __tablename__ = 'revoked_token'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    # jti - unique token identifer
    jti = db.Column(db.String(120), nullable=False, index=True)

    @classmethod
    def is_jti_blacklisted(cls, jti):
        return cls.query.filter_by(jti=jti).first()
