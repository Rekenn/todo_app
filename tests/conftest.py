import pytest
from app import app, db
from app.models import User
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token

@pytest.fixture(scope='module')
def test_client():
    testing_client = app.test_client()
 
    ctx = app.app_context()
    ctx.push()
 
    yield testing_client

    ctx.pop()

@pytest.fixture(scope='module')
def init_database():
    db.create_all()
 
    user = User(username='testuser', password=generate_password_hash('foobar'))
    db.session.add(user)
 
    yield db

    db.session.remove()

@pytest.fixture(scope='module')
def access_token():
    yield create_access_token(identity='testuser')