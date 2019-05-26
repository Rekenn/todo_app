import pytest
from app import app


@pytest.fixture(scope='module')
def test_client():
    testing_client = app.test_client()
 
    ctx = app.app_context()
    ctx.push()
 
    yield testing_client  # this is where the testing happens!
 
    ctx.pop()

@pytest.fixture(scope='module')
def init_database():
    db.create_all()
 
    user1 = User(username='faker', password='default')
    user2 = User(username='rekaf', password='tluafed')
    db.session.add(user1)
    db.session.add(user2)
 
    db.session.commit()
 
    yield db
 
    db.drop_all()
