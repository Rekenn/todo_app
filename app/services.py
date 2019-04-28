from app import db


def add_to_db(obj):
    try:
        db.add(obj)
        db.commit()
    except Exception as err:
        print(err)