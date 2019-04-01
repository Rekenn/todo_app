import os

class Config:
	SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
	SQLALCHEMY_TRACK_MODIFICATIONS = os.environ['SQLALCHEMY_TRACK_MODIFICATIONS']