import sqlalchemy
from flask_login import UserMixin
from sqlalchemy_serializer import SerializerMixin
from werkzeug.security import generate_password_hash, check_password_hash

from .db_session import SqlAlchemyBase


class User(SqlAlchemyBase, UserMixin, SerializerMixin):
    __tablename__ = 'users'

    id = sqlalchemy.Column(sqlalchemy.Integer,
                           primary_key=True, autoincrement=True)
    email = sqlalchemy.Column(sqlalchemy.String, index=True, unique=True, nullable=True)
    nickname = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    wallet = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
    currency = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    steam_level = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
    hashed_password = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    avatars = sqlalchemy.Column(sqlalchemy.String, default='avatar-184.png')

    def __repr__(self):
        return f'<User> id: {self.id}, nickname: {self.nickname}, steam level: {self.steam_level}'

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)
