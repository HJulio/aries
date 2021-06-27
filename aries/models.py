from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional, Type

import bcrypt
from peewee import (JOIN, BlobField, BooleanField, DateTimeField,
                    ForeignKeyField, IntegerField, Model, SqliteDatabase,
                    TextField)


def init_db(filename: str = ":memory:") -> SqliteDatabase:
    """
    Bind an SQLite database to the Peewee ORM models.
    """
    db = SqliteDatabase(filename)
    db.bind(AriesModel.model_registry)
    db.create_tables(AriesModel.model_registry)
    return db


def get_uuid() -> str:
    return uuid.uuid4().hex


class AriesModel(Model):
    """
    Base pewee model
    """

    model_registry: List[Type[AriesModel]] = []

    @classmethod
    def validate_model(cls):
        if cls.__name__ != "AriesModel":
            cls.model_registry.append(cls)
        return super().validate_model()


class User(AriesModel):

    """
    A user account corresponding to a TLS client certificate.
    """

    user_id = TextField(unique=True, index=True, default=get_uuid)
    username: str = TextField()
    created_at = DateTimeField(default=datetime.now)
    password = BlobField(null=True)

    @classmethod
    def login(cls, fingerprint: str) -> Optional[Certificate]:
        """
        Load a user from their certificate fingerprint.

        Join on the active_plant to avoid making an extra query, since we will
        almost always access the user's plant later.
        """
        query = (
            Certificate.select()
            .join(User, on=Certificate.user == User.id)
            .where(Certificate.fingerprint == fingerprint)
        )

        try:
            cert = query.get()
            cert.update(last_seen=datetime.now())
            cert.save()
        except Certificate.DoesNotExist:
            cert = None

        return cert

    def set_password(self, password: str) -> None:
        self.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def check_password(self, password: str) -> bool:
        if not self.password:
            return False
        return bcrypt.checkpw(password.encode(), self.password)


class Certificate(AriesModel):
    """
    A client certificate used for user authentication.
    """

    user = ForeignKeyField(User, backref="certificates")
    authorised = BooleanField(default=False)
    fingerprint = TextField(unique=True, index=True)
    subject = TextField(null=True)
    not_valid_before_utc = DateTimeField(null=True)
    not_valid_after_utc = DateTimeField(null=True)
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)


class Star(AriesModel):

    user = ForeignKeyField(User, backref="stars")
    created_at = DateTimeField(default=datetime.now)
    text = TextField()
