#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@author:CodeMonster
@file: __init__.py
@time: 2017/10/13 21:26
"""
from flask import Blueprint

auth = Blueprint('auth', __name__)

from . import views