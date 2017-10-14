#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@author:CodeMonster
@file: views.py
@time: 2017/10/13 21:27
"""
from flask import render_template,redirect,request,url_for,flash
from . import auth
from flask_login import login_user,login_required,logout_user,current_user
from ..models import User
from .forms import LoginForm,RegistrationForm
from .. import db
from ..email import send_email

@auth.route('/login',methods=['GET','POST'])
# 记住是methods,不是method!!!!!!
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user,form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password')
    return render_template('auth/login.html',form=form)
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))
@auth.route('/register',methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password = form.password.data)
        db.session.add(user)
        db.session.commit()
        # 即便通过配置已经设置了在请求末尾自动提交数据库变化,但是这里也要使用db.session.commit(),因为提交数据库
        # 后才能赋予新用户id值,而确认令牌需要用到id,所以不能延后提交
        token = user.generate_confirmation_token()
        send_email(user.email,"Confirm Your Account","auth/email/confirm",user=user,token=token)
        flash('A confirmation email has been sent to you by email.')
        flash('You can now login.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)
