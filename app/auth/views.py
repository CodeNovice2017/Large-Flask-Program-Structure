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

@auth.before_app_request
# 使用before_request或before_app_request的钩子函数,如果回调返回响应或者重定向,
# Flask会直接将其发送至客户端,而不会调用请求的视图函数,因此这些回调可以在必要时候拦截请求
def before_request():
    if current_user.is_authenticated \
        and not current_user.confirmed \
        and request.endpoint[:5] != 'auth.'\
        and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

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
@auth.route('/confirm/<token>')
# FLask-Login提供的login_required修饰器会保护这个路由,因此,用户点击确认邮件中的链接后,要先登录,才能执行这个视图函数
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))