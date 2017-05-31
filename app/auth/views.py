#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from ..models import User, Permission
from .. import db
from .forms import LoginForm, RegistrationForm, ChangeEmailRequestForm, \
ChangePasswordForm, PasswordResetRequestForm, PasswordResetForm
from ..email import send_email

'''import sys 
reload(sys) 
sys.setdefaultencoding('utf8')'''

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint \
                and request.endpoint[:5] != 'auth.' \
                and request.endpoint != 'static' \
                and request.endpoint != 'main.index':
            return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('用户名或密码无效'.decode('utf-8'))
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已注销'.decode('utf-8'))
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, '确认您的帐户'.decode('utf-8'), 'auth/email/confirm', user=user, token=token)
        flash('已通过电子邮件向您发送确认邮件'.decode('utf-8'))
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('您已经确认了您的帐户。谢谢！'.decode('utf-8'))
    else:
        flash('确认链接无效或已过期'.decode('utf-8'))
    return redirect(url_for('main.index'))

@auth.route('/confirm')
@login_required
def resend_confirmation():
    if current_user.confirmed != True:
        token = current_user.generate_confirmation_token()
        send_email(current_user.email, '确认您的帐户'.decode('utf-8'),
                    'auth/email/confirm', user=current_user, token=token)
        flash('新的确认邮件已向您发送'.decode('utf-8'))
        return redirect(url_for('main.index'))
    flash('您的帐号已经确认过了'.decode('utf-8'))
    return redirect(url_for('main.index'))

@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=current_user.email).first()
        if user is not None and user.verify_password(form.password.data):
            if user.can(Permission.COMMENT):
                token = user.generate_email_change_token(form.email.data)
                send_email(form.email.data, '确认您的新邮箱'.decode('utf-8'),
                            'auth/email/change_email', user=user, token=token)
                flash('已通过电子邮件向您发送确认邮件'.decode('utf-8'))
                return redirect(url_for('main.index'))
            flash('您已被封禁无法执行该操作'.decode('utf-8'))
            return redirect(url_for('main.index'))
        flash('密码错误'.decode('utf-8'))
    return render_template('auth/change_email.html', form=form)

@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash('您的电子邮件地址已更新'.decode('utf-8'))
    else:
        flash('确认链接无效或已过期'.decode('utf-8'))
    return redirect(url_for('main.index'))

@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            logout_user()
            flash('您的密码已更新，请您重新登录'.decode('utf-8'))
            return redirect(url_for('main.index'))
        else:
            flash('旧密码错误'.decode('utf-8'))
    return render_template("auth/change_password.html", form=form)

@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_password_reset_token()
            send_email(user.email, '重置您的密码'.decode('utf-8'),
                       'auth/email/reset_password',
                       user=user, token=token)
            flash('重置密码的邮件已向您发送'.decode('utf-8'))
            return redirect(url_for('auth.login'))
        flash('请使用注册时的邮件地址'.decode('utf-8'))
    return render_template('auth/reset_password.html', form=form)

@auth.route('/reset/<username>/<token>', methods=['GET', 'POST'])
def password_reset(username, token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    user = User.query.filter_by(username=username).first()
    if user is not None:
        form = PasswordResetForm()
        if form.validate_on_submit():
            if user.reset_password(token, form.password.data):
                flash('您的密码已更新'.decode('utf-8'))
                return redirect(url_for('auth.login'))
            else:
                flash('确认链接无效或已过期'.decode('utf-8'))
                return redirect(url_for('main.index'))
        return render_template('auth/reset_password.html', form=form)
    flash('没有找到该用户'.decode('utf-8'))
    return redirect(url_for('main.index'))
