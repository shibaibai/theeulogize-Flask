#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User

class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('密码'.decode('utf-8'), validators=[Required()])
    remember_me = BooleanField('保持登陆状态'.decode('utf-8'))
    submit = SubmitField('登陆'.decode('utf-8'))

class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    username = StringField('用户名'.decode('utf-8'), validators=[Required(), Length(1, 64), \
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, '用户名必须只有字母开头，字母，数字，点或下划线'.decode('utf-8'))])
    password = PasswordField('密码'.decode('utf-8'), validators=[\
        Required(), EqualTo('password2', message='两次输入的密码必须匹配'.decode('utf-8'))])
    password2 = PasswordField('确认密码'.decode('utf-8'), validators=[Required()])
    submit = SubmitField('注册'.decode('utf-8'))

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('电子邮件已经注册'.decode('utf-8'))
    
    def vaildate_username(self):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已经注册'.decode('utf-8'))

class ChangeEmailRequestForm(Form):
    email = StringField('新邮箱'.decode('utf-8'), validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField('密码'.decode('utf-8'), validators=[Required()])
    submit = SubmitField('更该电子邮件地址'.decode('utf-8'))

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('电子邮件已经注册'.decode('utf-8'))

class ChangePasswordForm(Form):
    old_password = PasswordField('旧密码'.decode('utf-8'), validators=[Required()])
    password = PasswordField('新密码'.decode('utf-8'), validators=[\
        Required(), EqualTo('password2', message='两次输入的新密码必须匹配'.decode('utf-8'))])
    password2 = PasswordField('确认新密码'.decode('utf-8'), validators=[Required()])
    submit = SubmitField('更改密码'.decode('utf-8'))

class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), \
                                             Email()])
    submit = SubmitField('重置密码'.decode('utf-8'))

class PasswordResetForm(Form):
    password = PasswordField('新密码'.decode('utf-8'), validators=[
        Required(), EqualTo('password2', message='两次输入的新密码必须匹配'.decode('utf-8'))])
    password2 = PasswordField('确认新密码'.decode('utf-8'), validators=[Required()])
    submit = SubmitField('重置密码'.decode('utf-8'))
