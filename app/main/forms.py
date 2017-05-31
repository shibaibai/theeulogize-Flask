#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_wtf import Form
from wtforms import StringField, TextAreaField, SubmitField, \
BooleanField, SelectField, PasswordField
# from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import Length, Required, Email
from wtforms import ValidationError
from flask_pagedown.fields import PageDownField
from ..models import Role, User

class PostForm(Form):
    title = StringField('标题'.decode('utf-8'), validators=[Required(), Length(1, 64)])
    body = PageDownField('正文'.decode('utf-8'), validators=[Required()])
    submit = SubmitField('提交'.decode('utf-8'))

class CommentForm(Form):
    body = PageDownField('输入您的评论'.decode('utf-8'), validators=[Required()])
    submit = SubmitField('提交'.decode('utf-8'))

class EditProfileForm(Form):
    location = StringField('位置'.decode('utf-8'), validators=[Length(0, 64)])
    about_me = TextAreaField('关于自己'.decode('utf-8'))
    submit = SubmitField('提交'.decode('utf-8'))

class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
    Email()])

    username = StringField('用户名'.decode('utf-8'), validators=[Required()])

    confirmed = BooleanField('确认状态'.decode('utf-8'))
    role = SelectField('角色'.decode('utf-8'), coerce=int)
    location = StringField('位置'.decode('utf-8'), validators=[Length(0, 64)])
    about_me = TextAreaField('关于自己'.decode('utf-8'))
    submit = SubmitField('提交'.decode('utf-8'))

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
        for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
        User.query.filter_by(email=field.data).first():
            raise ValidationError('电子邮件已经注册'.decode('utf-8'))

    def validate_username(self, field):
        if field.data != self.user.username and \
        User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已被使用'.decode('utf-8'))

'''class UploadForm(Form):
    photo = FileField(validators=[
        FileAllowed(photos, '只能上传图片'.decode('utf-8')), 
        FileRequired('文件未选择'.decode('utf-8'))])
    submit = SubmitField('上传'.decode('utf-8'))'''

class AdminForm(Form):
    user = SelectField('用户'.decode('utf-8'), coerce=int)
    title = StringField('标题'.decode('utf-8'), validators=[Required()])
    body = TextAreaField('正文'.decode('utf-8'), validators=[Required()])
    submit = SubmitField('提交'.decode('utf-8'))

