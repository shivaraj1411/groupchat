import os
import flask
from flask import Flask, url_for, redirect, render_template, request
from flask_sqlalchemy import SQLAlchemy
from wtforms import form, fields, validators
import flask_admin as admin
import flask_login as login
from flask_admin.contrib import sqla
from flask_admin import helpers, expose
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy_utils import ScalarListType
import enum
import json
from flask_security import roles_required
from emoji import emojize
#from flask_user import current_user, login_required, roles_required, UserManager, UserMixin

# Create Flask application
app = Flask(__name__)

# Create dummy secrey key so we can use sessions
app.config['SECRET_KEY'] = '123456790'

# Create in-memory database
app.config['DATABASE_FILE'] = 'sample_db.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + app.config['DATABASE_FILE']
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)

# Create user model.

class User(db.Model):
    __tablename__='user'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    login = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120))
    password = db.Column(db.String(64))
    groups = db.Column(ScalarListType())
    roles = db.relationship('Role', secondary='user_roles',
    backref=db.backref('users', lazy='dynamic'))

    #chats = db.relationship('Chat',backref='chatuser',lazy=True)

    # Flask-Login integration
    # NOTE: is_authenticated, is_active, and is_anonymous
    # are methods in Flask-Login < 0.3.0
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def get_role(self):
        return self.roles[0].name

    # Required for administrative interface
    def __unicode__(self):
        return self.username
    # Define the Role data model
    
class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True )

# Define the UserRoles data model
class UserRoles(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))

class Group(db.Model):
    __tablename__='group'
    group_id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    group_name = db.Column(db.String(80), unique=True, nullable=False)
    group_members = db.Column(ScalarListType())
    #chats = db.relationship('Chat',backref='chatgroup')

from sqlalchemy import DateTime
from sqlalchemy.sql import func
class Chat(db.Model):
    __tablename__='chat'
    chat_id = db.Column(db.Integer ,primary_key=True, autoincrement=True)
    group_id = db.Column(db.Integer,db.ForeignKey('group.group_id'),nullable=False) 
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'), nullable=False)
    chat_line = db.Column(db.String(200), nullable=False)
    created_at = db.Column(DateTime(timezone=True), server_default=func.now())
    likes = db.Column(db.Integer, nullable=False)
    group = db.relationship('Group')
    user = db.relationship('User')


# Define login and registration forms (for flask-login)
class LoginForm(form.Form):
    login = fields.StringField(validators=[validators.DataRequired()])
    password = fields.PasswordField(validators=[validators.DataRequired()])

    def validate_login(self, field):
        user = self.get_user()

        if user is None:
            raise validators.ValidationError('Invalid user')

        # we're comparing the plaintext pw with the the hash from the db
        if not check_password_hash(user.password, self.password.data):
        # to compare plain text passwords use
        # if user.password != self.password.data:
            raise validators.ValidationError('Invalid password')

    def get_user(self):
        return db.session.query(User).filter_by(login=self.login.data).first()


class RegistrationForm(form.Form):
    login = fields.StringField(validators=[validators.DataRequired()])
    email = fields.StringField(validators=[validators.DataRequired(), validators.Email()])
    password = fields.PasswordField(validators=[validators.DataRequired()])
    role = fields.StringField(validators=[validators.DataRequired()])

    def validate_login(self, field):
        if db.session.query(User).filter_by(login=self.login.data).count() > 0:
            raise validators.ValidationError('Duplicate username')


# Initialize flask-login
def init_login():
    login_manager = login.LoginManager()
    login_manager.init_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(User).get(user_id)


# Create customized model view class
class MyModelView(sqla.ModelView):
    def is_accessible(self):
        return login.current_user.is_authenticated


# Create customized index view class that handles login & registration
class MyAdminIndexView(admin.AdminIndexView):

    @expose('/')
    def index(self):
        if not login.current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        # handle user login
        form = LoginForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = form.get_user()
            login.login_user(user)

        if login.current_user.is_authenticated:
            return redirect(url_for('.index'))
        link = '<p>Don\'t have an account? <a href="' + url_for('.register_view') + '">Click here to register.</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        #else:
        return super(MyAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        form = RegistrationForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = User()

            form.populate_obj(user)
            # we hash the users password to avoid saving it as plaintext in the db,
            # remove to use plain text:
            user.password = generate_password_hash(form.password.data)

            db.session.add(user)
            db.session.commit()

            login.login_user(user)
            return redirect(url_for('.index'))
        link = '<p>Already have an account? <a href="' + url_for('.login_view') + '">Click here to log in.</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        
        #return flask.redirect(flask.url_for('groups'))
        login.logout_user()
        return redirect(url_for('.index'))
    @expose('/groups/')
    def groups_view(self):
        
        return flask.redirect(flask.url_for('groups'))
        #login.logout_user()
        #return redirect(url_for('.index'))


# Flask views
@app.route('/')
def index():
    return render_template('index.html')

# Initialize flask-login
init_login()

import pdb
# Create admin
admin = admin.Admin(app, 'GroupChat', index_view=MyAdminIndexView(), base_template='my_master.html', template_mode='bootstrap4')
#pdb.set_trace()

admin.add_view(MyModelView(User, db.session))
#from flask.ext.admin.contrib.sqla.view import ModelView, func
admin.add_view(MyModelView(Group, db.session))
admin.add_view(MyModelView(Chat, db.session))
# Add view

@app.route('/groups', methods=['GET','POST'])
@login.login_required
#@roles_required('normal')
def groups():
    #pdb.set_trace()
    u = User.query.filter_by(login='admin').first().groups
    if u is None:
        u=[]
        u.append('group1')
        u.append('group2')
        db.session.commit()
    member_groups=""
    #print("in groups",data,login,login.current_user,login.current_user.login,login.current_user.id, login.current_user.roles)
    for i in u:
        member_groups+=f"<h2><input type='submit' name='{i}' value='{i}' formaction=group/{i}/><h2><br>"
    if flask.request.method == 'GET':
        return render_template("chatgroups.html",member_groups=member_groups)
        """f'''
               <form action='group' method='POST'>
                   {member_groups}
               </form>
               '''"""
    
    group = flask.request.form['submit']
    print(f"group={group}")
    return flask.redirect(flask.url_for(group))
    #return 'Groups subscribed:' + data.keys() #flask_login.current_user.id
@app.route('/group/<id>/', methods=['POST','GET'])    
@login.login_required
#@roles_required('normal')
def get_group(id):
    #pdb.set_trace()
    message_str_pre='''<!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8"/>
    <title>Chat Room</title>
    <script src="//ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js"></script>
    <script type=text/javascript>
    var input = document.getElementById("chat-message-input")
        $(function() {
          $('a#chat-message-submit').on('click', function(e) {
            e.preventDefault()
            $.post('/post_group',{
                chat-message-input = data,
            });
            return false;
          });
        });
    </script>
    </head>
    <body>'''
    message_str=[]
    for m in Chat.query.filter_by(group_id=id):
        like_count=Chat.query.filter_by(group_id=id).first().likes
        if like_count:
            message_str.append(f"{m.chat_line} {like_count}"+emojize(":thumbs_up:"))
        else:
            message_str.append(f"{m.chat_line}"+"<br>")
    message_str_post=f'''<form action="/post_group/{id}" enctype="multipart/form-data" method="POST" ><br>
    <input id="chatmessageinput" name="chat-message-input" type="text" size="100"><br>
    <a href=# id="chat-message-submit"><button class='btn btn-default'>Send</button></a></form>'''
    return render_template("chatroom.html",message_str_pre=message_str_pre, message_str=message_str,message_str_post=message_str_post)

from flask import request
@app.route('/post_group/<id>/', methods=['POST','GET'])    
@login.login_required
#@roles_required('normal')
def post_group(id):
    jsdata = request.form['chat-message-input']
    db.session.add(Chat(group_id=id,user_id=login.current_user.id,chat_line=jsdata,likes=0))
    db.session.commit()
    return  redirect(request.referrer)


def build_sample_db():
    """
    Populate a small db with some example entries.
    """

    import string
    import random

    db.drop_all()
    db.create_all()
    # passwords are hashed, to use plaintext passwords instead:
    # test_user = User(login="test", password="test")
    test_user = User(login="test", password=generate_password_hash("test"))
    db.session.add(test_user)

    first_names = [
        'admin', 'normal', 'Harry', 'Amelia', 'Oliver', 'Jack', 'Isabella', 'Charlie','Sophie', 'Mia',
        'Jacob', 'Thomas', 'Emily', 'Lily', 'Ava', 'Isla', 'Alfie', 'Olivia', 'Jessica',
        'Riley', 'William', 'James', 'Geoffrey', 'Lisa', 'Benjamin', 'Stacey', 'Lucy'
    ]
    last_names = [
        '','','Brown', 'Smith', 'Patel', 'Jones', 'Williams', 'Johnson', 'Taylor', 'Thomas',
        'Roberts', 'Khan', 'Lewis', 'Jackson', 'Clarke', 'James', 'Phillips', 'Wilson',
        'Ali', 'Mason', 'Mitchell', 'Rose', 'Davis', 'Davies', 'Rodriguez', 'Cox', 'Alexander'
    ]

    for i in range(len(first_names)):
        user = User()
        user.first_name = first_names[i]
        user.last_name = last_names[i]
        user.login = user.first_name.lower()
        user.email = user.login + "@example.com"
        if user.login in ['admin','normal']:
            user.password = generate_password_hash('secret')
            user.roles.append(Role(name=user.login))
        else:
            user.password = generate_password_hash(''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(10)))
        db.session.add(user)

    #group_ids = [ 1,2,3]
    group_names = [ 'group1', 'group2', 'group3' ]
    group_members = [ 'harry@example.com,amelia@example.com','oliver@example.com,jack@example.com']

    for i in range(len(group_names)):
        group = Group()
        #group.group_id = group_ids[i]
        group.group_name = group_names[i]
        db.session.add(group)
    
    role_names = ['admin','normal']
    for i in range(len(role_names)):
        print(i,role_names[i])
        role= Role()
        #role.role_id = role_ids[i]
        role.r_name = role_names[i]
        db.session.add(role)
    db.session.commit()
    return

if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()
    else:
        print("db exists")

    # Start app
    app.run(debug=True)
