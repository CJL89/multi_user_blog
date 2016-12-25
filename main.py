# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#Dependecies for tha application
import os
import webapp2
import jinja2
import re
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)



def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#Creating a security around using the secret variable

secret = 'test_security'

def make_secure_val(val):
    """
    Creates the secure value using a secret.
    """
    return '%s|%s' %(val, hmac.new(secret, val).hexdigest())
def check_secure_val(secure_val):
    """
    Verification of the secure value against the secret
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        """
        Writes output to client browser
        """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """
        Render HTML Templates
        """
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """
        Creates a cookie to the browser
        """
        cookie_val = self.response.headers.add_header(
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

     def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

     def initialize(self, *a, **kw):
         """
         Initialize the cookie session for the website
         """
         webapp2.RequestHandler.initialize(self, *a, **kw)
         uid = self.read_secure_cookie('user_id')
         self.user = uid and User.by_id(int(uid))



def render_post(response, post):
    response.out.write('<b>' + post.subject + '<b><br>')
    response.out.write('post.content')

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Blogging Function
class MainPage(BaseHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts= posts)



# Post Function
class Post(db.Model):
    """
    Attributes for the Post datastore
    """
    # userid = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)


class PostPage(BaseHandler):
    def get(self, post_id):
        """
        Renders Posts to home page
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)


        if not post:
            self.error(404)
            return
        self.render("permalink.html", post = post)

    def post(self, post_id):
        """
        Loops through the posts
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        self.render("post.html", posts = posts)

class NewPostPage(BaseHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('post_text')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/')
            self.redirect('/blog/%s' %str(p.key().id()))
        else:
            error = "Please enter Subject and Content"
            self.render("newpost.html", subject= subject, content = content, error = error)

# Validation for Username, password, and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#Registration, Login, and Logout for User

class SignUpPage(BaseHandler):
    """
    Still Working on this function.
    Sign Up Page. Getting username, password, email,
    and verification of password from user input.
    """
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "Invalid Username"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Invalid password"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Password does not match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Invalid Email"
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Registration(Signup):
    def done(self):
        """
        Make sure user exists
        """
        u = User.by_name(self.username)

        if u:
            msg = "User name exists"
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.redirect('/')
#User

class User(db.Model):
    """
    Stores user information
    """
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty

    @classmethod
    def by_id(self, uid):
        """
        Returns user id from User object
        """
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(self, name):
        """
        Fetchs users by name from the User object
        """
        u = User.all().filter('name=', name).get()
        return u

    @classmethod
    def register(self, pw, email = None):
        """
        Creates the new user in the User object.
        """
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key,
                    name = name,
                    pw_hash = pw_hash,
                    email = email)





app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPostPage),
                               ('/signup', SignUpPage)
                              ], debug=True)
