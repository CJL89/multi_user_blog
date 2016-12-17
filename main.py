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

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Blogging Function
class BaseHandler(webapp2.RequestHandler):
    """

    """
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

def render_post(response, post):
    response.out.write('<b>' + post.subject + '<b><br>')
    response.out.write('post.content')

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class MainPage(BaseHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', post= posts)


# Post Function
class Post(db.model):
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

    def post(self, post_id):
        """
        Loops through the posts
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

class NewPostPage(BaseHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            newpost = Post(parent = blog_key(), subject = subject, content = content)
            newpost.put()
            self.redirect('/post/%s' %str(newpost.key().id()))
        else:
            error = "Please enter Subject and Content"
            self.render("newpost.html", subject= subject, content = content, error = error)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/([0-9]+)', PostPage)
                              ], debug=True)
