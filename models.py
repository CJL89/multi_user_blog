# Models for the Blogs
import main
from google.appengine.ext import ndb

#Blog - User Model
def users_key(group='default'):
    return ndb.Key('users', group)

class User(ndb.Model):
    """
    Stores user information
    """
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

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
        u = User.query().filter(ndb.GenericProperty('name')==name).get()
        return u

    @classmethod
    def register(self, name, pw, email = None):
        """
        Creates the new user in the User object.
        """
        pw_hash = main.make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)


    @classmethod
    def login(self, name, pw):
        u = self.by_name(name)
        if u and main.valid_pw(name, pw, u.pw_hash):
            return u
        else:
            print "Not valid"


# Blog- Post Model
def blog_key(name='default'):
    return ndb.Key('blogs', name)

class Post(ndb.Model):
    """
    Attributes for the Post datastore
    """
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    author = ndb.KeyProperty(kind = 'User')
    likes = ndb.KeyProperty(repeated= True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return main.render_str("post.html", p = self)

    @property
    def comments(self):
        comments = Comment.query().filter(Comment.post == self.key)
        return comments

    @property
    def likes(self):
     """
     Return Like from matching post and self key
     """
     likes = Like.query().filter(Like.post == self.key)
     return like

# Blog - Comment Model
class Comment(ndb.Model):
    """
    Attributes for comments datastore
    """
    post = ndb.KeyProperty(kind = 'Post')
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    author = ndb.KeyProperty(kind = 'User')

 # Blog - Like Model
# class Like(ndb.Model):
#      author = ndb.KeyProperty(kind = 'User')
#      post = ndb.KeyProperty(kind = 'Post')
