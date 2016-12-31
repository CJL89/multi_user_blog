# Models for the Blogs

from google.appengine.ext import ndb

def blog_key(name='default'):
    return ndb.Key('blogs', name)

class Post(ndb.Model):
    """
    Attributes for the Post datastore
    """
    #userid = db.IntegerProperty(required=True)
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class User(ndb.Model):
    """
    Stores user information
    """
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty

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
    def register(self, name, pw, email = None):
        """
        Creates the new user in the User object.
        """
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key,
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(self, name, pw):
        u = self.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
