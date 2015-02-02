import utils

from google.appengine.ext import db


def users_key(group="default"):
    return db.Key.from_path('users', group)


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, username):
        u = User.all().filter('username =', username).get()
        return u

    @classmethod
    def register(cls, username, password, email=None):
        pw_hash = utils.make_pw_hash(username, password)
        return User(parent=users_key(),
                    username=username,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u and utils.valid_pw(username, password, u.pw_hash):
            return u


def page_key(name='default'):
    return db.Key.from_path('pages', name)


class Page(db.Model):
    author = db.StringProperty(required=True)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    url = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_url(cls, url):
        p = Page.all().filter('url = ', url).get()
        return p

    @classmethod
    def save(cls, author, title, content, url):
        return Page(parent=page_key(),
                    author=author,
                    title=title,
                    content=content,
                    url=url)
