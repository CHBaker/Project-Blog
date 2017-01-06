import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import ndb
# initialize Jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
#sets string for hmac
secret = 'dogs'

#global render function for Jinja templates
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#creates new secure value using hmac and secret
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#makes sure secure val is equal to the val in make_secure_val
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#Main Blog Handler inherited by other Handlers
class BlogHandler(webapp2.RequestHandler):
    #simplifies write process
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    #class level render function with self, and user param
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    #class level render function render_str + write
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    #sets cookie to a secure hashed value
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    #gets cookie and checks match for the value
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    #uses cookie to keep user logged in
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    #uses cookie to log user out
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    #checks cookie on every page to keep user logged in
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

#render specific to a post
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

#class for example write
class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### user stuff
#creates password salts, hashes pass, validates hashes' pass
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

#creates user group for multiple blogs
def users_key(group = 'default'):
    return ndb.Key('users', group)

#model stores user info in db
class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()
    user_id = ndb.IntegerProperty()

    #get user by id shortcut
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    #get user by name shortcut
    @classmethod
    def by_name(cls, name):
        u = User.query().filter(ndb.GenericProperty('name')==name).get()
        return u

    #check/validate user pass on signup
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    #checks user and pass for login
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff
# creates parent/ancestor for strong consistancy
def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

# creates parent/ancestor for strong consistancy
def com_key(name = 'default'):
    return ndb.Key('comments', name)

# Post model to store Post info
class Post(ndb.Model, BlogHandler):
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    author = ndb.IntegerProperty(required = True)
    name = ndb.StringProperty(required = True)
    like_count = ndb.IntegerProperty(default = 0)

    #renders post content with <br> instead of \n
    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self, user = user)

#like model stores like info
class Like(ndb.Model, BlogHandler):
    user = ndb.KeyProperty(kind = 'User', required = True)

#Comment model to store comment info
class Comment(ndb.Model, BlogHandler):
    comment = ndb.StringProperty(required = True)
    post = ndb.KeyProperty(kind = 'Post', required = True)
    user = ndb.KeyProperty(kind = 'User', required = True)
    name = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)

#retrieves comments for post and updates with each new comment
class CommentPage(BlogHandler):
    def get(self, post_id):
        post_key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = post_key.get()

        comments = Comment.query(ancestor=com_key()).filter(
                                 Comment.post == post_key).order(
                                 -Comment.created)
        if not self.user:
            self.redirect('/signup')
        if not post:
            self.error(404)
            return

        self.render("comments.html", post = post,
                                     comments = comments)

    def post(self, post_id):
        post_key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = post_key.get()

        if not self.user:
            self.redirect('/signup')
        if not post:
            self.error(404)
            return

        comment = self.request.get('comment')
        user = self.user
        name = self.user.name
        comments = Comment.query(ancestor=com_key()).filter(
                                 Comment.post == post_key).order(
                                 -Comment.created)

        if comment:
            p = Comment(parent = com_key(),
                        comment = comment,
                        post = post.key,
                        user = user.key,
                        name = name)
            p.put()
            self.redirect('/blog/comments/%s' % post_id)
        else:
            error = "no blank comments"
            self.render("comments.html",
                         error = error,
                         post = post,
                         comments = comments)

# Renders Posts for main page by newest post
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.query(ancestor=blog_key()).order(-Post.created)
        self.render('front.html', posts = posts)

    #handles likes for front page
    def post(self):
        post_id = self.request.get("like")

        post_key = ndb.Key('Post', int(post_id), parent = blog_key())

        a_post = post_key.get()

        cur_user = self.user

        print "CUR USER ID", cur_user.key.id()
        likes_q = Like.query(ancestor = post_key).filter(cur_user.key.id() == like.user.key.id())
        print "LIKE USER ID", likes_q.user.id()
        print "### LIKES QU ###", likes

        #increments the likes for the post on click
        if post_key:
            if cur_user:
                if cur_user.key.id() != a_post.author:
                    if likes == []:
                        a_post.like_count + 1
                        a_post.put()
                        print "#LIKE COUNT", a_post.like_count
                        print "#LIKES", likes
                        l = Like(parent = post_key,
                                 user = cur_user.key)
                        l.put()
                        self.redirect('/blog')

                    else:
                        likes[0].delete()
                        a_post.like_count - 1
                        a_post.put()
                        print "LIKE COUNT", a_post.like_count
                        self.redirect('/blog')

#Post handler, after new post, redirect to permalink of post content
class PostPage(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return


        self.render("permalink.html", post = post)

#Handler to create a new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.key.id()
        name = self.user.name

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = author, name = name)
            p.put()
            self.redirect('/blog/%s' % str(p.key.id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

#Handler to Edit Post
class EditPost(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent = blog_key())
        post = key.get()

        if not post:
            return self.error(404)

        if self.user and self.user.key.id() == post.author:
            subject = post.subject
            content = post.content
            self.render("editpost.html", post = post, subject = subject, content = content)
        else:
            self.redirect('/blog')

    def post(self, post_id):
        key = ndb.Key('Post', int(post_id), parent = blog_key())
        post = key.get()

        cancel = self.request.get("cancel")
        if cancel != None:
            self.redirect('/blog')

        elif not self.user and user.key.id() == post.author:
            return self.redirect('/signup')

        #updates post Model with edited subject/content
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            author = self.user.key.id()
            if subject and content:
                post.subject = subject
                post.content = content
                post.author = author
                post.put()
                self.redirect('/blog')
            else:
                error = "subject and content, please!"
                self.render('/blog/editpost/%s' % p.key.id(), subject = subject, content = content, error = error)

#Handler to delete a post
class DeletePost(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent = blog_key())
        post = key.get()

        if not post:
            return self.error(404)

        if not self.user:
            self.redirect("/signup")

        self.render("delete.html", post = post)

    def post(self, post_id):
        yes_delete = self.request.get('delete')

        #checks to make sure user wants to delete post
        if yes_delete != None:
            ndb.Key('Post', int(post_id), parent = blog_key()).delete()
            self.redirect("/blog")
        else:
            self.redirect("/blog")

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)

#sets parameters for user name
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

#sets parameters for password
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

#sets parameters for email
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#handler for users to register
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        ##### errors for invalid inputs
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    #sets flag for console, for succesful signup
    def done(self, *a, **kw):
        raise NotImplementedError

#redirects new user to permalink for welcome page(not in use currently)
class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

#Handler inherits from Signup for user Registration
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

#handler for current users to log in
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        #checks database and confirms values for valid user/pass
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

#Handler for quick logout button on all pages
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

#welcome page for user (not currently in use)
class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')
#welcome page for user, checks values (not currently in use)
class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/comments/([0-9]+)', CommentPage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                               debug=True)
