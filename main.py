import webapp2
import jinja2
import os
import re
import utils
import time
import logging

from models import User
from models import Page

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = False)


class BaseHandler(webapp2.RequestHandler):
	#writes parameters from response
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	#renders Jinja templates with params
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	#renders page with Jinja template and response params
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	#renders page in json
	def render_json(self, d):
		pass

	def set_secure_cookie(self, name, val):
		cookie_val = utils.make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and utils.check_secure_val(cookie_val)

	#sets secure cookie, logs in user
	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	#removes secure cookie, logs out user
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	#initializes when when page is loaded, checks for cookie
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie("user_id")
		self.user = uid and User.by_id(int(uid))



# front of wiki. should return recent pages
class MainPage(BaseHandler):
	def get(self):
		pages = Page.all().order('-last_modified')
		self.render("front.html", pages = pages)


class Signup(BaseHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		#get user input from request
		username = self.request.get('username')
		password = self.request.get('password')
		verify_password = self.request.get('verify_password')
		email = self.request.get('email')
		verify_email = self.request.get('verify_email')
		#set params to be passed back to form if error
		params = dict(username = username, email = email)
		#get users from db
		user = User.by_name(username)
		#check if username already exists, if exists return error
		if user:
			params['exist_error'] = "That username already exists!"
			have_error = True
		#check that username is valid
		if not utils.valid_username(username):
			params['error_username'] = "That's not a valid username!"
			have_error = True
		#check that passoword is valid and passwords match
		if not utils.valid_password(password):
			params['error_password'] = "That's not a valid password!"
			have_error = True
		elif password != verify_password:
			params['error_verify_password'] = "Those passwords don't match!"
			have_error = True
		#check that email is valid and match
		if not utils.valid_email(email):
			params['error_email'] = "That's not a valid email!"
			have_error = True
		# elif email != verify_email:
		# 	params['error_verify_email'] = "Those emails don't match!"
		# 	have_error = True
		#if there is error, rerender form with error params, else redirect to main
		if have_error:
			self.render("signup.html", **params)
		else:
			#store in User table
			u = User.register(username, password, email)
			u.put()
			#set secure cookie
			self.login(u)
			self.redirect('/')


class Login(BaseHandler):
	def get(self):
		self.render("login.html")

	def post(self):
		#get username, password from post
		username = self.request.get("username")
		password = self.request.get("password")

		#create user & check if user already exists
		user = User.login(username, password)
		if user:
			self.login(user)
			self.redirect('/')
		else:
			msg = 'Invalid login!'
			self.render('login.html', error = msg)

#logout
class Logout(BaseHandler):
	def get(self):
		self.logout()
		self.redirect('/')


class CreatePage(BaseHandler):
	def get(self):
		if self.user:
			self.render("createpage.html")
		else: self.redirect("/signup")

	def post(self):
		title = self.request.get("title")
		url = "/" + title.replace(' ', '_')
		if not utils.valid_title(title):
			self.render("createpage.html", 
						title=title, 
						error= "Can only contain letters, numbers, spaces, or parenthesis!")
		elif Page.by_url(url):
			self.render("createpage.html", 
						title=title, 
						error= "That page already exists!")
		else:
			self.redirect(url)


class EditPage(BaseHandler):
	def get(self, url):
		if self.user:
			page = Page.by_url(url)
			if page:
				self.render("newpage.html", 
							title = page.title, 
							content = page.content)
			else:
				title = url[1:].replace('_', ' ')
				self.render("newpage.html", title = title)
		else:
			self.redirect("/signup")

	def post(self, url):
		author = self.user.username
		title = url[1:].replace('_', ' ')
		content = self.request.get('content')

		page = Page.by_url(url)
		if page:
			page.content = content
			page.put()
		else:
			p = Page.save(author, title, content, url)
			p.put()

		time.sleep(0.5) #combat replication lag on local server
		self.redirect('%s' % url)


class WikiPage(BaseHandler):
	def get(self, url):
		page = Page.by_url(url)
		if page:
			self.render("permalink.html", page = page)
		else:
			self.redirect('/_edit' + url)


PAGE_RE = r'(/(?:[()a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/', MainPage),
								('/signup', Signup),
								('/login', Login),
								('/logout', Logout),
								('/new', CreatePage),
								('/_edit' + PAGE_RE, EditPage),
								(PAGE_RE, WikiPage),
								], 
								debug=True)