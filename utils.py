import re
import hashlib
import random
import string
import hmac

from secret import secret_string


#user input validation

def valid_username(username):
	valid = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	return valid.match(username)

def valid_password(password):
	valid = re.compile(r"^.{3,20}$")
	return valid.match(password)

def valid_email(email):
	valid = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
	return not email or valid.match(email)


def valid_title(title):
	valid = re.compile(r"^[ ()a-zA-Z0-9_-]+$")
	return valid.match(title)


# Hash password with salt

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(username, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(username, password, salt)


# secure cookies vals

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret_string, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val