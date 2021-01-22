import os
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from flaskblog.forms import RegistrationForm, LoginForm, EditProfile, PostForm, ResetPasswordForm, RequestResetForm
from flaskblog import app, db, bcrypt, mail
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
import secrets
import requests
import smtplib
from flask_mail import Message
from threading import Thread


def	news_headlines():
	r = requests.get('http://newsapi.org/v2/top-headlines?country=us&category=science&apiKey=ff22b7a71bb34dac9df5571c99f7c961')
	rq = requests.get('http://newsapi.org/v2/top-headlines?country=us&category=technology&apiKey=ff22b7a71bb34dac9df5571c99f7c961')
	jdata = r.json()
	sdata = rq.json()
	return jdata['articles'],sdata['articles']

@app.route('/')
@app.route('/home')
def index():
	posts,post2 = news_headlines()
	return render_template('home.html', posts=posts,pposts=post2)
	
	
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404
	
@app.errorhandler(500)
def server_error(e):
	return render_template('500.html'), 500
	
@app.errorhandler(403)
def forbidden(e):
	return render_template('403.html'), 403
	
	
@app.route('/about')
def about():
	if current_user.is_authenticated and not current_user.confirmed:
		return redirect(url_for('unconfirmed'))
	return render_template('about.html', title='About')
	
@app.route('/register', methods=['GET','POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(username=form.username.data,email=form.email.data,password=hashed_password)
		db.session.add(user)
		db.session.commit()
		token = user.generate_confirmation_token()
		msg = Message('Confirm Email', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
		msg.body = f'''
				To confirm your account, follow the link:
		{url_for('confirm', token=token, _external=True)}
		link is valid for 1 hour
		'''
		send_email(msg)
		flash(f"Account created for user {form.username.data}!", 'success')
		return redirect(url_for('login'))
	return render_template('register.html', title='Register', form=form)
	
@app.route('/confirm/<token>')
@login_required
def confirm(token):
	if current_user.confirmed:
		return redirect(url_for('index'))
	if current_user.confirm(token):
		db.session.commit()
		flash('You have confirmed your account','success')
	else:
		flash('Confirmation link has expired or is invalid')
	return redirect(url_for('index'))
	

def checker():
	if current_user.is_authenticated and not current_user.confirmed:
		return redirect(url_for('unconfirmed'))
		
@app.route('/unconfirmed')
def unconfirmed():
	if current_user.is_anonymous or current_user.confirmed:
		return redirect(url_for('index'))
	return render_template('unconfirmed.html')
	
@app.route('/confirm')
@login_required
def resend_confirmation():
	token = current_user.generate_confirmation_token()
	msg = Message('Confirm Email', sender=app.config['MAIL_USERNAME'], recipients=[current_user.email])
	msg.body = f'''
			To confirm your account, follow the link:
	{url_for('confirm', token=token, _external=True)}
	link is valid for 1 hour
	'''
	send_email(msg)
	flash('A new confirmation email has been sent to you by email','info')
	return redirect(url_for('index'))

	
@app.route('/login', methods=['GET','POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password,form.password.data):
			login_user(user,remember=form.remember.data)
			next_page = request.args.get('next')
			if current_user.is_authenticated and not current_user.confirmed:
				return redirect(url_for('unconfirmed'))
			return redirect(next_page) if next_page else redirect(url_for('account'))
		else:
			flash('Invalid Credentials', 'danger')
			return redirect(url_for('login'))
	return render_template('login.html', title='Login', form=form)
	

@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('index'))


def save_picture(form_picture):
	rand_hex = secrets.token_hex(8)
	_,ext = os.path.splitext(form_picture.filename)
	picture_fn = rand_hex + ext
	picture_path = os.path.join(app.root_path,'static',picture_fn)
	size = (125,125)
	img = Image.open(form_picture)
	img.thumbnail(size)
	img.save(picture_path)
	return picture_fn
@app.route('/user/profile',methods=['GET','POST'])
@login_required
def profile():
	if current_user.is_authenticated and not current_user.confirmed:
		return redirect(url_for('unconfirmed'))
	form = EditProfile()
	if form.validate_on_submit():
		if form.picture.data:
			picture_file = save_picture(form.picture.data)
			current_user.image_file = picture_file
		current_user.username = form.username.data
		current_user.email = form.email.data
		db.session.commit()
		flash('Account Updated Successfully','success')
		return redirect(url_for('account'))
	elif request.method == 'GET':
		form.username.data = current_user.username
		form.email.data = current_user.email
	image_file = url_for('static',filename=current_user.image_file)
	return render_template('profile.html', title='Profile',image_file=image_file, form=form)

@app.route('/user/home')
@login_required
def account():
	if current_user.is_authenticated and not current_user.confirmed:
		return redirect(url_for('unconfirmed'))
	posts = Post.query.all()
	return render_template('account.html',title='User - Home', posts=posts)

@app.route('/post/new', methods=["GET","POST"])
@login_required
def new_post():
	if current_user.is_authenticated and not current_user.confirmed:
		return redirect(url_for('unconfirmed'))
	form = PostForm()
	if form.validate_on_submit():
		posts = Post(title=form.title.data,content=form.content.data, author=current_user)
		db.session.add(posts)
		db.session.commit()
		flash('Post added successfully','success')
		return redirect(url_for('account'))
	return render_template('create_post.html', title='New-Post',legend='New Post', form=form)

@app.route('/post/<int:post_id>', methods=["GET","POST"])
def post(post_id):
	if current_user.is_authenticated and not current_user.confirmed:
		return redirect(url_for('unconfirmed'))
	post = Post.query.get_or_404(post_id)
	return render_template('post.html',title='Post-Content',post=post)

@app.route('/post/<int:post_id>/update', methods=["GET","POST"])
@login_required
def update_post(post_id):
	if current_user.is_authenticated and not current_user.confirmed:
		return redirect(url_for('unconfirmed'))
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	form = PostForm()
	if form.validate_on_submit():
		post.title = form.title.data
		post.content = form.content.data
		db.session.commit()
		flash('Your post has been updated!','success')
		return redirect(url_for('post', post_id=post.id))
	elif request.method == 'GET':
		form.title.data = post.title
		form.content.data = post.content
	return render_template('create_post.html', title='Update-Post', legend='Update Post', form=form)

@app.route('/post/<int:post_id>/delete', methods=["POST"])
@login_required
def delete_post(post_id):
	if current_user.is_authenticated and not current_user.confirmed:
		return redirect(url_for('unconfirmed'))
	post = Post.query.get_or_404(post_id)
	if post.author !=  current_user:
		abort(403)
	db.session.delete(post)
	db.session.commit()
	flash('Post deleted successfully','success')
	return redirect(url_for('account'))

@app.route('/reset_password', methods=['GET','POST'])
def reset_request():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = RequestResetForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		token = user.get_reset_token()
		msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
		msg.body = f'''
				To reset your password, follow the link:
		{url_for('reset_password', token=token, _external=True)}
		link is valid for 30 minutes
	
		If you didn't make this request, kindly ignore
		'''
		send_email(msg)
		flash('Password reset email has been sent to your email','info')
		return redirect('login')
	return render_template('reset_request.html', title='Reset Request', form=form)


def send_async_email(app, msg):
	with app.app_context():
		mail.send(msg)


def send_email(msg):
	thr = Thread(target=send_async_email, args=[app, msg])
	thr.start()
	return thr


	
@app.route('/reset_password/<token>', methods=['GET','POST'])
def reset_password(token):
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	user = User.verify_reset_token(token)
	if user is None:
		flash('Token is invalid or expired','warning')
		return redirect(url_for('reset_request'))
	form = ResetPasswordForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user.password = hashed_password
		db.session.commit()
		flash(f"Password reset successful!", 'success')
		return redirect(url_for('login'))
	return render_template('reset_password.html', title='Reset Request', form=form)
	
