from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# to initialize the gravatar feature to show a simple image in front of the commenter based on their email address
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', back_populates='posts')
    comments = db.relationship('Comment', backref='post')


class User(UserMixin, db.Model):
    __Tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    posts = db.relationship('BlogPost', back_populates='author')
    comments = db.relationship('Comment', backref='commenter')
#     apparently i could do posts = db.relationship('BlogPost', backref='author') here in the parent and delete the
#       author attribute in the child.  The 'backref' is a shortcut that creates them both.  If you use
#       'back_populates' you have to put the attributes in both child and parent.
#       I tried this with the relationship between user and comment.

class Comment(db.Model):
    __Tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    commenter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


# working to keep this in rather than comment out after the database in created.
db.create_all()


# this was a decorator we had to create to make some parts of the website only available to the admin or user #1
# I mostly cut and pasted this but the internal if statements were custom to determine that you only proceeded
# if the user requirements were met.
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id != 1:
                # simple flask function to send a simple message to the screen
                abort(403)
            else:
                return f(*args, **kwargs)
        else:
            abort(403)
    return decorated_function


# cut and past to use the flask login manager.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # check to see if the users email address is already registered
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # flash messages get stored till they are displayed once; then get erased.
            # we do the display in the destination
            flash('You have already signed up with that email. Please login instead.')
            return redirect(url_for('login'))
        else:
            # create a new user with all the fields filled in from the form
            # also using the import to generate a hashed and salted password.
            new_user = User(name=form.name.data, email=form.email.data,
                            password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            # after register, login the user so they don't have to register AND login
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # first to check if this user is already registered and in the database.
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # if so, we check the password to see if matched.
            if check_password_hash(user.password, form.password.data):
                # if so, we log them in and return to the home page.
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                # if not, we flash a message and offer them to login again.
                flash('Your password is incorrect. Please try again.')
                return redirect(url_for('login'))
        else:
            # if user not registered.
            flash('That email does not exist. Please login again or register.')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    # form for new comments to display
    form = CommentForm()
    # get a list of old comments to display. with table relationships, here we only get comments attached to this post.
    comments = requested_post.comments
    if form.validate_on_submit():
        # only want logged in valid user to post, so check that before we store their comment.
        if current_user.is_authenticated:
            comment = Comment(body=form.comment.data, post=requested_post, commenter=current_user)
            db.session.add(comment)
            db.session.commit()
            return render_template('post.html', post=requested_post, form=form, comments=comments)
        else:
            # if not, send them a message.
            flash('You need to login or register to comment.')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
# here we add this decorator so only the admin can post.
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
# and only want the admin to be able to edit a post.
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
