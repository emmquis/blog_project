from datetime import date
from flask import Flask, render_template, url_for, flash, redirect, abort
from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_ckeditor import CKEditor
from forms import RegistrationForm, LoginForm, CreatePost, CommentForm, ContactForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user
import smtplib
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '3f31586573a0a6c66ee4c5c37bc1796b'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
ckeditor = CKEditor(app)

EMAIL_ADDRESS = os.environ["EMAIL_VAR"]
EMAIL_PASSWORD = os.environ["PASS_VAR"]
EMAIL_SMTP = os.environ["SMTP_VAR"]

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    image_file: Mapped[str] = mapped_column(String(20), nullable=False, default='default.jpg')
    posts = relationship("Post", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Post(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(100), nullable=False)
    sub_title: Mapped[str] = mapped_column(String(100), nullable=False)
    date_posted: Mapped[str] = mapped_column(String(250), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("Post", back_populates="comments")


with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
@app.route('/home')
def home():
    result = db.session.execute(db.select(Post))
    posts = result.scalars().all()
    return render_template("home.html", posts=posts, current_user=current_user)


@app.route('/about')
def about():
    return render_template("about.html", title="About", current_user=current_user)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    contact_form = ContactForm()
    if contact_form.validate_on_submit():
        name = contact_form.name.data
        email_address = contact_form.email.data
        text = contact_form.contact_text.data
        # print(name, email_address, text)
        with smtplib.SMTP(EMAIL_SMTP) as connection:
            connection.starttls()
            connection.login(user=EMAIL_ADDRESS, password=EMAIL_PASSWORD)
            connection.sendmail(from_addr=EMAIL_ADDRESS,
                                to_addrs=EMAIL_ADDRESS,
                                msg=f"Subject: Blog Message From {name}\n\n{name}\n{email_address}\n{text}")
        flash("Your message has been sent!", category='success')
        return redirect(url_for('home'))
    return render_template("contact.html", title="Contact", current_user=current_user, form=contact_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if not user:
            flash("That email does not exist, please try again.", category='danger')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again', category='danger')
            return redirect(url_for('login'))
        else:
            login_user(user)
            flash(message='You are logged in!', category='success')
            return redirect(url_for('home'))
    return render_template("login.html", title="Login", form=form, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            flash("You've already signed up with that email, log in instead!", category='danger')
            return redirect(url_for('login'))
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            username=form.username.data,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash(message=f'Account created for {form.username.data}!', category='success')
        return redirect(url_for('home'))
    return render_template("register.html", title="Register", form=form, current_user=current_user)


@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePost()
    if form.validate_on_submit():
        new_post = Post(
            title=form.title.data,
            sub_title=form.sub_title.data,
            content=form.content.data,
            author=current_user,
            date_posted=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("make_post.html", form=form, current_user=current_user)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = db.get_or_404(Post, post_id)
    comment = CommentForm()
    if comment.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.", category='danger')
            return redirect(url_for('login'))
        new_comment = Comment(
            text=comment.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("show_post.html", post=requested_post, comment=comment)


@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(Post, post_id)
    edit_form = CreatePost(
        title=post.title,
        sub_title=post.sub_title,
        author=post.author,
        content=post.content
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.author = current_user
        post.content = edit_form.content.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make_post.html", form=edit_form, current_user=current_user, is_edit=True)


@app.route('/delete/<int:post_id>', methods=['GET', 'POST'])
@admin_only
def delete(post_id):
    post = db.get_or_404(Post, post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/edit-comment/<int:comment_id>', methods=['GET', 'POST'])
@admin_only
def edit_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)
    comment.text = "(deleted due to content)"
    db.session.commit()
    return redirect(url_for('show_post', post_id=comment.post_id))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
