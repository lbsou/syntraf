from lib.st_global import CompilationOptions, DefaultValues

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from flask import current_app as app
    from flask import Flask, Response, render_template, request, send_from_directory, current_app, safe_join, jsonify, \
        make_response, flash, redirect, session, abort, url_for, g, Blueprint

    from flask_login import login_required, logout_user, current_user, login_user
    from .st_forms import LoginForm, SignupForm
    from . import login_manager
    from . import db
    from .st_home_bp import User

# Blueprint Configuration
st_auth_bp = Blueprint(
    'st_auth_bp', __name__,
    template_folder='templates',
    static_folder='static'
)

@st_auth_bp.route('/login2', methods=['GET', 'POST'])
def login():
    """
    Log-in page for registered users.

    GET requests serve Log-in page.
    POST requests validate and redirect user to dashboard.
    """
    # Bypass if user is logged in
    if current_user.is_authenticated:
        return redirect(url_for('home.html'))

    form = LoginForm()
    # Validate login attempt
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(password=form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main_bp.dashboard'))
        flash('Invalid username/password combination')
        return redirect(url_for('login2'))
    return render_template(
        'login2.html',
        form=form,
        title='Log in.',
        template='login-page',
        body="Log in with your User account."
    )


@st_auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    pass