from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from flask_login import current_user
from app.models import User
from app.utils import validate_password_complexity


class RegistrationForm(FlaskForm):
    """
    Form handling new user registration with strict server-side validation.
    Enforces regex format, email validation, uniqueness checks, and password complexity.
    """
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=30, message="Username must be between 3 and 30 characters."),
            Regexp(
                r"^[a-zA-Z0-9_.-]+$",
                message="Username may only contain letters, numbers, dots, hyphens, and underscores."
            ),
        ]
    )
    email = StringField(
        "Email Address",
        validators=[
            DataRequired(message="Email address is required."),
            Email(message="Please provide a valid email address."),
            Length(max=120, message="Email cannot exceed 120 characters.")
        ]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(min=8, max=128, message="Password must be at least 8 characters long.")
        ]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo("password", message="Passwords must match.")
        ]
    )
    submit = SubmitField("Create Account")

    def validate_password(self, field):
        """Enforce OWASP password complexity rules."""
        is_valid, msg = validate_password_complexity(field.data)
        if not is_valid:
            raise ValidationError(msg)

    def validate_username(self, field):
        """Ensure username is unique (case-insensitive check)."""
        existing = User.query.filter(User.username.ilike(field.data.strip())).first()
        if existing:
            raise ValidationError("This username is already taken. Please choose another.")

    def validate_email(self, field):
        """Ensure email is unique (case-insensitive check)."""
        existing = User.query.filter(User.email.ilike(field.data.strip())).first()
        if existing:
            raise ValidationError("An account with this email address already exists.")


class LoginForm(FlaskForm):
    """
    Form handling user authentication via username or email.
    """
    login_id = StringField(
        "Username or Email",
        validators=[DataRequired(message="Please enter your username or email address.")]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Please enter your password.")]
    )
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Sign In")


class ProfileUpdateForm(FlaskForm):
    """
    Form allowing users to update permitted profile fields.
    Does NOT allow users to change their own role or ID (prevents privilege escalation).
    """
    email = StringField(
        "Email Address",
        validators=[
            DataRequired(message="Email address is required."),
            Email(message="Please enter a valid email address."),
            Length(max=120)
        ]
    )
    bio = TextAreaField(
        "Bio / About Me",
        validators=[Length(max=250, message="Bio must not exceed 250 characters.")]
    )
    submit = SubmitField("Save Changes")

    def validate_email(self, field):
        """Check for collision with other users' emails."""
        candidate = field.data.strip()
        existing = User.query.filter(
            User.email.ilike(candidate),
            User.id != current_user.id
        ).first()
        if existing:
            raise ValidationError("This email address is already in use by another account.")


class ChangePasswordForm(FlaskForm):
    """
    Form allowing authenticated users to change their password after verifying current password.
    """
    current_password = PasswordField(
        "Current Password",
        validators=[DataRequired(message="Current password is required to authorize this change.")]
    )
    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(message="New password is required."),
            Length(min=8, max=128, message="Password must be at least 8 characters.")
        ]
    )
    confirm_new_password = PasswordField(
        "Confirm New Password",
        validators=[
            DataRequired(message="Please confirm your new password."),
            EqualTo("new_password", message="New passwords must match.")
        ]
    )
    submit = SubmitField("Update Password")

    def validate_new_password(self, field):
        """Validate complexity and prevent reuse of same password."""
        is_valid, msg = validate_password_complexity(field.data)
        if not is_valid:
            raise ValidationError(msg)
        if hasattr(self, "current_password") and field.data == self.current_password.data:
            raise ValidationError("New password cannot be identical to current password.")


class EmptyForm(FlaskForm):
    """
    Minimal form containing only CSRF token for state-changing POST actions
    (e.g., Logout, User Deletion, Role Toggling).
    """
    pass
