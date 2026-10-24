from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError


class LoginForm(FlaskForm):
    """Secure login form with CSRF protection."""
    email = StringField(
        "Work Email",
        validators=[DataRequired(message="Email is required."), Email(message="Enter a valid email address.")],
        render_kw={"placeholder": "you@company.com", "autocomplete": "email"}
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(max=128, message="Password cannot exceed 128 characters.")
        ],
        render_kw={"placeholder": "••••••••", "autocomplete": "current-password"}
    )
    submit = SubmitField("Sign In")


class TenantRegistrationForm(FlaskForm):
    """
    Form to onboard a brand-new company tenant and its initial Admin.
    Public registration can only create a new organization; it cannot join an existing one.
    """
    company_name = StringField(
        "Company Name",
        validators=[DataRequired(), Length(min=2, max=100, message="Company name must be between 2 and 100 characters.")],
        render_kw={"placeholder": "Acme Corporation"}
    )
    full_name = StringField(
        "Admin Full Name",
        validators=[DataRequired(), Length(min=2, max=100, message="Name must be between 2 and 100 characters.")],
        render_kw={"placeholder": "Jane Doe"}
    )
    admin_email = StringField(
        "Admin Work Email",
        validators=[DataRequired(), Email(message="Enter a valid work email.")],
        render_kw={"placeholder": "admin@acme.com", "autocomplete": "email"}
    )
    password = PasswordField(
        "Master Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128, message="Password must be between 8 and 128 characters long.")
        ],
        render_kw={"placeholder": "••••••••", "autocomplete": "new-password"}
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            Length(max=128),
            EqualTo("password", message="Passwords must match exactly.")
        ],
        render_kw={"placeholder": "••••••••", "autocomplete": "new-password"}
    )
    
    # Honeypot field for anti-bot protection: genuine humans won't see or fill this
    website = HiddenField("Website")

    submit = SubmitField("Create Secure Vault")

    def validate_website(self, field: HiddenField) -> None:
        """Reject submission if honeypot field is filled by an automated bot."""
        if field.data:
            raise ValidationError("Automated bot submission detected.")


class ChangePasswordForm(FlaskForm):
    """Form for authenticated users to update their password."""
    current_password = PasswordField(
        "Current Password",
        validators=[DataRequired(), Length(max=128)],
        render_kw={"placeholder": "••••••••"}
    )
    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128, message="Password must be between 8 and 128 characters long.")
        ],
        render_kw={"placeholder": "••••••••"}
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[
            DataRequired(),
            Length(max=128),
            EqualTo("new_password", message="Passwords must match.")
        ],
        render_kw={"placeholder": "••••••••"}
    )
    submit = SubmitField("Update Password")
