from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from trustvault.models.user import UserRole


class UserProvisionForm(FlaskForm):
    """
    Form for Tenant Admin to provision a new user within their own organization.
    Security: Role choice is strictly constrained to OWNER and VIEWER only.
    Admins cannot create additional ADMIN accounts or self-assign roles.
    """
    full_name = StringField(
        "Full Name",
        validators=[
            DataRequired(message="Full name is required."),
            Length(min=2, max=100, message="Full name must be between 2 and 100 characters.")
        ],
        render_kw={"placeholder": "Jane Smith"}
    )
    email = StringField(
        "Corporate Email Address",
        validators=[
            DataRequired(message="Email address is required."),
            Email(message="Please enter a valid email address."),
            Length(max=255)
        ],
        render_kw={"placeholder": "jane.smith@yourcompany.com", "autocomplete": "off"}
    )
    role = SelectField(
        "Assigned Role",
        choices=[
            (UserRole.VIEWER, "Viewer — Access & download explicitly shared documents"),
            (UserRole.OWNER, "Owner — Upload, organize, share, and manage documents"),
        ],
        default=UserRole.VIEWER,
        validators=[DataRequired(message="Please select a role.")]
    )
    password = PasswordField(
        "Initial Temporary Password",
        validators=[
            DataRequired(message="Temporary password is required."),
            Length(min=8, max=128, message="Password must be between 8 and 128 characters long.")
        ],
        render_kw={"placeholder": "••••••••", "autocomplete": "new-password"}
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm the password."),
            Length(max=128),
            EqualTo("password", message="Passwords must match exactly.")
        ],
        render_kw={"placeholder": "••••••••", "autocomplete": "new-password"}
    )
    submit = SubmitField("Provision Account")

    def validate_role(self, field):
        """Strict server-side defense against forged privilege escalation attempts."""
        allowed_roles = [UserRole.OWNER, UserRole.VIEWER]
        if field.data not in allowed_roles:
            raise ValidationError("Invalid role. Only OWNER and VIEWER accounts may be provisioned.")
