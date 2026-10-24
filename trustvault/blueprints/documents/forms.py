from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Optional, Email


class DocumentUploadForm(FlaskForm):
    """Secure document upload form with size and metadata bounds."""
    title = StringField(
        "Document Title",
        validators=[
            DataRequired(message="Document title is required."),
            Length(min=3, max=200, message="Title must be between 3 and 200 characters long.")
        ]
    )
    category = SelectField(
        "Category",
        choices=[
            ("General", "General"),
            ("Legal", "Legal & Contracts"),
            ("Financial", "Financial Records"),
            ("Engineering", "Engineering & Technical"),
            ("HR", "HR & Operations"),
            ("Confidential", "Confidential / Executive"),
        ],
        default="General",
        validators=[DataRequired()]
    )
    description = TextAreaField(
        "Description (Optional)",
        validators=[
            Optional(),
            Length(max=1000, message="Description cannot exceed 1000 characters.")
        ]
    )
    file = FileField(
        "Confidential Document File",
        validators=[
            FileRequired(message="Please select a document file to upload.")
        ]
    )


class ShareDocumentForm(FlaskForm):
    """Form to grant document access to another active user in the same tenant."""
    recipient_email = StringField(
        "Colleague's Email Address",
        validators=[
            DataRequired(message="Recipient email is required."),
            Email(message="Please enter a valid email address."),
            Length(max=255)
        ]
    )
    permission_level = SelectField(
        "Permission Level",
        choices=[
            ("VIEW_DOWNLOAD", "View Metadata & Download"),
        ],
        default="VIEW_DOWNLOAD",
        validators=[DataRequired()]
    )
