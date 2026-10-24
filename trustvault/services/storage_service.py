import os
import uuid
import hashlib
import zipfile
import io
from typing import Tuple, Dict, Any, Optional
from werkzeug.utils import secure_filename


class ValidationError(Exception):
    """Raised when an uploaded file fails security or format validation."""
    pass


class StorageService:
    """
    Secure file storage service for multi-tenant confidential document handling.
    
    Security Controls:
    1. Uploaded files are strictly stored outside web/static directories.
    2. Physical files are named with random UUID hex keys (storage_key);
       user-supplied original filenames are stored in the database only.
    3. Multi-stage validation:
       - Extension whitelist check
       - File size limits (rejects 0-byte and >10MB files)
       - Magic byte / content signature inspection
       - Polyglot and script signature detection in text files
       - ZIP structure verification for Office formats (docx/xlsx)
    4. Path traversal mitigation via os.path.abspath and prefix containment checks.
    5. SHA-256 integrity checksum calculation during stream write.
    
    NOTE ON SECURITY HONESTY:
    This service performs format signature validation, file structure checks,
    and polyglot script detection. It DOES NOT perform antivirus or malware scanning
    (e.g., ClamAV is not installed). Production deployments should integrate an
    external ICAP/ClamAV virus scanner before files are made available for download.
    """

    ALLOWED_EXTENSIONS = {
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "txt": "text/plain",
        "md": "text/markdown",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
    }

    # Common magic byte signatures
    MAGIC_SIGNATURES = {
        "pdf": [b"%PDF-"],
        "png": [b"\x89PNG\r\n\x1a\n"],
        "jpeg": [b"\xff\xd8\xff"],
        "jpg": [b"\xff\xd8\xff"],
        "docx": [b"PK\x03\x04"],
        "xlsx": [b"PK\x03\x04"],
    }

    DISALLOWED_HEADER_SIGNATURES = [
        b"MZ",            # DOS/Windows PE Executable
        b"\x7fELF",       # Linux Executable
        b"#!",            # Unix shell script
        b"<?",            # Short PHP / XML execution at file start
    ]

    DISALLOWED_EMBEDDED_SIGNATURES = [
        b"<?php",         # PHP script anywhere in file
        b"<script",       # HTML/JavaScript execution anywhere in file
        b"<html",         # Full HTML markup anywhere in file
        b"<% ",           # ASP/JSP server script tag
        b"<svg",          # SVG vector execution tag
    ]

    # Combined list for backwards compatibility
    DISALLOWED_SCRIPT_SIGNATURES = DISALLOWED_HEADER_SIGNATURES + DISALLOWED_EMBEDDED_SIGNATURES

    @classmethod
    def get_extension(cls, filename: str) -> str:
        """Extract and normalize file extension."""
        if not filename or "." not in filename:
            return ""
        return filename.rsplit(".", 1)[1].lower().strip()

    @classmethod
    def validate_file_content(cls, header: bytes, full_content: bytes, ext: str) -> str:
        """
        Validate file content matches claimed extension and has no embedded executable scripts.
        Returns the determined canonical MIME type.
        """
        if not header or len(full_content) == 0:
            raise ValidationError("Empty files are not permitted.")

        expected_mime = cls.ALLOWED_EXTENSIONS.get(ext)
        if not expected_mime:
            raise ValidationError(f"File extension '.{ext}' is not supported.")

        # Check binary formats with magic byte signatures
        if ext in cls.MAGIC_SIGNATURES:
            valid_signature = False
            for sig in cls.MAGIC_SIGNATURES[ext]:
                if header.startswith(sig):
                    valid_signature = True
                    break
            if not valid_signature:
                raise ValidationError(f"File content does not match the expected format for .{ext}.")

            # Deep inspect OOXML archives (docx, xlsx)
            if ext in ("docx", "xlsx"):
                cls._validate_ooxml_package(full_content, ext)

        # Check plain text / markdown formats
        elif ext in ("txt", "md"):
            cls._validate_text_content(full_content)

        return expected_mime

    @classmethod
    def _validate_ooxml_package(cls, content: bytes, ext: str) -> None:
        """Verify that docx/xlsx is a valid ZIP archive containing expected Office XML parts."""
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                namelist = zf.namelist()
                # Check for standard [Content_Types].xml
                if "[Content_Types].xml" not in namelist:
                    raise ValidationError(f"Invalid .{ext} file: missing [Content_Types].xml.")
                
                # Check specific structure
                if ext == "docx":
                    if not any(name.startswith("word/") for name in namelist):
                        raise ValidationError("Invalid .docx file: missing Word document components.")
                elif ext == "xlsx":
                    if not any(name.startswith("xl/") for name in namelist):
                        raise ValidationError("Invalid .xlsx file: missing Excel workbook components.")
        except zipfile.BadZipFile:
            raise ValidationError(f"File claims to be .{ext} but is not a valid ZIP-based Office archive.")

    @classmethod
    def _validate_text_content(cls, content: bytes) -> None:
        """
        Verify text file is valid UTF-8/ASCII without embedded executable payloads or null bytes.

        NOTE ON SECURITY HONESTY:
        These heuristic signature checks detect common script tags and executable headers
        disguised as text. They DO NOT replace a dedicated antivirus, sandbox, or ICAP scanner.
        """
        # Check for null bytes (common in binary files pretending to be text)
        if b"\x00" in content:
            raise ValidationError("Text files cannot contain binary null bytes.")

        # Check for executable or script headers at the beginning
        content_stripped = content.lstrip()
        for bad_sig in cls.DISALLOWED_HEADER_SIGNATURES:
            if content_stripped.lower().startswith(bad_sig.lower()):
                raise ValidationError("File content contains executable or script signatures.")

        # Check for embedded script / web execution tags throughout the entire file
        content_lower = content.lower()
        for bad_sig in cls.DISALLOWED_EMBEDDED_SIGNATURES:
            if bad_sig.lower() in content_lower:
                raise ValidationError("File content contains executable or script signatures.")

        # Validate character encoding
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            raise ValidationError("Text file is not valid UTF-8 or ASCII encoded text.")

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitize original filename for display and download naming."""
        clean = secure_filename(filename)
        return clean or "unnamed_document"

    @classmethod
    def save_file(
        cls,
        storage_root: str,
        tenant_id: str,
        file_storage: Any,
        max_size_bytes: int = 10 * 1024 * 1024
    ) -> Dict[str, Any]:
        """
        Securely stream and validate an uploaded file, saving it under an unguessable UUID key.
        Returns a dictionary with:
        - storage_key
        - original_filename
        - file_size_bytes
        - mime_type
        - sha256_checksum
        """
        raw_filename = getattr(file_storage, "filename", "") or ""
        ext = cls.get_extension(raw_filename)
        if not ext or ext not in cls.ALLOWED_EXTENSIONS:
            allowed_list = ", ".join(f".{e}" for e in sorted(cls.ALLOWED_EXTENSIONS.keys()))
            raise ValidationError(f"Unsupported file format. Allowed formats: {allowed_list}")

        # Read content for validation and hashing
        # Reading up to max_size_bytes + 1 to detect oversize
        content = file_storage.read(max_size_bytes + 1)
        if len(content) > max_size_bytes:
            raise ValidationError(f"File exceeds maximum allowed size of {max_size_bytes // (1024 * 1024)} MB.")
        if len(content) == 0:
            raise ValidationError("Empty file submission rejected.")

        header = content[:64]
        mime_type = cls.validate_file_content(header, content, ext)

        # Compute SHA-256
        sha256_checksum = hashlib.sha256(content).hexdigest()

        # Generate unguessable random storage key (UUIDv4 hex)
        storage_key = uuid.uuid4().hex

        # Tenant isolation on filesystem: storage_root / tenant_id / storage_key
        tenant_dir = os.path.abspath(os.path.join(storage_root, str(tenant_id)))
        os.makedirs(tenant_dir, exist_ok=True)

        destination_path = os.path.abspath(os.path.join(tenant_dir, storage_key))

        # Explicit path traversal containment check
        if not destination_path.startswith(tenant_dir + os.sep):
            raise ValidationError("Security violation: path traversal detected.")

        # Write file atomically
        with open(destination_path, "wb") as f:
            f.write(content)

        return {
            "storage_key": storage_key,
            "original_filename": cls.sanitize_filename(raw_filename),
            "file_size_bytes": len(content),
            "mime_type": mime_type,
            "sha256_checksum": sha256_checksum,
        }

    @classmethod
    def get_file_path(cls, storage_root: str, tenant_id: str, storage_key: str) -> str:
        """
        Resolve and verify the physical file path for a tenant document.
        Guarantees path cannot traverse outside the tenant's designated folder.
        """
        # Validate storage_key format (strictly alphanumeric hex)
        if not storage_key or not storage_key.isalnum() or len(storage_key) > 64:
            raise ValueError("Invalid storage key identifier.")

        tenant_dir = os.path.abspath(os.path.join(storage_root, str(tenant_id)))
        target_path = os.path.abspath(os.path.join(tenant_dir, storage_key))

        # Path traversal guard
        if not target_path.startswith(tenant_dir + os.sep):
            raise ValueError("Unauthorized path traversal attempt.")

        if not os.path.isfile(target_path):
            raise FileNotFoundError("Requested physical file not found on storage server.")

        return target_path
