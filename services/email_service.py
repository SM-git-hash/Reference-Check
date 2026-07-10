import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from html import escape


logger = logging.getLogger(__name__)

REQUIRED_SMTP_ENV_VARS = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_FROM_EMAIL",
    "SMTP_FROM_NAME",
)


class EmailConfigurationError(RuntimeError):
    """Raised when SMTP settings are incomplete or invalid."""


def _destination_domain(email_address):
    if "@" not in email_address:
        return "unknown"
    return email_address.rsplit("@", 1)[1].lower()


def _smtp_config():
    missing = [name for name in REQUIRED_SMTP_ENV_VARS if not os.environ.get(name)]
    if missing:
        raise EmailConfigurationError(
            "Missing SMTP environment variable(s): " + ", ".join(missing)
        )

    try:
        port = int(os.environ["SMTP_PORT"])
    except ValueError as exc:
        raise EmailConfigurationError("SMTP_PORT must be an integer.") from exc

    return {
        "host": os.environ["SMTP_HOST"],
        "port": port,
        "username": os.environ["SMTP_USERNAME"],
        "password": os.environ["SMTP_PASSWORD"],
        "from_email": os.environ["SMTP_FROM_EMAIL"],
        "from_name": os.environ["SMTP_FROM_NAME"],
    }


def _plain_text_body(referee_name, candidate_name, secure_link):
    return f"""Dear {referee_name},

You have been asked to provide an employment reference for {candidate_name}.

Please complete the secure reference form using the link below:

{secure_link}

This link is unique and can only be used once.

Kind regards,
ReferenceBridge
Bridging Trust in Recruitment
"""


def _html_body(referee_name, candidate_name, secure_link):
    safe_referee_name = escape(referee_name)
    safe_candidate_name = escape(candidate_name)
    safe_secure_link = escape(secure_link, quote=True)

    return f"""\
<!doctype html>
<html>
  <body style="font-family: Arial, sans-serif; color: #172033; line-height: 1.5;">
    <p>Dear {safe_referee_name},</p>
    <p>You have been asked to provide an employment reference for {safe_candidate_name}.</p>
    <p>Please complete the secure reference form using the link below:</p>
    <p>
      <a href="{safe_secure_link}" style="background: #2563eb; color: #ffffff; padding: 12px 16px; text-decoration: none; border-radius: 6px; display: inline-block;">
        Complete secure reference form
      </a>
    </p>
    <p>If the button does not work, copy and paste this link into your browser:</p>
    <p><a href="{safe_secure_link}">{safe_secure_link}</a></p>
    <p>This link is unique and can only be used once.</p>
    <p>Kind regards,<br>ReferenceBridge<br>Bridging Trust in Recruitment</p>
  </body>
</html>
"""


def send_reference_invitation(
    referee_name: str,
    referee_email: str,
    candidate_name: str,
    secure_link: str,
) -> None:
    config = _smtp_config()
    destination_domain = _destination_domain(referee_email)

    message = EmailMessage()
    message["From"] = formataddr((config["from_name"], config["from_email"]))
    message["To"] = referee_email
    message["Reply-To"] = config["username"]
    message["Subject"] = f"Employment reference request for {candidate_name}"
    message.set_content(_plain_text_body(referee_name, candidate_name, secure_link))
    message.add_alternative(
        _html_body(referee_name, candidate_name, secure_link),
        subtype="html",
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(config["host"], config["port"], context=context) as smtp:
            smtp.login(config["username"], config["password"])
            smtp.send_message(message)
    except Exception:
        logger.exception(
            "Reference invitation email failed for destination domain %s",
            destination_domain,
        )
        raise

    logger.info(
        "Reference invitation email sent to destination domain %s",
        destination_domain,
    )
