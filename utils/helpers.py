"""Utility helper functions."""

import os
import re
from datetime import datetime, timedelta
from markupsafe import escape
from urllib.parse import urlparse


def next_occurrence(target_weekday, target_time, ref):
    """Calculate the next occurrence of a weekday/time combination."""
    diff = (target_weekday - ref.weekday()) % 7
    candidate = ref.replace(
        hour=target_time.hour, minute=target_time.minute, second=0, microsecond=0
    ) + timedelta(days=diff)
    if candidate < ref:
        candidate += timedelta(days=7)
    return candidate


def is_pub_slot(meal_slot):
    """Check if a meal slot is a pub night (Tuesday/Thursday dinner)."""
    slot_date = datetime.strptime(meal_slot["date"], "%Y-%m-%d").date()
    return meal_slot["meal_type"].lower() == "dinner" and slot_date.weekday() in [1, 3]


def validate_csv_upload(file_obj):
    """Validate uploaded CSV file for security.

    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not file_obj:
        return False, "No file provided."

    # Check filename extension
    filename = file_obj.filename or ""
    if not filename:
        return False, "No filename provided."

    # Sanitize and validate filename
    allowed_extensions = {".csv", ".txt"}
    ext = os.path.splitext(filename.lower())[1]
    if ext not in allowed_extensions:
        return False, "Invalid file type. Only .csv and .txt files are allowed."

    # Check for path traversal attempts in filename
    if ".." in filename or "/" in filename or "\\" in filename:
        return False, "Invalid filename."

    return True, None


def parse_markdown(text, content_key=None):
    """Parse basic markdown formatting in text with HTML sanitization."""
    # First, escape all HTML to prevent XSS
    text = str(escape(text))

    # Convert markdown links to HTML (only allow http/https URLs)
    def safe_link(match):
        link_text = match.group(1)
        url = match.group(2)
        # Only allow http, https, and mailto URLs
        if url.startswith(("http://", "https://", "mailto:")):
            # Validate URL structure to prevent javascript: injection via encoded characters
            try:
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https", "mailto"):
                    return link_text
                # Escape any remaining special characters in URL
                safe_url = str(escape(url))
                return f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer">{link_text}</a>'
            except Exception:
                return link_text
        return link_text  # Return just the text if URL is not safe

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", safe_link, text)

    # Convert bold text
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)

    # Convert italic text
    text = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", text)

    # Special handling for meal_rules - convert each line to a bulleted list item
    if content_key == "meal_rules":
        lines = text.split("\n")
        bulleted_lines = []
        for line in lines:
            line = line.strip()
            if line:  # Only add non-empty lines
                bulleted_lines.append(f"<li>{line}</li>")
        if bulleted_lines:
            text = f'<ul>{"".join(bulleted_lines)}</ul>'
        else:
            text = ""
    else:
        # Convert line breaks to HTML for other content
        text = text.replace("\n", "<br>")

    return text


def export_sort_key(row):
    """Sort key for export data: by weekday, meal type, then first name."""
    # Compute weekday (Monday=0, Sunday=6)
    dt = datetime.strptime(row["date"], "%Y-%m-%d").date()
    weekday = dt.weekday()
    # Define meal order mapping; treat 'brunch' as breakfast (order 1)
    meal = row["meal_type"].lower()
    meal_order = {"breakfast": 1, "lunch": 2, "dinner": 3, "brunch": 1}.get(meal, 99)
    # Extract first name from the user's name
    first_name = (row["name"] or "").split()[0].lower() if row["name"] else ""
    return (weekday, meal_order, first_name)
