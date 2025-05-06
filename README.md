# Template Management System

A web-based system for creating, managing, and exporting markdown templates with editable components.

## Features

- User management system
- Markdown editing with rich text interface
- Template creation with editable input boxes
- Document creation from templates (modoc)
- Export to DOCX and TXT formats

## Project Structure

- `app/` - Core application code
- `database/` - Database models and management
- `static/` - CSS, JavaScript, and other static assets
- `templates/` - HTML templates
- `tests/` - Test cases

## Setup Instructions

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Initialize the database:
   ```
   python app/init_db.py
   ```

3. Run the application:
   ```
   python app/app.py
   ```

## Technology Stack

- Python (Flask web framework)
- SQLite for database
- HTML/CSS/JavaScript for frontend
- python-docx for DOCX export
