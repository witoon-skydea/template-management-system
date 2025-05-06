# Template Management System

A web-based system for creating, managing, and exporting markdown templates with editable components.

## Features

- User management system with authentication
- Markdown editing with rich text interface
- Template creation with editable input boxes
- Document creation from templates
- Export to DOCX and TXT formats
- Responsive design with Bootstrap

## Project Structure

- `app/` - Core application code
  - `app.py` - Main Flask application
- `database/` - Database models and management
  - `models.py` - SQLAlchemy models
  - `init_db.py` - Database initialization script
- `static/` - CSS, JavaScript, and other static assets
  - `css/styles.css` - Custom styles
  - `js/main.js` - JavaScript functionality
- `templates/` - HTML templates for the web UI
- `tests/` - Test cases
- `exports/` - Directory for exported documents

## Technology Stack

- Python (Flask web framework)
- SQLite for database (with SQLAlchemy ORM)
- HTML/CSS/JavaScript for frontend
- Bootstrap for responsive design
- SimpleMDE for markdown editing
- python-docx for DOCX export

## Setup Instructions

1. Clone the repository:
   ```
   git clone <repository-url>
   cd template-management-system
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Initialize the database:
   ```
   python database/init_db.py
   ```

5. Run the application:
   ```
   python app/app.py
   ```

6. Access the application in your browser at:
   ```
   http://localhost:6789
   ```

## Usage

### Login
- Default admin credentials:
  - Username: admin
  - Password: admin123

### Templates
- Create templates with markdown formatting
- Use the syntax `*****input-name*****` to create input boxes
- Edit and manage your templates

### Documents
- Create documents from templates
- Fill in the input boxes
- Export documents to DOCX or TXT format

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
