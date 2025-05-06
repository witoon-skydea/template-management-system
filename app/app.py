import os
import sys
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from passlib.hash import pbkdf2_sha256
import markdown
import json
import re
from docx import Document as DocxDocument
import bleach
from functools import wraps

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sqlalchemy.orm import joinedload
from database.models import init_db, get_session, User, Template, InputBox, Document, DocumentInputValue

# Configure application
app = Flask(__name__, 
            static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static"),
            template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates"))
app.config['SECRET_KEY'] = 'template-management-secret-key'

# Configure database
db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database", "template_management.db")
engine = init_db(db_path)

# Configure login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    db_session = get_session(engine)
    user = db_session.query(User).get(int(user_id))
    db_session.close()
    return user

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def extract_input_boxes(content):
    """
    Extract input boxes from markdown content using the *****input-box***** syntax
    Returns a list of box IDs
    """
    pattern = r'\*\*\*\*\*(.*?)\*\*\*\*\*'
    input_boxes = re.findall(pattern, content)
    return input_boxes

def markdown_to_html(md_content):
    """
    Convert markdown to HTML with enhanced extensions for better rendering
    """
    try:
        # Use more extensions for better markdown rendering
        extensions = [
            'markdown.extensions.extra',
            'markdown.extensions.codehilite',
            'markdown.extensions.nl2br',  # Convert line breaks to <br>
            'markdown.extensions.sane_lists',
            'markdown.extensions.smarty',
            'markdown.extensions.tables',
        ]
        
        html = markdown.markdown(md_content, extensions=extensions)
        
        # Use bleach to clean but allow most HTML tags for proper rendering
        # Convert frozenset to list before adding additional tags
        additional_tags = [
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div', 'span', 'br', 'hr',
            'table', 'thead', 'tbody', 'tr', 'th', 'td', 'pre', 'code', 'blockquote'
        ]
        allowed_tags = list(bleach.sanitizer.ALLOWED_TAGS) + additional_tags
        
        allowed_attributes = {
            **bleach.sanitizer.ALLOWED_ATTRIBUTES,
            'img': ['src', 'alt', 'title'],
            '*': ['class', 'id', 'style'],
        }
        
        clean_html = bleach.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        
        return clean_html
    except Exception as e:
        # If there's any error during markdown rendering, return a simple error message
        error_html = f"<div class='alert alert-danger'>Error rendering content: {str(e)}</div>"
        return error_html

def create_docx(document_id):
    """
    Create a docx file from a document with improved markdown formatting
    """
    db_session = get_session(engine)
    document = db_session.query(Document).get(document_id)
    
    if not document:
        db_session.close()
        return None
    
    # Get rendered content
    content = document.get_rendered_content()
    
    # Create docx
    docx = DocxDocument()
    docx.add_heading(document.title, 0)
    
    # Process markdown content with better formatting
    lines = content.split('\n')
    current_paragraph = []
    in_list = False
    list_items = []
    
    for line in lines:
        # Handle headers
        if line.startswith('#'):
            # Add any accumulated paragraph text
            if current_paragraph:
                p = docx.add_paragraph(''.join(current_paragraph))
                current_paragraph = []
            
            # Add header with appropriate level
            level = len(re.match(r'^#+', line).group(0))
            header_text = line.lstrip('#').strip()
            docx.add_heading(header_text, level)
            continue
        
        # Handle list items
        if line.strip().startswith('- ') or line.strip().startswith('* '):
            if not in_list:
                # Add any accumulated paragraph text before starting list
                if current_paragraph:
                    p = docx.add_paragraph(''.join(current_paragraph))
                    current_paragraph = []
                in_list = True
            
            list_items.append(line.strip()[2:].strip())
            continue
        elif in_list and line.strip() == '':
            # End of list, add the list items
            for item in list_items:
                p = docx.add_paragraph(item, style='List Bullet')
            list_items = []
            in_list = False
            continue
        elif in_list:
            # Continuation of a list item (indented content)
            if line.strip():
                list_items[-1] += ' ' + line.strip()
            continue
        
        # Handle regular paragraph text
        if line.strip() == '' and current_paragraph:
            # Empty line marks the end of a paragraph
            p = docx.add_paragraph(''.join(current_paragraph))
            current_paragraph = []
        elif line.strip():
            # Process inline markdown in the line
            formatted_line = line
            # Handle bold text
            formatted_line = re.sub(r'\*\*(.*?)\*\*', lambda m: m.group(1), formatted_line)
            # Handle italic text
            formatted_line = re.sub(r'\*(.*?)\*', lambda m: m.group(1), formatted_line)
            # Handle links
            formatted_line = re.sub(r'\[(.*?)\]\((.*?)\)', lambda m: m.group(1), formatted_line)
            
            current_paragraph.append(formatted_line + ' ')
    
    # Add any remaining paragraph text
    if current_paragraph:
        p = docx.add_paragraph(''.join(current_paragraph))
    
    # Add any remaining list items
    if list_items:
        for item in list_items:
            p = docx.add_paragraph(item, style='List Bullet')
    
    db_session.close()
    return docx

# Routes
@app.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template('login.html')
        
        db_session = get_session(engine)
        user = db_session.query(User).filter_by(username=username).first()
        
        if user and pbkdf2_sha256.verify(password, user.password_hash):
            login_user(user)
            db_session.close()
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'danger')
        db_session.close()
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        db_session = get_session(engine)
        
        # Check if username or email already exists
        existing_user = db_session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('Username or email already exists', 'danger')
            db_session.close()
            return render_template('register.html')
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=pbkdf2_sha256.hash(password),
            is_admin=False,
            is_active=True
        )
        
        db_session.add(new_user)
        db_session.commit()
        db_session.close()
        
        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logout route"""
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Admin user management page"""
    db_session = get_session(engine)
    users = db_session.query(User).all()
    db_session.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/<int:user_id>/suspend')
@login_required
@admin_required
def admin_suspend_user(user_id):
    """Suspend a user"""
    db_session = get_session(engine)
    user = db_session.query(User).get(user_id)
    
    if not user:
        db_session.close()
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    
    # Prevent suspending the admin account
    if user.username == 'admin':
        db_session.close()
        flash('Cannot suspend admin account', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_active = False
    db_session.commit()
    db_session.close()
    
    flash(f'User {user.username} has been suspended', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/activate')
@login_required
@admin_required
def admin_activate_user(user_id):
    """Activate a suspended user"""
    db_session = get_session(engine)
    user = db_session.query(User).get(user_id)
    
    if not user:
        db_session.close()
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_active = True
    db_session.commit()
    db_session.close()
    
    flash(f'User {user.username} has been activated', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete')
@login_required
@admin_required
def admin_delete_user(user_id):
    """Delete a user"""
    db_session = get_session(engine)
    user = db_session.query(User).get(user_id)
    
    if not user:
        db_session.close()
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    
    # Prevent deleting the admin account
    if user.username == 'admin':
        db_session.close()
        flash('Cannot delete admin account', 'danger')
        return redirect(url_for('admin_users'))
    
    # Delete all user's documents and templates
    db_session.query(Document).filter_by(creator_id=user.id).delete()
    db_session.query(Template).filter_by(creator_id=user.id).delete()
    
    # Delete the user
    db_session.delete(user)
    db_session.commit()
    db_session.close()
    
    flash(f'User {user.username} has been deleted', 'success')
    return redirect(url_for('admin_users'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing templates and documents"""
    db_session = get_session(engine)
    
    # Get user's templates
    templates = db_session.query(Template).filter_by(creator_id=current_user.id).all()
    
    # Get user's documents, eagerly loading the template relationship to prevent DetachedInstanceError
    documents = db_session.query(Document).options(joinedload(Document.template)).filter_by(creator_id=current_user.id).all()
    
    db_session.close()
    
    return render_template('dashboard.html', templates=templates, documents=documents)

@app.route('/templates/create', methods=['GET', 'POST'])
@login_required
def create_template():
    """Create a new template"""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        content = request.form.get('content')
        
        if not title or not content:
            flash('Title and content are required', 'danger')
            return render_template('create_template.html')
        
        # Extract input boxes
        input_boxes = extract_input_boxes(content)
        
        db_session = get_session(engine)
        
        # Create template
        new_template = Template(
            title=title,
            description=description,
            content=content,
            creator_id=current_user.id
        )
        
        db_session.add(new_template)
        db_session.flush()  # Flush to get the ID
        
        # Create input boxes
        for i, box_id in enumerate(input_boxes):
            input_box = InputBox(
                box_id=box_id,
                template_id=new_template.id,
                label=box_id,  # Use box_id as label by default
                position=i
            )
            db_session.add(input_box)
        
        db_session.commit()
        db_session.close()
        
        flash('Template created successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('create_template.html')

@app.route('/templates/<int:template_id>')
@login_required
def view_template(template_id):
    """View a template"""
    db_session = get_session(engine)
    # Eagerly load the input_boxes relationship to prevent DetachedInstanceError
    template = db_session.query(Template).options(joinedload(Template.input_boxes)).get(template_id)
    
    if not template:
        db_session.close()
        flash('Template not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the user is the creator
    if template.creator_id != current_user.id:
        db_session.close()
        flash('You do not have permission to view this template', 'danger')
        return redirect(url_for('dashboard'))
    
    # Convert markdown to HTML
    html_content = markdown_to_html(template.content)
    
    db_session.close()
    
    return render_template('view_template.html', template=template, html_content=html_content)

@app.route('/templates/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_template(template_id):
    """Edit a template"""
    db_session = get_session(engine)
    # Eagerly load the input_boxes relationship to prevent DetachedInstanceError
    template = db_session.query(Template).options(joinedload(Template.input_boxes)).get(template_id)
    
    if not template:
        db_session.close()
        flash('Template not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the user is the creator
    if template.creator_id != current_user.id:
        db_session.close()
        flash('You do not have permission to edit this template', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        content = request.form.get('content')
        
        if not title or not content:
            flash('Title and content are required', 'danger')
            return render_template('edit_template.html', template=template)
        
        # Extract input boxes
        new_input_boxes = extract_input_boxes(content)
        
        # Update template
        template.title = title
        template.description = description
        template.content = content
        
        # Delete old input boxes and create new ones
        db_session.query(InputBox).filter_by(template_id=template.id).delete()
        db_session.flush()
        
        # Create input boxes
        for i, box_id in enumerate(new_input_boxes):
            input_box = InputBox(
                box_id=box_id,
                template_id=template.id,
                label=box_id,  # Use box_id as label by default
                position=i
            )
            db_session.add(input_box)
        
        db_session.commit()
        
        flash('Template updated successfully', 'success')
        return redirect(url_for('view_template', template_id=template.id))
    
    db_session.close()
    
    return render_template('edit_template.html', template=template)

@app.route('/templates/<int:template_id>/create_document', methods=['GET', 'POST'])
@login_required
def create_document(template_id):
    """Create a document from a template"""
    db_session = get_session(engine)
    # Eagerly load the input_boxes relationship to prevent DetachedInstanceError
    template = db_session.query(Template).options(joinedload(Template.input_boxes)).get(template_id)
    
    if not template:
        db_session.close()
        flash('Template not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get input boxes for the template
    input_boxes = db_session.query(InputBox).filter_by(template_id=template.id).order_by(InputBox.position).all()
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        
        if not title:
            flash('Title is required', 'danger')
            return render_template('create_document.html', template=template, input_boxes=input_boxes)
        
        # Create document
        document = Document(
            title=title,
            description=description,
            template_id=template.id,
            creator_id=current_user.id
        )
        
        db_session.add(document)
        db_session.flush()  # Flush to get the ID
        
        # Create input values
        for input_box in input_boxes:
            value = request.form.get(f'input_{input_box.id}', '')
            
            input_value = DocumentInputValue(
                document_id=document.id,
                input_box_id=input_box.id,
                value=value
            )
            db_session.add(input_value)
        
        db_session.commit()
        
        flash('Document created successfully', 'success')
        return redirect(url_for('view_document', document_id=document.id))
    
    db_session.close()
    
    return render_template('create_document.html', template=template, input_boxes=input_boxes)

@app.route('/documents/<int:document_id>')
@login_required
def view_document(document_id):
    """View a document"""
    db_session = get_session(engine)
    
    # Eagerly load the template relationship and input_values with input_box to prevent DetachedInstanceError
    document = db_session.query(Document).options(
        joinedload(Document.template),
        joinedload(Document.input_values).joinedload(DocumentInputValue.input_box)
    ).get(document_id)
    
    if not document:
        db_session.close()
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the user is the creator
    if document.creator_id != current_user.id:
        db_session.close()
        flash('You do not have permission to view this document', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Get rendered content
        rendered_content = document.get_rendered_content()
        
        # Convert markdown to HTML
        html_content = markdown_to_html(rendered_content)
    except Exception as e:
        db_session.close()
        flash(f'Error rendering document: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get input values and filter out any with null input_box
    input_values = [v for v in document.input_values if v.input_box is not None]
    
    # Create a dictionary with input_box_id -> value
    input_value_dict = {value.input_box_id: value for value in input_values}
    
    # Get input boxes
    input_boxes = db_session.query(InputBox).filter_by(template_id=document.template_id).order_by(InputBox.position).all()
    
    db_session.close()
    
    return render_template('view_document.html', 
                          document=document, 
                          html_content=html_content, 
                          input_boxes=input_boxes,
                          input_value_dict=input_value_dict)

@app.route('/documents/<int:document_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_document(document_id):
    """Edit a document"""
    db_session = get_session(engine)
    # Eagerly load the template relationship to prevent DetachedInstanceError
    document = db_session.query(Document).options(joinedload(Document.template)).get(document_id)
    
    if not document:
        db_session.close()
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the user is the creator
    if document.creator_id != current_user.id:
        db_session.close()
        flash('You do not have permission to edit this document', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get input boxes for the template
    input_boxes = db_session.query(InputBox).filter_by(template_id=document.template_id).order_by(InputBox.position).all()
    
    # Get input values
    input_values = db_session.query(DocumentInputValue).filter_by(document_id=document.id).all()
    # Create a dictionary with input_box_id -> value
    input_value_dict = {value.input_box_id: value.value for value in input_values}
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        
        if not title:
            flash('Title is required', 'danger')
            return render_template('edit_document.html', document=document, input_boxes=input_boxes, input_value_dict=input_value_dict)
        
        # Update document
        document.title = title
        document.description = description
        
        # Update input values
        for input_box in input_boxes:
            value = request.form.get(f'input_{input_box.id}', '')
            
            # Get existing value or create new one
            input_value = db_session.query(DocumentInputValue).filter_by(
                document_id=document.id,
                input_box_id=input_box.id
            ).first()
            
            if input_value:
                input_value.value = value
            else:
                input_value = DocumentInputValue(
                    document_id=document.id,
                    input_box_id=input_box.id,
                    value=value
                )
                db_session.add(input_value)
        
        db_session.commit()
        
        flash('Document updated successfully', 'success')
        return redirect(url_for('view_document', document_id=document.id))
    
    db_session.close()
    
    return render_template('edit_document.html', 
                          document=document, 
                          input_boxes=input_boxes, 
                          input_value_dict=input_value_dict)

@app.route('/documents/<int:document_id>/export/docx')
@login_required
def export_docx(document_id):
    """Export a document to docx"""
    db_session = get_session(engine)
    document = db_session.query(Document).get(document_id)
    
    if not document:
        db_session.close()
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the user is the creator
    if document.creator_id != current_user.id:
        db_session.close()
        flash('You do not have permission to export this document', 'danger')
        return redirect(url_for('dashboard'))
    
    # Create docx
    docx = create_docx(document_id)
    
    if not docx:
        db_session.close()
        flash('Error creating docx file', 'danger')
        return redirect(url_for('view_document', document_id=document_id))
    
    # Create export directory if it doesn't exist
    export_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exports")
    if not os.path.exists(export_dir):
        os.makedirs(export_dir)
    
    # Save docx
    docx_path = os.path.join(export_dir, f"{document.title.replace(' ', '_')}.docx")
    docx.save(docx_path)
    
    db_session.close()
    
    flash(f'Document exported to {docx_path}', 'success')
    return redirect(url_for('view_document', document_id=document_id))

@app.route('/documents/<int:document_id>/export/txt')
@login_required
def export_txt(document_id):
    """Export a document to txt with improved formatting"""
    db_session = get_session(engine)
    document = db_session.query(Document).get(document_id)
    
    if not document:
        db_session.close()
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the user is the creator
    if document.creator_id != current_user.id:
        db_session.close()
        flash('You do not have permission to export this document', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get rendered content
    content = document.get_rendered_content()
    
    # Process markdown for better TXT formatting
    lines = content.split('\n')
    processed_lines = []
    
    for line in lines:
        # Handle headers - keep them with some emphasis
        header_match = re.match(r'^(#+)\s+(.*?)$', line)
        if header_match:
            level = len(header_match.group(1))
            text = header_match.group(2)
            
            if level == 1:
                processed_lines.append('\n' + text.upper() + '\n' + '=' * len(text))
            elif level == 2:
                processed_lines.append('\n' + text + '\n' + '-' * len(text))
            else:
                processed_lines.append('\n' + text)
            continue
            
        # Process inline formatting
        processed_line = line
        processed_line = re.sub(r'\*\*(.*?)\*\*', r'\1', processed_line)  # Remove bold
        processed_line = re.sub(r'\*(.*?)\*', r'\1', processed_line)  # Remove italic
        processed_line = re.sub(r'!\[(.*?)\]\((.*?)\)', '', processed_line)  # Remove images
        processed_line = re.sub(r'\[(.*?)\]\((.*?)\)', r'\1', processed_line)  # Remove links
        
        # Handle list items - keep the bullets
        if processed_line.strip().startswith('- ') or processed_line.strip().startswith('* '):
            # Preserve list formatting with proper indentation
            processed_lines.append(processed_line)
        else:
            processed_lines.append(processed_line)
    
    # Join lines back together
    plain_content = '\n'.join(processed_lines)
    
    # Create export directory if it doesn't exist
    export_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exports")
    if not os.path.exists(export_dir):
        os.makedirs(export_dir)
    
    # Save txt
    txt_path = os.path.join(export_dir, f"{document.title.replace(' ', '_')}.txt")
    with open(txt_path, 'w') as f:
        f.write(plain_content)
    
    db_session.close()
    
    flash(f'Document exported to {txt_path}', 'success')
    return redirect(url_for('view_document', document_id=document_id))

@app.route('/api/input_value/<int:document_id>/<int:input_box_id>', methods=['POST'])
@login_required
def update_input_value(document_id, input_box_id):
    """API to update an input value"""
    db_session = get_session(engine)
    document = db_session.query(Document).get(document_id)
    
    if not document:
        db_session.close()
        return jsonify({'status': 'error', 'message': 'Document not found'}), 404
    
    # Check if the user is the creator
    if document.creator_id != current_user.id:
        db_session.close()
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403
    
    # Get input box
    input_box = db_session.query(InputBox).get(input_box_id)
    
    if not input_box or input_box.template_id != document.template_id:
        db_session.close()
        return jsonify({'status': 'error', 'message': 'Input box not found'}), 404
    
    # Get data from request
    data = request.get_json()
    value = data.get('value', '')
    
    # Sanitize input
    value = bleach.clean(value)
    
    # Get existing value or create new one
    input_value = db_session.query(DocumentInputValue).filter_by(
        document_id=document.id,
        input_box_id=input_box.id
    ).first()
    
    if input_value:
        input_value.value = value
    else:
        input_value = DocumentInputValue(
            document_id=document.id,
            input_box_id=input_box.id,
            value=value
        )
        db_session.add(input_value)
    
    db_session.commit()
    db_session.close()
    
    return jsonify({'status': 'success', 'message': 'Input value updated'})

if __name__ == '__main__':
    app.run(debug=True, port=6789)
