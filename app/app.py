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
import copy
import datetime
from sqlalchemy import and_, or_

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sqlalchemy.orm import joinedload
from database.models import init_db, get_session, User, Template, InputBox, Document, DocumentInputValue, TemplateAssignment, Notification

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

def markdown_to_html(md_content, input_boxes=None, input_values=None, document_id=None):
    """
    Convert markdown to HTML with enhanced extensions for better rendering
    
    If input_boxes and input_values are provided, the function will add
    special markup for input boxes to make them interactive in the UI
    """
    try:
        # Process input boxes if provided
        processed_content = md_content
        box_mappings = {}
        
        if input_boxes and document_id:
            # Create a map of input box placeholders to their IDs for later replacement
            for box in input_boxes:
                placeholder = f'*****{box.box_id}*****'
                value = ""
                
                # Find the value for this box if input_values provided
                if input_values:
                    for val in input_values:
                        if val.input_box_id == box.id:
                            value = val.value
                            break
                
                # Create a unique placeholder that won't be affected by markdown processing
                unique_placeholder = f'INPUTBOX_{box.id}_{box.box_id}'
                box_mappings[unique_placeholder] = {
                    'id': box.id,
                    'label': box.label,
                    'value': value
                }
                
                # Replace the original placeholder with our unique one
                processed_content = processed_content.replace(placeholder, unique_placeholder)
        
        # Use more extensions for better markdown rendering
        extensions = [
            'markdown.extensions.extra',
            'markdown.extensions.codehilite',
            'markdown.extensions.nl2br',  # Convert line breaks to <br>
            'markdown.extensions.sane_lists',
            'markdown.extensions.smarty',
            'markdown.extensions.tables',
        ]
        
        html = markdown.markdown(processed_content, extensions=extensions)
        
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
            'span': ['class', 'id', 'style', 'data-input-id', 'data-box-id', 'data-box-label', 'data-value', 
                     'contenteditable', 'title', 'onclick'],
            '*': ['class', 'id', 'style'],
        }
        
        clean_html = bleach.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        
        # Replace our unique placeholders with interactive spans
        if box_mappings:
            for placeholder, box in box_mappings.items():
                # Create a more visually distinct and clickable input box span
                input_span = f'<span class="interactive-input-box" ' + \
                           f'data-box-id="{box["id"]}" ' + \
                           f'data-box-label="{box["label"]}" ' + \
                           f'data-value="{box["value"]}" ' + \
                           f'title="Click to edit: {box["label"]}">' + \
                           f'{box["value"] or "[Click to enter value]"}</span>'
                clean_html = clean_html.replace(placeholder, input_span)
        
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
    my_templates = db_session.query(Template).filter_by(creator_id=current_user.id).all()
    
    # Get templates assigned to the user with eager loading of creator and assignments relationships
    assigned_templates_query = db_session.query(Template).options(
        joinedload(Template.creator),
        joinedload(Template.assignments)
    ).join(
        TemplateAssignment, Template.id == TemplateAssignment.template_id
    ).filter(
        TemplateAssignment.assignee_id == current_user.id
    )
    assigned_templates = assigned_templates_query.all()
    
    # Get user's documents, eagerly loading the template relationship to prevent DetachedInstanceError
    documents = db_session.query(Document).options(joinedload(Document.template)).filter_by(creator_id=current_user.id).all()
    
    # Get all users for template assignment
    users = db_session.query(User).filter(User.id != current_user.id).all()
    
    db_session.close()
    
    return render_template('dashboard.html', 
                          my_templates=my_templates, 
                          assigned_templates=assigned_templates,
                          documents=documents,
                          users=users)

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
    
    # Check if the user is the creator or has edit permission
    has_permission = False
    
    # Creator always has permission
    if template.creator_id == current_user.id:
        has_permission = True
    else:
        # Check if user has been assigned this template with edit permission
        assignment = db_session.query(TemplateAssignment).filter_by(
            template_id=template.id,
            assignee_id=current_user.id,
            can_edit=True
        ).first()
        
        if assignment:
            has_permission = True
    
    if not has_permission:
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
        # Get input boxes for the template
        input_boxes = db_session.query(InputBox).filter_by(template_id=document.template_id).order_by(InputBox.position).all()
        
        # Get input values
        input_values = db_session.query(DocumentInputValue).filter_by(document_id=document.id).all()
        
        # Get the template content and rendered content
        template_content = document.template.content
        rendered_content = document.get_rendered_content()
        
        # Convert markdown to HTML with interactive input boxes
        # We use rendered_content for viewing since it already has the values filled in
        html_content = markdown_to_html(rendered_content, input_boxes, input_values, document_id)
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
    
    # For document editing, we need to ensure we're working with the template content
    # and replacing the input box placeholders with their current values
    template = db_session.query(Template).options(joinedload(Template.input_boxes)).get(document.template_id)
    template_content = template.content
    
    # Pass input boxes, values and document_id for interactive editing
    input_values = db_session.query(DocumentInputValue).filter_by(document_id=document.id).all()
    html_content = markdown_to_html(template_content, input_boxes, input_values, document.id)
    
    # Debug information for the console
    print(f"Rendering template for document {document.id} with {len(input_boxes)} input boxes")
    for box in input_boxes:
        value = input_value_dict.get(box.id, "")
        print(f"Input box {box.id} ({box.box_id}): {value}")
    
    return render_template('edit_document.html', 
                          document=document, 
                          input_boxes=input_boxes, 
                          input_value_dict=input_value_dict,
                          html_content=html_content)

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

@app.route('/templates/<int:template_id>/assign', methods=['POST'])
@login_required
def assign_template(template_id):
    """Assign a template to another user"""
    db_session = get_session(engine)
    template = db_session.query(Template).get(template_id)
    
    if not template:
        db_session.close()
        flash('Template not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the user is the creator
    if template.creator_id != current_user.id:
        db_session.close()
        flash('You do not have permission to assign this template', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get form data
    assignee_id = request.form.get('assignee_id')
    can_edit = 'can_edit' in request.form
    
    if not assignee_id:
        db_session.close()
        flash('Please select a user to assign the template to', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the assignee exists
    assignee = db_session.query(User).get(assignee_id)
    if not assignee:
        db_session.close()
        flash('Selected user not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if assignment already exists
    existing_assignment = db_session.query(TemplateAssignment).filter_by(
        template_id=template.id,
        assignee_id=assignee.id
    ).first()
    
    if existing_assignment:
        # Update existing assignment
        existing_assignment.can_edit = can_edit
        existing_assignment.assigned_by_id = current_user.id
        existing_assignment.assigned_at = datetime.datetime.utcnow()
        
        # Save the username before closing the session
        username = assignee.username
        
        db_session.commit()
        db_session.close()
        
        flash(f'Template reassigned to {username}', 'success')
        return redirect(url_for('dashboard'))
    
    # Create new assignment
    assignment = TemplateAssignment(
        template_id=template.id,
        assignee_id=assignee.id,
        assigned_by_id=current_user.id,
        can_edit=can_edit
    )
    
    # Save the username before closing the session
    username = assignee.username
    
    db_session.add(assignment)
    db_session.commit()
    db_session.close()
    
    flash(f'Template assigned to {username}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/templates/<int:template_id>/fork')
@login_required
def fork_template(template_id):
    """Fork a template to create your own copy"""
    db_session = get_session(engine)
    
    # Load the template with input boxes
    template = db_session.query(Template).options(joinedload(Template.input_boxes)).get(template_id)
    
    if not template:
        db_session.close()
        flash('Template not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if user has access to the template (creator or assignee)
    has_access = False
    
    if template.creator_id == current_user.id:
        has_access = True
    else:
        # Check if user has been assigned this template
        assignment = db_session.query(TemplateAssignment).filter_by(
            template_id=template.id,
            assignee_id=current_user.id
        ).first()
        
        if assignment:
            has_access = True
    
    if not has_access:
        db_session.close()
        flash('You do not have permission to fork this template', 'danger')
        return redirect(url_for('dashboard'))
    
    # Create a new template as a fork
    forked_template = Template(
        title=f"{template.title} (Fork)",
        description=template.description,
        content=template.content,
        creator_id=current_user.id,
        parent_id=template.id,
        is_fork=True
    )
    
    db_session.add(forked_template)
    db_session.flush()  # Flush to get the ID
    
    # Copy input boxes
    for box in template.input_boxes:
        new_box = InputBox(
            box_id=box.box_id,
            template_id=forked_template.id,
            label=box.label,
            default_value=box.default_value,
            position=box.position
        )
        db_session.add(new_box)
    
    db_session.commit()
    
    # Store the template_id before closing the session to prevent DetachedInstanceError
    forked_template_id = forked_template.id
    
    db_session.close()
    
    flash('Template forked successfully', 'success')
    return redirect(url_for('view_template', template_id=forked_template_id))

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

@app.route('/templates/<int:template_id>/delete')
@login_required
def delete_template(template_id):
    """Delete a template and all associated documents"""
    db_session = get_session(engine)
    
    # Get the template with eager loading of input_boxes
    template = db_session.query(Template).options(joinedload(Template.input_boxes)).get(template_id)
    
    if not template:
        db_session.close()
        flash('Template not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the user is the creator
    if template.creator_id != current_user.id:
        db_session.close()
        flash('You do not have permission to delete this template', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Get all documents based on this template
        documents = db_session.query(Document).filter_by(template_id=template.id).all()
        
        # Find all users who have documents based on this template
        affected_users = set()
        for doc in documents:
            if doc.creator_id != current_user.id:  # Don't notify yourself
                affected_users.add(doc.creator_id)
        
        # Get template name before deletion
        template_name = template.title
        
        # Create notifications for affected users
        for user_id in affected_users:
            notification = Notification(
                user_id=user_id,
                title="Template Deleted",
                message=f"A template you were using '{template_name}' has been deleted by {current_user.username}. Any documents you created using this template have also been deleted.",
                notification_type="template_deletion"
            )
            db_session.add(notification)
        
        # Delete all documents based on this template
        for document in documents:
            # Delete document input values first
            db_session.query(DocumentInputValue).filter_by(document_id=document.id).delete()
        
        # Now delete the documents
        db_session.query(Document).filter_by(template_id=template.id).delete()
        
        # Delete template assignments
        db_session.query(TemplateAssignment).filter_by(template_id=template.id).delete()
        
        # Delete the template
        db_session.delete(template)
        
        db_session.commit()
        
        flash(f'Template "{template_name}" and all associated documents have been deleted', 'success')
        
    except Exception as e:
        db_session.rollback()
        flash(f'Error deleting template: {str(e)}', 'danger')
    finally:
        db_session.close()
    
    return redirect(url_for('dashboard'))

@app.route('/notifications')
@login_required
def view_notifications():
    """View all notifications for the current user"""
    db_session = get_session(engine)
    
    # Get all notifications for the current user
    notifications = db_session.query(Notification).filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).all()
    
    db_session.close()
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/notifications/<int:notification_id>/mark-as-read')
@login_required
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    db_session = get_session(engine)
    
    # Get the notification
    notification = db_session.query(Notification).filter_by(
        id=notification_id,
        user_id=current_user.id
    ).first()
    
    if notification:
        notification.is_read = True
        db_session.commit()
    
    db_session.close()
    
    return redirect(url_for('view_notifications'))

@app.route('/notifications/mark-all-read')
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    db_session = get_session(engine)
    
    # Update all notifications for the current user
    db_session.query(Notification).filter_by(
        user_id=current_user.id,
        is_read=False
    ).update({Notification.is_read: True})
    
    db_session.commit()
    db_session.close()
    
    return redirect(url_for('view_notifications'))

@app.context_processor
def inject_unread_notifications_count():
    """Inject unread notifications count into all templates"""
    if current_user.is_authenticated:
        db_session = get_session(engine)
        count = db_session.query(Notification).filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
        db_session.close()
        return {'unread_notifications_count': count}
    return {'unread_notifications_count': 0}

if __name__ == '__main__':
    app.run(debug=True, port=6789)
