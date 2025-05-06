from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from flask_login import UserMixin
import datetime
import json
import os

Base = declarative_base()

# Notification model for system messages
class Notification(Base):
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    title = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_read = Column(Boolean, default=False)
    notification_type = Column(String(50), nullable=True)  # For categorizing notifications
    
    # Relationships
    user = relationship("User", back_populates="notifications")
    
    def __repr__(self):
        return f"<Notification(id={self.id}, user_id={self.user_id}, title='{self.title}')>"

# Template assignment model for sharing templates with other users
class TemplateAssignment(Base):
    __tablename__ = 'template_assignments'
    
    id = Column(Integer, primary_key=True)
    template_id = Column(Integer, ForeignKey('templates.id'), nullable=False)
    assignee_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    assigned_by_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    assigned_at = Column(DateTime, default=datetime.datetime.utcnow)
    can_edit = Column(Boolean, default=False)  # Whether the assignee can edit the template
    
    # Relationships
    template = relationship("Template", back_populates="assignments")
    assignee = relationship("User", foreign_keys=[assignee_id], back_populates="assigned_templates")
    assigned_by = relationship("User", foreign_keys=[assigned_by_id])
    
    def __repr__(self):
        return f"<TemplateAssignment(template_id={self.template_id}, assignee_id={self.assignee_id})>"

class User(Base, UserMixin):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    # Relationships
    templates = relationship("Template", foreign_keys="Template.creator_id", back_populates="creator")
    documents = relationship("Document", back_populates="creator")
    assigned_templates = relationship("TemplateAssignment", foreign_keys="TemplateAssignment.assignee_id", back_populates="assignee")
    notifications = relationship("Notification", back_populates="user", cascade="all, delete-orphan")
    
    def get_id(self):
        return str(self.id)
        
    def is_authenticated(self):
        return True
        
    def is_active(self):
        return self.is_active
        
    def is_anonymous(self):
        return False
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"


class Template(Base):
    __tablename__ = 'templates'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    content = Column(Text, nullable=False)  # Markdown content with input-box syntax
    creator_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    modified_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    parent_id = Column(Integer, ForeignKey('templates.id'), nullable=True)  # For forked templates
    is_fork = Column(Boolean, default=False)  # Flag to identify if this is a forked template
    
    # Relationships
    creator = relationship("User", foreign_keys=[creator_id], back_populates="templates")
    input_boxes = relationship("InputBox", back_populates="template", cascade="all, delete-orphan")
    documents = relationship("Document", back_populates="template")
    assignments = relationship("TemplateAssignment", back_populates="template", cascade="all, delete-orphan")
    
    # Self-referential relationship for forks
    parent = relationship("Template", remote_side=[id], backref="forks", foreign_keys=[parent_id])
    
    def __repr__(self):
        return f"<Template(title='{self.title}', creator_id={self.creator_id})>"


class InputBox(Base):
    __tablename__ = 'input_boxes'
    
    id = Column(Integer, primary_key=True)
    box_id = Column(String(50), nullable=False)  # Unique identifier within the template
    template_id = Column(Integer, ForeignKey('templates.id'), nullable=False)
    label = Column(String(100), nullable=True)
    default_value = Column(Text, nullable=True)
    position = Column(Integer, nullable=True)  # For ordering boxes in display
    
    # Relationships
    template = relationship("Template", back_populates="input_boxes")
    document_values = relationship("DocumentInputValue", back_populates="input_box")
    
    def __repr__(self):
        return f"<InputBox(box_id='{self.box_id}', template_id={self.template_id})>"


class Document(Base):
    __tablename__ = 'documents'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    template_id = Column(Integer, ForeignKey('templates.id'), nullable=False)
    creator_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    modified_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    template = relationship("Template", back_populates="documents")
    creator = relationship("User", back_populates="documents")
    input_values = relationship("DocumentInputValue", back_populates="document", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Document(title='{self.title}', template_id={self.template_id})>"
    
    def get_rendered_content(self):
        """
        Renders the template with the document's input values
        """
        template_content = self.template.content
        
        # Create a dictionary of box_id to value for easy replacement
        # Skip any input values where input_box is None
        input_values_dict = {}
        for value in self.input_values:
            if value.input_box is not None:
                input_values_dict[value.input_box.box_id] = value.value
        
        # Replace all input box placeholders with their values
        for box_id, value in input_values_dict.items():
            placeholder = f"*****{box_id}*****"
            template_content = template_content.replace(placeholder, value or "")
        
        return template_content


class DocumentInputValue(Base):
    __tablename__ = 'document_input_values'
    
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey('documents.id'), nullable=False)
    input_box_id = Column(Integer, ForeignKey('input_boxes.id'), nullable=False)
    value = Column(Text, nullable=True)
    
    # Relationships
    document = relationship("Document", back_populates="input_values")
    input_box = relationship("InputBox", back_populates="document_values")
    
    def __repr__(self):
        return f"<DocumentInputValue(document_id={self.document_id}, input_box_id={self.input_box_id})>"


def init_db(db_path):
    """
    Initialize the database with tables
    """
    engine = create_engine(f'sqlite:///{db_path}')
    Base.metadata.create_all(engine)
    return engine


def get_session(engine):
    """
    Create a session to interact with the database
    """
    Session = sessionmaker(bind=engine)
    return Session()
