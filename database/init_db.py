import os
import sys
from passlib.hash import pbkdf2_sha256

# Add parent directory to path to allow importing from database.models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.models import init_db, get_session, User, Template, TemplateAssignment

def setup_database():
    """
    Initialize the database and create a test admin user
    """
    # Get the absolute path to the database file
    db_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(db_dir, 'template_management.db')
    
    # Check if database already exists
    if os.path.exists(db_path):
        print(f"Database already exists at {db_path}")
        return
    
    # Initialize the database
    engine = init_db(db_path)
    session = get_session(engine)
    
    # Create admin user
    admin_user = User(
        username="admin",
        email="admin@example.com",
        password_hash=pbkdf2_sha256.hash("admin123"),
        is_admin=True
    )
    
    # Create test user
    test_user = User(
        username="test",
        email="test@example.com",
        password_hash=pbkdf2_sha256.hash("test123"),
        is_admin=False
    )
    
    session.add(admin_user)
    session.add(test_user)
    session.commit()
    
    print(f"Database initialized at {db_path}")
    print("Created admin user:")
    print("  Username: admin")
    print("  Password: admin123")
    print("Created test user:")
    print("  Username: test")
    print("  Password: test123")
    
    session.close()

if __name__ == "__main__":
    setup_database()
