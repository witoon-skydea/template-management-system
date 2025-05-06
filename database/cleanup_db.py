import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import init_db, get_session, DocumentInputValue

def cleanup_database():
    """
    Clean up orphaned records in the database
    """
    # Get the absolute path to the database file
    db_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(db_dir, 'template_management.db')
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return
    
    # Initialize the database connection
    engine = init_db(db_path)
    session = get_session(engine)
    
    try:
        # Find and delete DocumentInputValue records with null input_box references
        orphaned_values = session.query(DocumentInputValue).filter(
            DocumentInputValue.input_box_id.is_(None)
        ).all()
        
        if orphaned_values:
            print(f"Found {len(orphaned_values)} orphaned DocumentInputValue records")
            for value in orphaned_values:
                session.delete(value)
            
            # Commit the changes
            session.commit()
            print(f"Deleted {len(orphaned_values)} orphaned records")
        else:
            print("No orphaned records found")
    
    except Exception as e:
        session.rollback()
        print(f"Error during cleanup: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    cleanup_database()