import os
import sys
import sqlite3

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def migrate_database():
    """
    Update the database schema to add the is_admin column to the users table
    and set admin user to is_admin=True
    """
    # Get the absolute path to the database file
    db_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(db_dir, 'template_management.db')
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        print("Please run init_db.py first to create the database.")
        return
    
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if is_admin column already exists in users table
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'is_admin' not in column_names:
            # Add is_admin column to users table with default value False
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0")
            print("Added is_admin column to users table")
            
            # Set admin user to is_admin=True
            cursor.execute("UPDATE users SET is_admin = 1 WHERE username = 'admin'")
            print("Set admin user's is_admin to True")
            
            # Commit changes
            conn.commit()
            print("Database migration successful!")
        else:
            print("is_admin column already exists in users table")
    except Exception as e:
        conn.rollback()
        print(f"Error during migration: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()