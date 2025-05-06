import os
import sys
import sqlite3
import datetime

# Add parent directory to path to allow importing from database models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def fix_database_schema():
    """
    Fix the database schema by adding the station_id column to the templates table
    and creating station-related tables if they don't exist
    """
    # Get the absolute path to the database file
    db_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(db_dir, 'template_management.db')
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"Database does not exist at {db_path}. Please run init_db.py first.")
        return
    
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if the stations table already exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='stations'")
        stations_exists = cursor.fetchone() is not None
        
        if not stations_exists:
            print("Creating stations table...")
            # Create the stations table
            cursor.execute('''
            CREATE TABLE stations (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
            ''')
            
            # Create the station_users association table
            print("Creating station_users table...")
            cursor.execute('''
            CREATE TABLE station_users (
                id INTEGER PRIMARY KEY,
                station_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (station_id) REFERENCES stations (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')
        
        # Check if templates table has station_id column
        cursor.execute("PRAGMA table_info(templates)")
        columns = cursor.fetchall()
        station_id_exists = any(column[1] == 'station_id' for column in columns)
        
        if not station_id_exists:
            print("Adding station_id column to templates table...")
            # Add station_id column to templates table
            cursor.execute('''
            ALTER TABLE templates ADD COLUMN station_id INTEGER
            ''')
            
            # Create default station for existing templates
            cursor.execute('''
            INSERT INTO stations (name, description, created_by)
            VALUES ('Default Station', 'Default station for existing templates', 
                   (SELECT id FROM users WHERE username = 'admin'))
            ''')
            
            # Get the new station's ID
            default_station_id = cursor.lastrowid
            print(f"Created Default Station with ID {default_station_id}")
            
            # Update all existing templates to belong to the default station
            cursor.execute('''
            UPDATE templates SET station_id = ?
            ''', (default_station_id,))
            print("Updated existing templates to use Default Station")
            
            # Add all existing users to the default station
            cursor.execute('''
            SELECT id, username FROM users
            ''')
            users = cursor.fetchall()
            
            # Make admin the station master
            cursor.execute('''
            INSERT INTO station_users (station_id, user_id, role)
            VALUES (?, (SELECT id FROM users WHERE username = 'admin'), 'station_master')
            ''', (default_station_id,))
            print("Added admin as station_master")
            
            # Make other users station staff
            for user_id, username in users:
                if username != 'admin':
                    cursor.execute('''
                    INSERT INTO station_users (station_id, user_id, role)
                    VALUES (?, ?, 'station_staff')
                    ''', (default_station_id, user_id))
                    print(f"Added user {username} as station_staff")
            
            conn.commit()
            print("Migration fix completed successfully!")
        else:
            print("Templates table already has station_id column.")
    
    except Exception as e:
        conn.rollback()
        print(f"Error during migration fix: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    fix_database_schema()
