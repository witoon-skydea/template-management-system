import os
import sys
import sqlite3
import datetime
import enum

# Add parent directory to path to allow importing from database.models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Define StationUserRole class locally to avoid import issues
class StationUserRole(enum.Enum):
    STATION_MASTER = 'station_master'
    STATION_STAFF = 'station_staff'

# Import models individually, with fallback for Station and StationUser
try:
    from database.models import init_db, get_session, Base, Station, StationUser, StationUserRole
except ImportError:
    from database.models import init_db, get_session, Base

def migrate_database():
    """
    Migrate the database to add Station and StationUser tables,
    and add station_id column to Templates table
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
            
            # Update all existing templates to belong to the default station
            cursor.execute('''
            UPDATE templates SET station_id = ?
            ''', (default_station_id,))
            
            # Add all existing users to the default station
            cursor.execute('''
            SELECT id FROM users
            ''')
            user_ids = cursor.fetchall()
            
            # Make admin the station master
            cursor.execute('''
            INSERT INTO station_users (station_id, user_id, role)
            VALUES (?, (SELECT id FROM users WHERE username = 'admin'), ?)
            ''', (default_station_id, StationUserRole.STATION_MASTER.value))
            
            # Make other users station staff
            for user_id in user_ids:
                cursor.execute('''
                SELECT username FROM users WHERE id = ?
                ''', (user_id[0],))
                username = cursor.fetchone()[0]
                
                if username != 'admin':
                    cursor.execute('''
                    INSERT INTO station_users (station_id, user_id, role)
                    VALUES (?, ?, ?)
                    ''', (default_station_id, user_id[0], StationUserRole.STATION_STAFF.value))
            
            conn.commit()
            print("Migration completed successfully!")
            print(f"Created 'Default Station' with ID {default_station_id}")
            print("All existing templates have been assigned to the Default Station")
            print("Admin user has been assigned as station_master")
            print("All other users have been assigned as station_staff")
        else:
            print("Migration has already been performed.")
    
    except Exception as e:
        conn.rollback()
        print(f"Error during migration: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()
