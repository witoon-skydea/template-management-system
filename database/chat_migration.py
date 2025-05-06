import os
import sys
import sqlite3
import datetime

# Add parent directory to path to import from database.models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.models import init_db, get_session, ChatChannel, ChatChannelType, Station

def migrate_database():
    """
    Add chat tables to the database and create the general chat channel
    """
    print("Starting chat system migration...")
    
    # Database path
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template_management.db")
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return
    
    # Initialize the database engine
    engine = init_db(db_path)
    db_session = get_session(engine)
    
    try:
        # Create the general chat channel
        general_channel = db_session.query(ChatChannel).filter_by(
            channel_type=ChatChannelType.GENERAL.value,
            name="General Chat"
        ).first()
        
        if not general_channel:
            general_channel = ChatChannel(
                name="General Chat",
                channel_type=ChatChannelType.GENERAL.value
            )
            db_session.add(general_channel)
            print("Created General Chat channel")
        
        # Create station chat channels for existing stations
        stations = db_session.query(Station).all()
        for station in stations:
            # Check if station already has a channel
            station_channel = db_session.query(ChatChannel).filter_by(
                channel_type=ChatChannelType.STATION.value,
                station_id=station.id
            ).first()
            
            if not station_channel:
                station_channel = ChatChannel(
                    name=f"{station.name} Chat",
                    channel_type=ChatChannelType.STATION.value,
                    station_id=station.id
                )
                db_session.add(station_channel)
                print(f"Created chat channel for station: {station.name}")
        
        db_session.commit()
        print("Chat system migration completed successfully")
        
    except Exception as e:
        db_session.rollback()
        print(f"Error during migration: {str(e)}")
    finally:
        db_session.close()

if __name__ == "__main__":
    migrate_database()
