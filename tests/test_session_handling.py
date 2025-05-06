import os
import sys
import unittest

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import joinedload
from database.models import init_db, get_session, User, Template, Document

class TestSessionHandling(unittest.TestCase):
    """Test session handling and eager loading"""
    
    def setUp(self):
        """Set up test database"""
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                   "database", "test_session.db")
        self.engine = init_db(self.db_path)
        self.session = get_session(self.engine)
        
        # Create a test user
        self.user = User(
            username="test_user",
            email="test@example.com",
            password_hash="test_hash"
        )
        self.session.add(self.user)
        
        # Create a test template
        self.template = Template(
            title="Test Template",
            description="Test Description",
            content="Test Content",
            creator_id=1  # Will be the first user
        )
        self.session.add(self.template)
        
        # Create a test document
        self.document = Document(
            title="Test Document",
            description="Test Document Description",
            template_id=1,  # Will be the first template
            creator_id=1    # Will be the first user
        )
        self.session.add(self.document)
        
        self.session.commit()
    
    def tearDown(self):
        """Clean up test database"""
        self.session.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_eager_loading(self):
        """Test eager loading of template relationship"""
        # Test with eager loading - should work after session is closed
        documents = self.session.query(Document).options(joinedload(Document.template)).all()
        self.session.close()  # Close the session
        
        # This should not raise a DetachedInstanceError because of eager loading
        for doc in documents:
            print(f"Document: {doc.title}, Template: {doc.template.title}")
        
    def test_lazy_loading(self):
        """Test lazy loading of template relationship"""
        # Test with lazy loading - should fail after session is closed
        documents = self.session.query(Document).all()
        self.session.close()  # Close the session
        
        # This should raise a DetachedInstanceError because of lazy loading
        try:
            for doc in documents:
                print(f"Document: {doc.title}, Template: {doc.template.title}")
            self.fail("Expected DetachedInstanceError was not raised")
        except Exception as e:
            self.assertTrue("DetachedInstanceError" in str(e))

if __name__ == "__main__":
    unittest.main()
