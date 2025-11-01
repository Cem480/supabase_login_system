from app import create_app, db
from models.models import User, Session, MagicLink, OAuthConnection, AuditLog

def init_database():
    """Initialize the database with all tables"""
    app = create_app()
    
    with app.app_context():
        print("Creating database tables...")

        db.create_all()
        
        print("✅ Database tables created successfully!")
        print("\nTables created:")
        print("- users")
        print("- sessions")
        print("- magic_links")
        print("- oauth_connections")
        print("- audit_log")
        
        # Create a test user (optional)
        create_test_user = input("\nCreate a test user? (y/n): ")
        if create_test_user.lower() == 'y':
            email = input("Email: ")
            password = input("Password: ")
            name = input("Full Name (optional): ")
            
            user = User(email=email, full_name=name or None)
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            print(f"✅ Test user created: {email}")
        
        print("\n🎉 Database initialization complete!")

if __name__ == '__main__':
    init_database()
