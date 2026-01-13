#!/usr/bin/env python3
"""Initialize database and run migrations."""
import os
from app import app, db
from flask_migrate import init, migrate, upgrade
from models import User

def setup_database():
    """Set up database with migrations."""
    with app.app_context():
        # Ensure data directory exists
        data_dir = os.path.join(os.getcwd(), 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Check if migrations directory exists
        migrations_dir = os.path.join(os.getcwd(), 'migrations')
        
        if not os.path.exists(migrations_dir):
            print("Initializing database migrations...")
            init()
            print("Creating initial migration...")
            migrate(message="Initial migration")
        
        # Apply migrations
        print("Applying database migrations...")
        try:
            upgrade()
            print("Database migrations applied successfully.")
        except Exception as e:
            print(f"Error applying migrations: {e}")
            print("Creating tables directly...")
            db.create_all()
        
        # Create default admin user if no users exist
        if User.query.count() == 0:
            admin = User(username='admin', email='admin@neonc2.local')
            admin.set_password('admin')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: username='admin', password='admin'")
        else:
            print(f"Database already has {User.query.count()} user(s).")

if __name__ == '__main__':
    setup_database()
