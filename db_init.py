import sqlite3
import bcrypt
import os

# Path setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database', 'hms.db')
SCHEMA_PATH = os.path.join(BASE_DIR, 'database', 'schema.sql')

def initialize_database():
    # Read and execute schema
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        with open(SCHEMA_PATH, 'r') as f:
            conn.executescript(f.read())
        print("✓ Tables created successfully")

        # Create default admin account
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            password = 'admin123'
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ('admin', hashed.decode('utf-8'), 'Admin')
            )
            conn.commit()
            print("✓ Default admin account created")
            print("  Username: admin")
            print("  Password: admin123")
        else:
            print("✓ Admin account already exists")

if __name__ == '__main__':
    initialize_database()
    print("\n✓ Database initialized successfully")
    print(f"  Location: {DB_PATH}")