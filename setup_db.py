import sqlite3
from werkzeug.security import generate_password_hash

def create_database():
    conn = sqlite3.connect('users.db')  
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'admin'))
        )
    ''')

    
    admin_username = 'admin'
    admin_password = generate_password_hash('admin123')

    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       (admin_username, admin_password, 'admin'))
        conn.commit()
        print("Admin account created successfully!")
    except sqlite3.IntegrityError:
        print("Admin account already exists.")

    conn.close()
    print("Database setup complete!")

if __name__ == '__main__':
    create_database()
