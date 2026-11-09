from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import sqlite3
import jwt

app = FastAPI()

# CWE-798: Uso de credenciales codificadas en duro (Hardcoded Secret)
SECRET_KEY = "super_secret_dev_key_123"

# Inicialización insegura de la base de datos
def init_db():
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    conn.commit()
    conn.close()

init_db()

class User(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(user: User):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # CWE-89: Inyección SQL (Concatenación de strings en lugar de consultas parametrizadas)
    # CWE-256: Almacenamiento de contraseñas en texto plano (Falta de Hashing)
    query = f"INSERT INTO users (username, password, role) VALUES ('{user.username}', '{user.password}', 'user')"
    try:
        cursor.executescript(query)
        conn.commit()
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()
        
    return {"message": "User registered successfully"}

@app.post("/login")
def login(user: User):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # CWE-89: Inyección SQL en el proceso de autenticación
    query = f"SELECT id, username, role FROM users WHERE username = '{user.username}' AND password = '{user.password}'"
    cursor.execute(query)
    record = cursor.fetchone()
    conn.close()
    
    if record:
        # Generación de token básico
        token = jwt.encode({"user_id": record[0], "role": record[2]}, SECRET_KEY, algorithm="HS256")
        return {"access_token": token.decode('utf-8') if isinstance(token, bytes) else token}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/users/{user_id}")
def get_user(user_id: str):
    # CWE-284: Control de acceso inadecuado / IDOR (Cualquiera puede ver los datos de cualquier usuario sin token)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    query = f"SELECT id, username, role FROM users WHERE id = {user_id}"
    cursor.execute(query)
    record = cursor.fetchone()
    conn.close()
    
    if record:
        return {"id": record[0], "username": record[1], "role": record[2]}
    raise HTTPException(status_code=404, detail="User not found")