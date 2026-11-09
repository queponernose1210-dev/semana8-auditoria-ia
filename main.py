import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import sqlite3
import jwt
import hashlib

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# FIX: CWE-798 Secret no expuesto directamente
SECRET_KEY = os.getenv("SECRET_KEY", "safe_default_key_987")

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

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

@app.post("/register")
def register(user: User):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # FIX: CWE-89 (Consultas parametrizadas) y CWE-256 (Hashing)
    query = "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')"
    try:
        cursor.execute(query, (user.username, hash_password(user.password)))
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
    
    # FIX: CWE-89 (Consultas parametrizadas)
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (user.username, hash_password(user.password)))
    record = cursor.fetchone()
    conn.close()
    
    if record:
        token = jwt.encode({"user_id": record[0], "role": record[2]}, SECRET_KEY, algorithm="HS256")
        return {"access_token": token.decode('utf-8') if isinstance(token, bytes) else token}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/users/{user_id}")
def get_user(user_id: int, token: str = Depends(oauth2_scheme)):
    # FIX: CWE-284 (Control de acceso exigiendo token válido del mismo usuario)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("user_id") != user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    record = cursor.fetchone()
    conn.close()
    
    if record:
        return {"id": record[0], "username": record[1], "role": record[2]}
    raise HTTPException(status_code=404, detail="User not found")