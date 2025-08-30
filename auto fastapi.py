from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import bcrypt # type: ignore
# Fake in-memory database
app = FastAPI()
users_db = {}
roles_permissions = {
    "admin": ["add_user", "delete_user"],
    "user": ["view_profile"]
}
#Data models
class user(BaseModel):
    username: str
    password: str
    role: str = "user"
class Login(BaseModel):
    username: str
    password: str
#Register endpoint
@app.post("/register")
def register(user:user):
    if user.username in users_db:
        raise HTTPException(400,"username exist")
    if user.role not in roles_permissions:
        user.role = "user"
    hashed = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    users_db[user.username]= {"password": hashed, "role": user.role}
    return {"message": "User registered", "role": user.role}
# Login endpoint
@app.post("/login")
def login(data: Login):
    user = users_db.get(data.username)
    if not user or not bcrypt.checkpw(data.password.encode(), user["password"]):
        raise HTTPException(401, "invalid username or passeword")
    return {"message": "Login successful", "role": user["role"]}
# Permission check
@app.get("/permission/{username}/{perm}")
def check_permission(username:str, permission: str):
    user= users_db.get(username)
    if not user:
        raise HTTPException(404, "user not found")
    allowed = permission in roles_permissions.get(user["role"],[])
    return {"username": username, "permission": permission, "allowed": allowed} 