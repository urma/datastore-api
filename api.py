import jwt
import os
import secrets
import shelve

from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from pydantic import BaseModel
from typing import Optional

###
# Model definitions
###
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[str] = None

class UserInDB(User):
    hashed_password: str

###
# Helper methods
###
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/token')
jwt_key = secrets.token_bytes(64)

async def authenticate(username: str, password: str):
    with shelve.open('userdb', 'c') as user_db:
        if username in user_db and user_db[username].hashed_password == password:
            user = User(**user_db[username].dict())
            payload = {
                'iss': 'datastore-api.local',
                'exp': datetime.utcnow() + timedelta(minutes=30),
                'sub': user.dict()
            }
            return jwt.encode(payload, jwt_key, algorithm='HS256')
    return None

async def get_current_active_user(token: str = Security(oauth2_scheme)):
    try:
        payload = jwt.decode(token, jwt_key, [ 'HS256' ])
        with shelve.open('userdb', 'c') as user_db:
            return User(**user_db[payload['sub']['username']].dict())
    except jwt.PyJWTError:
        raise HTTPException(status_code=403, detail='Invalid credentials')

###
# Main API definitions and entrypoints
###
app = FastAPI()

@app.post('/token')
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    access_token = await authenticate(form_data.username, form_data.password)
    if access_token:
        return { 'access_token': access_token, 'token_type': 'bearer' }
    else:
        raise HTTPException(status_code=400, detail='Invalid username and/or password')

@app.get('/users/me')
async def get_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user