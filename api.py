from typing import Optional
from pydantic import BaseModel

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

fake_users_db = {
    'urma': {
        'username': 'urma',
        'full_name': 'Ulisses Albuquerque',
        'email': 'ulisses.montenegro@gmail.com',
        'hashed_password': 'fakehashedurma',
        'disabled': False
    },
    'rvbc': {
        'username': 'rvbc',
        'full_name': 'Roberta Capobiango',
        'email': 'roberta.capobiango@gmail.com',
        'hashed_password': 'fakehashedrvbc',
        'disabled': True
    }
}

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/token')

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[str] = None

class UserInDB(User):
    hashed_password: str

def fake_hash_password(password: str):
    return 'fakehashed' + password

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def fake_decode_token(token):
    user = get_user(fake_users_db, token)
    print(user)
    return user

async def get_current_user(token: str = Security(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(status_code=400, detail='Invalid authentication credentials')
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail='Inactive user')
    return current_user

@app.post('/token')
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail='Invalid username and/or password')

    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail='Invalid username and/or password')

    return { 'access_token': user.username, 'token_type': 'bearer' }

@app.get('/users/me')
async def get_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user