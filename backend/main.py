#!/path/to/your/project/backend/.venv/bin/python
# Your code below...
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Welcome to GitHeal!"}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "GitHeal"}
