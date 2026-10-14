import os
import hmac
import hashlib
import secrets
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, String, Text, DateTime, ForeignKey,
    Boolean, Integer, select
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, sessionmaker
)

# =====================================================
# NEXORA CLOUD — CONFIGURATION
# =====================================================

APP_NAME = "Nexora Cloud"

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nexora.db")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()

if not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET environment variable must be configured."
    )

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://", "postgresql+psycopg://", 1
    )
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )

engine_options = {}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
else:
    engine_options["pool_pre_ping"] = True

engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(
    bind=engine, expire_on_commit=False
)


def now():
    return datetime.now(timezone.utc)


# =====================================================
# DATABASE MODELS
# =====================================================

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(
        Boolean, default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now
    )


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(
        String(500), default=""
    )
    is_public: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now
    )


class RepositoryFile(Base):
    __tablename__ = "repository_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id"), index=True
    )
    path: Mapped[str] = mapped_column(String(500))
    content: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), index=True
    )
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    runtime: Mapped[str] = mapped_column(
        String(30), default="static"
    )
    build_command: Mapped[str] = mapped_column(
        String(500), default=""
    )
    start_command: Mapped[str] = mapped_column(
        String(500), default=""
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now
    )


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), default="QUEUED"
    )
    logs: Mapped[str] = mapped_column(Text, default="")
    public_url: Mapped[str] = mapped_column(
        String(500), default=""
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now
    )


# =====================================================
# PASSWORD SECURITY
# =====================================================

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1
    )
    return (
        salt.hex() + ":" + derived.hex()
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# =====================================================
# REQUEST SCHEMAS
# =====================================================

class RegisterInput(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=10, max_length=128)


class LoginInput(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class RepositoryInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    is_public: bool = False


class FileInput(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=200000)


class ProjectInput(BaseModel):
    repository_id: int
    name: str = Field(min_length=1, max_length=100)
    runtime: str = "static"
    build_command: str = ""
    start_command: str = ""


# =====================================================
# APPLICATION
# =====================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=APP_NAME,
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="nexora_session",
    same_site="lax",
    https_only=os.getenv("COOKIE_SECURE", "true").lower()
    == "true",
    max_age=60 * 60 * 24 * 7
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "ALLOWED_ORIGINS", ""
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"]
)


# =====================================================
# HELPERS
# =====================================================

def current_user(request: Request, db):
    user_id = request.session.get("user_id")

    if not user_id:
        raise HTTPException(401, "Login required")

    user = db.get(User, user_id)

    if not user:
        request.session.clear()
        raise HTTPException(401, "Session expired")

    return user


def get_repository(db, repo_id, user):
    repo = db.get(Repository, repo_id)

    if not repo:
        raise HTTPException(404, "Repository not found")

    if repo.owner_id != user.id and not repo.is_public:
        raise HTTPException(404, "Repository not found")

    return repo


def valid_path(path):
    if (
        path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise HTTPException(400, "Invalid file path")

    return path


def repo_json(repo):
    return {
        "id": repo.id,
        "name": repo.name,
        "description": repo.description,
        "is_public": repo.is_public,
        "created_at": repo.created_at.isoformat()
    }


def deployment_json(item):
    return {
        "id": item.id,
        "project_id": item.project_id,
        "status": item.status,
        "logs": item.logs,
        "public_url": item.public_url or None,
        "created_at": item.created_at.isoformat()
    }


# =====================================================
# HEALTH
# =====================================================

@app.get("/health")
def health():
    return {"status": "ok", "service": APP_NAME}


@app.get("/ready")
def ready():
    with engine.connect() as connection:
        connection.exec_driver_sql("SELECT 1")
    return {"status": "ready"}


# =====================================================
# AUTHENTICATION
# =====================================================

@app.post("/api/register")
def register(data: RegisterInput, request: Request):
    email = data.email.strip().lower()

    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(400, "Enter a valid email address")

    with SessionLocal() as db:
        existing = db.scalar(
            select(User).where(User.email == email)
        )

        if existing:
            raise HTTPException(409, "Email already registered")

        user = User(
            email=email,
            password_hash=hash_password(data.password),
            is_admin=bool(ADMIN_EMAIL and email == ADMIN_EMAIL)
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        request.session.clear()
        request.session["user_id"] = user.id

        return {
            "message": "Account created",
            "user": {
                "id": user.id,
                "email": user.email,
                "is_admin": user.is_admin
            }
        }


@app.post("/api/login")
def login(data: LoginInput, request: Request):
    email = data.email.strip().lower()

    with SessionLocal() as db:
        user = db.scalar(
            select(User).where(User.email == email)
        )

        if not user or not verify_password(
            data.password, user.password_hash
        ):
            raise HTTPException(401, "Invalid email or password")

        request.session.clear()
        request.session["user_id"] = user.id

        return {
            "message": "Logged in",
            "user": {
                "id": user.id,
                "email": user.email,
                "is_admin": user.is_admin
            }
        }


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"message": "Logged out"}


@app.get("/api/me")
def me(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)

        return {
            "id": user.id,
            "email": user.email,
            "is_admin": user.is_admin
        }


# =====================================================
# REPOSITORIES
# =====================================================

@app.get("/api/repositories")
def list_repositories(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)

        repos = db.scalars(
            select(Repository)
            .where(Repository.owner_id == user.id)
            .order_by(Repository.id.desc())
        ).all()

        return [repo_json(repo) for repo in repos]


@app.post("/api/repositories")
def create_repository(
    data: RepositoryInput,
    request: Request
):
    name = data.name.strip()

    if not name or any(c in name for c in "/\\"):
        raise HTTPException(400, "Invalid repository name")

    with SessionLocal() as db:
        user = current_user(request, db)

        duplicate = db.scalar(
            select(Repository).where(
                Repository.owner_id == user.id,
                Repository.name == name
            )
        )

        if duplicate:
            raise HTTPException(409, "Repository already exists")

        repo = Repository(
            owner_id=user.id,
            name=name,
            description=data.description,
            is_public=data.is_public
        )

        db.add(repo)
        db.commit()
        db.refresh(repo)

        return repo_json(repo)


@app.get("/api/repositories/{repo_id}")
def repository_detail(repo_id: int, request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)
        repo = get_repository(db, repo_id, user)

        files = db.scalars(
            select(RepositoryFile)
            .where(RepositoryFile.repository_id == repo.id)
            .order_by(RepositoryFile.path)
        ).all()

        return {
            **repo_json(repo),
            "files": [
                {"path": f.path, "updated_at": f.updated_at.isoformat()}
                for f in files
            ]
        }


@app.put("/api/repositories/{repo_id}/files")
def save_file(
    repo_id: int,
    data: FileInput,
    request: Request
):
    path = valid_path(data.path)

    with SessionLocal() as db:
        user = current_user(request, db)
        repo = db.get(Repository, repo_id)

        if not repo or repo.owner_id != user.id:
            raise HTTPException(404, "Repository not found")

        file = db.scalar(
            select(RepositoryFile).where(
                RepositoryFile.repository_id == repo.id,
                RepositoryFile.path == path
            )
        )

        if file:
            file.content = data.content
            file.updated_at = now()
        else:
            file = RepositoryFile(
                repository_id=repo.id,
                path=path,
                content=data.content
            )
            db.add(file)

        db.commit()

        return {"message": "File saved", "path": path}


@app.get("/api/repositories/{repo_id}/files/{file_path:path}")
def read_file(
    repo_id: int,
    file_path: str,
    request: Request
):
    path = valid_path(file_path)

    with SessionLocal() as db:
        user = current_user(request, db)
        repo = get_repository(db, repo_id, user)

        file = db.scalar(
            select(RepositoryFile).where(
                RepositoryFile.repository_id == repo.id,
                RepositoryFile.path == path
            )
        )

        if not file:
            raise HTTPException(404, "File not found")

        return {"path": file.path, "content": file.content}


# =====================================================
# PROJECTS
# =====================================================

@app.post("/api/projects")
def create_project(data: ProjectInput, request: Request):
    supported = {"static", "node", "python", "fastapi", "flask"}

    if data.runtime not in supported:
        raise HTTPException(400, "Unsupported runtime")

    with SessionLocal() as db:
        user = current_user(request, db)
        repo = db.get(Repository, data.repository_id)

        if not repo or repo.owner_id != user.id:
            raise HTTPException(404, "Repository not found")

        project = Project(
            owner_id=user.id,
            repository_id=repo.id,
            name=data.name.strip(),
            runtime=data.runtime,
            build_command=data.build_command,
            start_command=data.start_command
        )

        db.add(project)
        db.commit()
        db.refresh(project)

        return {
            "id": project.id,
            "name": project.name,
            "repository_id": project.repository_id,
            "runtime": project.runtime
        }


@app.get("/api/projects")
def list_projects(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)

        projects = db.scalars(
            select(Project)
            .where(Project.owner_id == user.id)
            .order_by(Project.id.desc())
        ).all()

        return [
            {
                "id": p.id,
                "name": p.name,
                "repository_id": p.repository_id,
                "runtime": p.runtime
            }
            for p in projects
        ]


# =====================================================
# DEPLOYMENT REQUESTS
# =====================================================

@app.post("/api/projects/{project_id}/deploy")
def request_deployment(
    project_id: int,
    request: Request
):
    with SessionLocal() as db:
        user = current_user(request, db)
        project = db.get(Project, project_id)

        if not project or project.owner_id != user.id:
            raise HTTPException(404, "Project not found")

        deployment = Deployment(
            project_id=project.id,
            owner_id=user.id,
            status="QUEUED",
            logs=(
                "Deployment request recorded. "
                "No worker has claimed this job yet."
            )
        )

        db.add(deployment)
        db.commit()
        db.refresh(deployment)

        return deployment_json(deployment)


@app.get("/api/deployments")
def list_deployments(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)

        items = db.scalars(
            select(Deployment)
            .where(Deployment.owner_id == user.id)
            .order_by(Deployment.id.desc())
        ).all()

        return [deployment_json(item) for item in items]


@app.get("/api/deployments/{deployment_id}")
def get_deployment(
    deployment_id: int,
    request: Request
):
    with SessionLocal() as db:
        user = current_user(request, db)
        deployment = db.get(Deployment, deployment_id)

        if (
            not deployment
            or deployment.owner_id != user.id
        ):
            raise HTTPException(404, "Deployment not found")

        return deployment_json(deployment)


# =====================================================
# ADMIN
# =====================================================

@app.get("/api/admin/overview")
def admin_overview(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)

        if not user.is_admin:
            raise HTTPException(403, "Admin access required")

        return {
            "users": db.query(User).count(),
            "repositories": db.query(Repository).count(),
            "projects": db.query(Project).count(),
            "deployments": db.query(Deployment).count()
        }


# =====================================================
# WEB INTERFACE
# =====================================================

HTML = r"""
<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nexora Cloud</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1020;color:#e8edff;
font-family:Inter,Segoe UI,Arial,sans-serif}
header{padding:22px 6%;border-bottom:1px solid #242b40;
display:flex;justify-content:space-between;align-items:center}
.logo{font-size:24px;font-weight:800;color:#8c9dff}
main{max-width:1050px;margin:35px auto;padding:20px}
h1{font-size:36px;margin-bottom:8px}
p{color:#9ca9c9}
.card{background:#121a2d;border:1px solid #28324b;
border-radius:16px;padding:22px;margin:18px 0}
input,textarea,select{width:100%;padding:12px;margin:7px 0;
border-radius:8px;border:1px solid #35415d;background:#0b1020;
color:white}
button{padding:11px 16px;border:0;border-radius:8px;
background:#7469f7;color:white;font-weight:700;cursor:pointer;
margin:5px 5px 5px 0}
button:hover{background:#958cff}
pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#b9c6e8}
small{color:#8e9bb9}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.hidden{display:none}
</style>
</head>
<body>
<header>
 <div class="logo">◈ NEXORA CLOUD</div>
 <button onclick="logout()">Chiqish</button>
</header>
<main>
 <h1>Code. Deploy. Scale.</h1>
 <p>Bir joyda loyihalaringizni boshqaring.</p>

 <section id="auth" class="card">
  <h2>Hisobingiz</h2>
  <input id="email" type="email" placeholder="Email">
  <input id="password" type="password" placeholder="Kamida 10 belgili parol">
  <button onclick="auth('register')">Ro‘yxatdan o‘tish</button>
  <button onclick="auth('login')">Kirish</button>
  <pre id="authmsg"></pre>
 </section>

 <section id="dashboard" class="hidden">
  <div class="card">
   <h2>Dashboard</h2>
   <div id="profile"></div>
   <div class="grid">
    <div class="card"><h3>Repositories</h3><div id="repos">0</div></div>
    <div class="card"><h3>Projects</h3><div id="projects">0</div></div>
    <div class="card"><h3>Deployments</h3><div id="deployments">0</div></div>
   </div>
  </div>

  <div class="card">
   <h2>+ Repository yaratish</h2>
   <input id="reponame" placeholder="Repository nomi">
   <input id="repodesc" placeholder="Tavsif">
   <button onclick="createRepo()">Repository yaratish</button>
   <div id="repolist"></div>
  </div>

  <div class="card">
   <h2>Kod faylini saqlash</h2>
   <input id="fileRepo" type="number" placeholder="Repository ID">
   <input id="filepath" placeholder="index.html">
   <textarea id="filecontent" rows="7"
   placeholder="HTML yoki boshqa kodni yozing"></textarea>
   <button onclick="saveFile()">Faylni saqlash</button>
   <pre id="filemsg"></pre>
  </div>

  <div class="card">
   <h2>Loyiha yaratish</h2>
   <input id="projectrepo" type="number" placeholder="Repository ID">
   <input id="projectname" placeholder="Loyiha nomi">
   <select id="runtime">
    <option value="static">Static website</option>
    <option value="node">Node.js</option>
    <option value="python">Python</option>
    <option value="fastapi">FastAPI</option>
    <option value="flask">Flask</option>
   </select>
   <input id="buildcmd" placeholder="Build command (ixtiyoriy)">
   <input id="startcmd" placeholder="Start command (ixtiyoriy)">
   <button onclick="createProject()">Loyiha yaratish</button>
   <div id="projectlist"></div>
  </div>

  <div class="card">
   <h2>Deployments</h2>
   <p>Deploy so‘rovlari yaratiladi. Ishga tushirish uchun alohida worker talab qilinadi.</p>
   <button onclick="loadDeployments()">Yangilash</button>
   <div id="deploymentlist"></div>
  </div>

  <div class="card">
   <h2>Admin</h2>
   <button onclick="loadAdmin()">Statistikani ko‘rish</button>
   <pre id="adminstats"></pre>
  </div>
 </section>
 <pre id="notice"></pre>
</main>
<script>
async function api(path, method="GET", body=null){
 const options={method,headers:{"Content-Type":"application/json"},
 credentials:"same-origin"};
 if(body!==null)options.body=JSON.stringify(body);
 const response=await fetch(path,options);
 const data=await response.json().catch(()=>({detail:"Server error"}));
 if(!response.ok)throw new Error(data.detail||"Request failed");
 return data;
}
function msg(id,text){document.getElementById(id).textContent=text}
async function auth(action){
 try{
  const data=await api("/api/"+action,"POST",{
   email:document.getElementById("email").value,
   password:document.getElementById("password").value});
  msg("authmsg",data.message||"Tayyor");
  await refresh();
 }catch(e){msg("authmsg",e.message)}
}
async function logout(){
 try{await api("/api/logout","POST");location.reload()}
 catch(e){msg("notice",e.message)}
}
async function refresh(){
 try{
  const user=await api("/api/me");
  document.getElementById("auth").classList.add("hidden");
  document.getElementById("dashboard").classList.remove("hidden");
  msg("profile",user.email+(user.is_admin?" — ADMIN":""));
  await loadRepos();await loadProjects();await loadDeployments();
 }catch(e){
  document.getElementById("auth").classList.remove("hidden");
  document.getElementById("dashboard").classList.add("hidden");
 }
}
async function loadRepos(){
 const items=await api("/api/repositories");
 msg("repos",items.length);
 document.getElementById("repolist").replaceChildren();
 items.forEach(r=>{
  const d=document.createElement("div");d.className="card";
  const t=document.createElement("strong");t.textContent=r.name+" (#"+r.id+")";
  const p=document.createElement("p");p.textContent=r.description;
  const b=document.createElement("button");b.textContent="Fayllar";
  b.onclick=()=>{document.getElementById("fileRepo").value=r.id;
  document.getElementById("projectrepo").value=r.id};
  d.append(t,p,b);document.getElementById("repolist").append(d);
 });
}
async function createRepo(){
 try{await api("/api/repositories","POST",{
  name:document.getElementById("reponame").value,
  description:document.getElementById("repodesc").value,
  is_public:false});
  await loadRepos();msg("notice","Repository yaratildi");
 }catch(e){msg("notice",e.message)}
}
async function saveFile(){
 try{
  const id=document.getElementById("fileRepo").value;
  const result=await api("/api/repositories/"+id+"/files","PUT",{
   path:document.getElementById("filepath").value,
   content:document.getElementById("filecontent").value});
  msg("filemsg",result.message);
 }catch(e){msg("filemsg",e.message)}
}
async function createProject(){
 try{
  const p=await api("/api/projects","POST",{
   repository_id:Number(document.getElementById("projectrepo").value),
   name:document.getElementById("projectname").value,
   runtime:document.getElementById("runtime").value,
   build_command:document.getElementById("buildcmd").value,
   start_command:document.getElementById("startcmd").value});
  msg("notice","Loyiha yaratildi: "+p.name);
  await loadProjects();
 }catch(e){msg("notice",e.message)}
}
async function loadProjects(){
 const items=await api("/api/projects");
 msg("projects",items.length);
 const box=document.getElementById("projectlist");box.replaceChildren();
 items.forEach(p=>{
  const d=document.createElement("div");d.className="card";
  const t=document.createElement("strong");
  t.textContent=p.name+" (#"+p.id+") — "+p.runtime;
  const b=document.createElement("button");b.textContent="Deploy so‘rovi";
  b.onclick=async()=>{
   try{
    const result=await api("/api/projects/"+p.id+"/deploy","POST");
    msg("notice","Deploy #"+result.id+": "+result.status);
    await loadDeployments();
   }catch(e){msg("notice",e.message)}
  };
  d.append(t,b);box.append(d);
 });
}
async function loadDeployments(){
 try{
  const items=await api("/api/deployments");
  msg("deployments",items.length);
  const box=document.getElementById("deploymentlist");
  box.replaceChildren();
  items.forEach(x=>{
   const d=document.createElement("div");d.className="card";
   const t=document.createElement("strong");
   t.textContent="#"+x.id+" — "+x.status;
   const p=document.createElement("pre");p.textContent=x.logs;
   d.append(t,p);box.append(d);
  });
 }catch(e){msg("notice",e.message)}
}
async function loadAdmin(){
 try{msg("adminstats",JSON.stringify(await api("/api/admin/overview"),null,2))}
 catch(e){msg("adminstats",e.message)}
}
refresh();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


# =====================================================
# STARTUP
# =====================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000"))
    )
