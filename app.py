# app.py
# =============================================================================
# FastAPI + SQLAlchemy (assíncrono com asyncpg) + JWT
# - Aceita DATABASE_URL interna (sem SSL) ou externa (.render.com) automaticamente.
# - Cria tabelas no startup e garante usuário admin/123 se não existir (configurável).
# =============================================================================

import os
import sys
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from sqlalchemy import String, Integer, DateTime, func, select
from sqlalchemy.orm import Mapped, mapped_column, declarative_base
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from passlib.context import CryptContext
from jose import jwt, JWTError

# =============================================================================
# Configurações de Ambiente
# =============================================================================

DATABASE_URL_RAW = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL_RAW:
    raise RuntimeError("A variável de ambiente DATABASE_URL não foi definida.")

# Secret de JWT (troque em produção)
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-me")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "360"))  # 6 horas padrão

# CORS (origem do seu frontend; ajuste se precisar)
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:8000")
CORS_ORIGINS = ["*"]

# Se quiser pular criação do admin automático, defina INIT_ADMIN=false
INIT_ADMIN = os.getenv("INIT_ADMIN", "true").lower() == "true"
INIT_ADMIN_USER = os.getenv("INIT_ADMIN_USER", "admin")
INIT_ADMIN_PASS = os.getenv("INIT_ADMIN_PASS", "123")

# =============================================================================
# Normalização de DATABASE_URL para asyncpg (interno vs externo)
# - Interno (host sem ponto, ex.: dpg-...-a) => sem SSL
# - Externo (.render.com) => força SSL para asyncpg
# =============================================================================

u = urlparse(DATABASE_URL_RAW)

# 1) Garante driver assíncrono (asyncpg)
scheme = u.scheme or "postgresql"
if scheme == "postgresql":
    scheme = "postgresql+asyncpg"
elif scheme.startswith("postgresql+") and "asyncpg" not in scheme:
    scheme = "postgresql+asyncpg"

# 2) Detecta URL externa (tem ponto no hostname, ex.: .render.com) vs interna
host = (u.hostname or "")
is_external = "." in host

# 3) Limpa query antiga e aplica SSL só quando for externo
qs = dict(parse_qsl(u.query or "", keep_blank_values=True))
qs.pop("sslmode", None)  # asyncpg não usa sslmode
qs.pop("ssl", None)

if is_external:
    # Externo => SSL habilitado para asyncpg
    qs["ssl"] = "true"

DATABASE_URL = urlunparse(u._replace(scheme=scheme, query=urlencode(qs)))

# =============================================================================
# Banco de Dados (SQLAlchemy 2.0 assíncrono)
# =============================================================================

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# Monta kwargs do engine sem passar None em connect_args
engine_kwargs = dict(echo=False, pool_pre_ping=True)
if is_external:
    # Apenas quando externo
    engine_kwargs["connect_args"] = {"ssl": True}

engine = create_async_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = async_sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =============================================================================
# Utilidades de Autenticação
# =============================================================================

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_ctx.verify(password, password_hash)

def create_access_token(sub: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN)
    payload = {"sub": sub, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub: str = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido (sem sub).")
        return sub
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token inválido: {str(e)}")

# =============================================================================
# Schemas (Pydantic)
# =============================================================================

class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MeOut(BaseModel):
    id: int
    username: str
    created_at: datetime

# =============================================================================
# App FastAPI
# =============================================================================

app = FastAPI(title="Auth API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Startup / Shutdown
# =============================================================================

@app.on_event("startup")
async def startup() -> None:
    # Cria tabelas
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Cria admin se solicitado
    if INIT_ADMIN:
        async with SessionLocal() as session:
            res = await session.execute(select(User).where(User.username == INIT_ADMIN_USER))
            user = res.scalar_one_or_none()
            if not user:
                user = User(
                    username=INIT_ADMIN_USER,
                    password_hash=hash_password(INIT_ADMIN_PASS),
                )
                session.add(user)
                await session.commit()
                print(f"[startup] Usuário admin criado: {INIT_ADMIN_USER}/{INIT_ADMIN_PASS}", file=sys.stderr)
            else:
                print("[startup] Usuário admin já existe; pulando criação.", file=sys.stderr)

@app.on_event("shutdown")
async def shutdown() -> None:
    # Nada específico; o engine é limpo ao encerrar o processo
    pass

# =============================================================================
# Dependências
# =============================================================================

async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session

# =============================================================================
# Rotas
# =============================================================================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "driver": DATABASE_URL.split("://", 1)[0],
        "external_ssl": bool(is_external),
        "time": datetime.utcnow().isoformat() + "Z",
    }

@app.post("/auth/login", response_model=TokenOut)
async def login(body: LoginIn, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(User).where(User.username == body.username))
    user = res.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário ou senha inválidos.")
    token = create_access_token(sub=user.username)
    return TokenOut(access_token=token)

@app.get("/me", response_model=MeOut)
async def me(authorization: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """
    Use o header: Authorization: Bearer <token>
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Header Authorization ausente.")
    token = authorization.split(" ", 1)[1].strip()
    # Decodifica token e busca usuário
    username = decode_access_token(token)
    res = await db.execute(select(User).where(User.username == username))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário não encontrado.")
    return MeOut(id=user.id, username=user.username, created_at=user.created_at)

@app.get("/")
async def root():
    return {"message": "API no ar. Use /auth/login para obter token e /me para verificar."}

# =============================================================================
# Execução local (apenas para desenvolvimento): uvicorn app:app --reload
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
