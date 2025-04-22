from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from database import supabase
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from jose import JWTError, jwt

load_dotenv()

app = FastAPI()

# Configuración de seguridad
SECRET_KEY = os.getenv("SECRET_KEY", "tu_secreto_muy_seguro_actualiza_esto")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Modelos Pydantic
class UsuarioBase(BaseModel):
    usuario_nombre: str
    cargo_id: int

class UsuarioCreate(BaseModel):
    usuario_id: Optional[int] = None  # Ahora el usuario puede proporcionar el ID
    usuario_nombre: str
    usuario_password: str
    cargo_id: int

class Usuario(UsuarioBase):
    usuario_id: int

    class Config:
        from_attributes = True  # Actualizado de orm_mode a from_attributes

class CargoBase(BaseModel):
    cargo_id: Optional[int] = None
    cargo_nombre: str
    cargo_descripcion: str

class Cargo(CargoBase):
    cargo_id: int

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    usuario_id: Optional[str] = None

# Funciones de ayuda
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def authenticate_user(usuario_id: int, password: str):
    usuario = supabase.table("usuario").select("*").eq("usuario_id", usuario_id).execute()
    if not usuario.data:
        return False
    if usuario.data[0]["usuario_password"] != password:
        return False
    return usuario.data[0]

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        usuario_id: str = payload.get("sub")
        if usuario_id is None:
            raise credentials_exception
        token_data = TokenData(usuario_id=usuario_id)
    except JWTError:
        raise credentials_exception
    
    usuario = supabase.table("usuario").select("*").eq("usuario_id", int(token_data.usuario_id)).execute()
    if not usuario.data:
        raise credentials_exception
    return usuario.data[0]

# Endpoints de Autenticación
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        usuario_id = int(form_data.username)  # Usamos username para el ID
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El ID de usuario debe ser un número"
        )
    
    user = await authenticate_user(usuario_id, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["usuario_id"])}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/usuarios/add", response_model=Usuario)
async def agregar_usuario(usuario: UsuarioCreate):
    try:
        # Verificar si el cargo existe
        cargo = supabase.table("cargo").select("*").eq("cargo_id", usuario.cargo_id).execute()
        print(f"Cargo encontrado: {cargo}")  # Log para depuración
        if not cargo.data:
            raise HTTPException(status_code=400, detail="El cargo especificado no existe")
        
        # Verificar si el usuario ya existe (si se proporciona un usuario_id)
        if usuario.usuario_id is not None:
            usuario_existente = supabase.table("usuario").select("*").eq("usuario_id", usuario.usuario_id).execute()
            print(f"Usuario existente: {usuario_existente}")  # Log para depuración
            if usuario_existente.data:
                raise HTTPException(status_code=400, detail="El ID de usuario ya existe")
        
        # Preparar los datos para insertar
        usuario_data = {
            "usuario_nombre": usuario.usuario_nombre,
            "usuario_password": usuario.usuario_password,
            "cargo_id": usuario.cargo_id
        }
        if usuario.usuario_id is not None:
            usuario_data["usuario_id"] = usuario.usuario_id  # Usar el ID proporcionado
        
        # Insertar nuevo usuario
        data = supabase.table("usuario").insert(usuario_data).execute()
        print(f"Resultado de inserción: {data}")  # Log para depuración
        
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al agregar el usuario")
        
        return data.data[0]
    except HTTPException as http_err:
        print(f"HTTPException: {http_err.detail}")  # Log para depuración
        raise
    except Exception as e:
        print(f"Error inesperado: {e}")  # Log para depuración
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

# Endpoints de Usuarios
@app.get("/usuarios/", response_model=list[dict])
async def listar_usuarios():
    try:
        # Obtener todos los usuarios
        usuarios = supabase.table("usuario").select("usuario_id, usuario_nombre").execute()
        
        if not usuarios.data:
            raise HTTPException(status_code=404, detail="No se encontraron usuarios")
        
        # Retornar la lista de usuarios con sus IDs y nombres
        return usuarios.data
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error al obtener los usuarios")
    
@app.post("/cargos/add", response_model=Cargo)
async def agregar_cargo(cargo: CargoBase):
    try:
        # Verificar si el cargo ya existe
        cargo_existente = supabase.table("cargo").select("*").eq("cargo_nombre", cargo.cargo_nombre).execute()
        print(f"Cargo existente: {cargo_existente}")  # Log para depuración
        if cargo_existente.data:
            raise HTTPException(status_code=400, detail="El cargo especificado ya existe")
        
        # Preparar los datos para insertar
        cargo_data = {
            "cargo_nombre": cargo.cargo_nombre,
            "cargo_descripcion": cargo.cargo_descripcion
        }
        if cargo.cargo_id is not None:
            cargo_data["cargo_id"] = cargo.cargo_id
        
        # Insertar nuevo cargo
        data = supabase.table("cargo").insert(cargo_data).execute()
        print(f"Resultado de inserción: {data}")  # Log para depuración
        
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al agregar el cargo")
        
        return data.data[0]
    except HTTPException as http_err:
        print(f"HTTPException: {http_err.detail}")  # Log para depuración
        raise
    except Exception as e:
        print(f"Error inesperado: {e}")  # Log para depuración
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.put("/usuarios/update/{usuario_id}", response_model=Usuario)
async def actualizar_usuario(usuario_id: int, usuario: UsuarioCreate):
    try:
        # Verificar si el usuario existe
        usuario_existente = supabase.table("usuario").select("*").eq("usuario_id", usuario_id).execute()
        print(f"Usuario existente: {usuario_existente}")  # Log para depuración
        if not usuario_existente.data:
            raise HTTPException(status_code=404, detail="El usuario especificado no existe")
        
        # Verificar si el cargo existe
        cargo = supabase.table("cargo").select("*").eq("cargo_id", usuario.cargo_id).execute()
        print(f"Cargo encontrado: {cargo}")  # Log para depuración
        if not cargo.data:
            raise HTTPException(status_code=400, detail="El cargo especificado no existe")
        
        # Preparar los datos para actualizar
        usuario_data = {
            "usuario_nombre": usuario.usuario_nombre,
            "usuario_password": usuario.usuario_password,
            "cargo_id": usuario.cargo_id
        }
        
        # Actualizar el usuario en la base de datos
        data = supabase.table("usuario").update(usuario_data).eq("usuario_id", usuario_id).execute()
        print(f"Resultado de actualización: {data}")  # Log para depuración
        
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar el usuario")
        
        return data.data[0]
    except HTTPException as http_err:
        print(f"HTTPException: {http_err.detail}")  # Log para depuración
        raise
    except Exception as e:
        print(f"Error inesperado: {e}")  # Log para depuración
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")