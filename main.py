from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
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

origins = ["*"]  # Permitir todas las orígenes para CORS

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UsuarioBase(BaseModel):
    usuario_nombre: str
    cargo_nombre: str  # Cambiado de cargo_id a cargo_nombre

class UsuarioCreate(BaseModel):
    usuario_id: int
    usuario_nombre: str
    usuario_password: str
    cargo_nombre: str  # Cambiado de cargo_id a cargo_nombre

class Usuario(UsuarioBase):
    usuario_id: int

    class Config:
        from_attributes = True

class UsuarioUpdate(BaseModel):
    usuario_nombre: Optional[str] = None
    usuario_password: Optional[str] = None
    cargo_nombre: Optional[str] = None  # Cambiado de cargo_id a cargo_nombre

class CargoBase(BaseModel):
    cargo_nombre: str
    cargo_descripcion: str

class Cargo(CargoBase):
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    cargo_nombre: str

class TokenData(BaseModel):
    usuario_id: Optional[str] = None

class ProductoBase(BaseModel):
    producto_nombre: str
    producto_descripcion: str
    producto_bodega: int
    producto_proovedor: int

class ProductoCreate(ProductoBase):
    producto_id: int

class ProductoUpdate(BaseModel):
    producto_nombre: Optional[str] = None
    producto_descripcion: Optional[str] = None
    producto_bodega: Optional[int] = None
    producto_proovedor: Optional[int] = None

class MovimientoBase(BaseModel):
    movimiento_producto: int
    movimiento_descripcion: str
    bodega_origen: int
    bodega_destino: int
    movimiento_usuario: int

class MovimientoCreate(MovimientoBase):
    movimiento_id: int

class ProveedorBase(BaseModel):
    proveedor_id: int
    proveedor_nombre: str
    proveedor_vendedor: str
    proveedor_contacto: str
    proveedor_direccion: str
    proveedor_comuna: str
    proveedor_giro: str

class ProveedorCreate(ProveedorBase):
    proveedor_id: int


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
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "cargo_nombre": user.get("cargo_nombre")
    }

# Endpoints de Usuarios
@app.get("/usuarios/", response_model=list[dict])
async def listar_usuarios():
    try:
        # Obtener todos los usuarios con sus nombres de cargo
        usuarios = supabase.table("usuario").select("usuario_id, usuario_nombre, cargo_nombre").execute()
        
        if not usuarios.data:
            raise HTTPException(status_code=404, detail="No se encontraron usuarios")
        
        # Retornar la lista de usuarios con sus IDs, nombres y cargos
        return usuarios.data
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error al obtener los usuarios")
    
@app.post("/usuarios/add", response_model=Usuario)
async def agregar_usuario(
    usuario_nombre: str,
    usuario_password: str,
    cargo_nombre: str,
    usuario_id: int
):
    try:
        # Verificar si el cargo existe
        cargo = supabase.table("cargo").select("*").eq("cargo_nombre", cargo_nombre).execute()
        print(f"Cargo encontrado: {cargo}")  # Log para depuración
        if not cargo.data:
            raise HTTPException(status_code=400, detail="El cargo especificado no existe")
        
        # Verificar si el usuario ya existe
        usuario_existente = supabase.table("usuario").select("*").eq("usuario_id", usuario_id).execute()
        print(f"Usuario existente: {usuario_existente}")  # Log para depuración
        if usuario_existente.data:
            raise HTTPException(status_code=400, detail="El ID de usuario ya existe")
        
        # Preparar los datos para insertar
        usuario_data = {
            "usuario_nombre": usuario_nombre,
            "usuario_password": usuario_password,
            "cargo_nombre": cargo_nombre
        }
        if usuario_id is not None:
            usuario_data["usuario_id"] = usuario_id  # Usar el ID proporcionado
        
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
    
@app.post("/cargos/add", response_model=Cargo)
async def agregar_cargo(
    cargo_nombre: str,
    cargo_descripcion: str
):
    try:
        # Verificar si el cargo ya existe
        cargo_existente = supabase.table("cargo").select("*").eq("cargo_nombre", cargo_nombre).execute()
        if cargo_existente.data:
            raise HTTPException(status_code=400, detail="El cargo especificado ya existe")
        
        # Insertar nuevo cargo
        cargo_data = {
            "cargo_nombre": cargo_nombre,
            "cargo_descripcion": cargo_descripcion
        }
        data = supabase.table("cargo").insert(cargo_data).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al agregar el cargo")
        
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.put("/usuarios/update/{usuario_id}", response_model=Usuario)
async def actualizar_usuario(usuario_id: int, datos: UsuarioUpdate):
    try:
        usuario_existente = supabase.table("usuario").select("*").eq("usuario_id", usuario_id).execute()
        if not usuario_existente.data:
            raise HTTPException(status_code=404, detail="El usuario especificado no existe")

        if datos.cargo_nombre is not None:
            cargo = supabase.table("cargo").select("*").eq("cargo_nombre", datos.cargo_nombre).execute()
            if not cargo.data:
                raise HTTPException(status_code=400, detail="El cargo especificado no existe")

        usuario_data = {}
        if datos.usuario_nombre is not None:
            usuario_data["usuario_nombre"] = datos.usuario_nombre
        if datos.usuario_password is not None:
            usuario_data["usuario_password"] = datos.usuario_password
        if datos.cargo_nombre is not None:
            usuario_data["cargo_nombre"] = datos.cargo_nombre

        if not usuario_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar")

        data = supabase.table("usuario").update(usuario_data).eq("usuario_id", usuario_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar el usuario")

        return data.data[0]
    except HTTPException as http_err:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.delete("/usuarios/delete/{usuario_id}", response_model=dict)
async def eliminar_usuario(usuario_id: int):
    try:
        # Verificar si el usuario existe
        usuario_existente = supabase.table("usuario").select("*").eq("usuario_id", usuario_id).execute()
        print(f"Usuario existente: {usuario_existente}")  # Log para depuración
        if not usuario_existente.data:
            raise HTTPException(status_code=404, detail="El usuario especificado no existe")
        
        # Eliminar el usuario de la base de datos
        data = supabase.table("usuario").delete().eq("usuario_id", usuario_id).execute()
        print(f"Resultado de eliminación: {data}")  # Log para depuración
        
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al eliminar el usuario")
        
        return {"message": f"Usuario con ID {usuario_id} eliminado exitosamente"}
    except HTTPException as http_err:
        print(f"HTTPException: {http_err.detail}")  # Log para depuración
        raise
    except Exception as e:
        print(f"Error inesperado: {e}")  # Log para depuración
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.get("/cargos/", response_model=list[dict])
async def listar_cargos():
    try:
        cargos = supabase.table("cargo").select("cargo_id, cargo_nombre, cargo_descripcion").execute()
        if not cargos.data:
            raise HTTPException(status_code=404, detail="No se encontraron cargos")
        return cargos.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los cargos: {str(e)}")
    
@app.get("/productos/", response_model=list[dict])
async def listar_productos():
    try:
        productos = supabase.table("producto").select(
            "producto_id, producto_nombre, producto_descripcion, producto_bodega, producto_proovedor"
        ).execute()
        if not productos.data:
            raise HTTPException(status_code=404, detail="No se encontraron productos")
        return productos.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los productos: {str(e)}")
    
@app.post("/productos/add", response_model=dict)
async def agregar_producto(
    producto_id: int,
    producto_nombre: str,
    producto_descripcion: str,
    producto_bodega: int,
    producto_proovedor: int
):
    try:
        producto_existente = supabase.table("producto").select("*").eq("producto_id", producto_id).execute()
        if producto_existente.data:
            raise HTTPException(status_code=400, detail="El ID de producto ya existe")
        producto_data = {
            "producto_id": producto_id,
            "producto_nombre": producto_nombre,
            "producto_descripcion": producto_descripcion,
            "producto_bodega": producto_bodega,
            "producto_proovedor": producto_proovedor
        }
        data = supabase.table("producto").insert(producto_data).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al agregar el producto")
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.put("/productos/update/{producto_id}", response_model=dict)
async def actualizar_producto(producto_id: int, datos: ProductoUpdate):
    try:
        producto_existente = supabase.table("producto").select("*").eq("producto_id", producto_id).execute()
        if not producto_existente.data:
            raise HTTPException(status_code=404, detail="El producto especificado no existe")
        producto_data = {}
        if datos.producto_nombre is not None:
            producto_data["producto_nombre"] = datos.producto_nombre
        if datos.producto_descripcion is not None:
            producto_data["producto_descripcion"] = datos.producto_descripcion
        if datos.producto_bodega is not None:
            producto_data["producto_bodega"] = datos.producto_bodega
        if datos.producto_proovedor is not None:
            producto_data["producto_proovedor"] = datos.producto_proovedor
        if not producto_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar")
        data = supabase.table("producto").update(producto_data).eq("producto_id", producto_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar el producto")
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.delete("/productos/delete/{producto_id}", response_model=dict)
async def eliminar_producto(producto_id: int):
    try:
        producto_existente = supabase.table("producto").select("*").eq("producto_id", producto_id).execute()
        if not producto_existente.data:
            raise HTTPException(status_code=404, detail="El producto especificado no existe")
        data = supabase.table("producto").delete().eq("producto_id", producto_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al eliminar el producto")
        return {"message": f"Producto con ID {producto_id} eliminado exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.get("/movimientos/", response_model=list[dict])
async def listar_movimientos():
    try:
        movimientos = supabase.table("movimientos").select(
            "movimiento_id, movimiento_producto, movimiento_descripcion, bodega_origen, bodega_destino, movimiento_usuario"
        ).execute()
        if not movimientos.data:
            raise HTTPException(status_code=404, detail="No se encontraron movimientos")
        return movimientos.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los movimientos: {str(e)}")
    
@app.post("/movimientos/add", response_model=dict)
async def agregar_movimiento(
    movimiento_id: int,
    movimiento_producto: int,
    movimiento_descripcion: str,
    bodega_origen: int,
    bodega_destino: int,
    movimiento_usuario: int
):
    try:
        movimiento_data = {
            "movimiento_id": movimiento_id,
            "movimiento_producto": movimiento_producto,
            "movimiento_descripcion": movimiento_descripcion,
            "bodega_origen": bodega_origen,
            "bodega_destino": bodega_destino,
            "movimiento_usuario": movimiento_usuario
        }
        data = supabase.table("movimientos").insert(movimiento_data).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al agregar el movimiento")
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.get("/proveedores/", response_model=list[dict])
async def listar_proveedores():
    try:
        proveedores = supabase.table("proveedor").select(
            "proveedor_id, proveedor_nombre, proveedor_vendedor, proveedor_contacto, proveedor_direccion, proveedor_comuna, proveedor_giro"
        ).execute()
        if not proveedores.data:
            raise HTTPException(status_code=404, detail="No se encontraron proveedores")
        return proveedores.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los proveedores: {str(e)}")

@app.post("/proveedores/add", response_model=dict)
async def agregar_proveedor(
    proveedor_id: int,
    proveedor_nombre: str,
    proveedor_vendedor: str,
    proveedor_contacto: str,
    proveedor_direccion: str,
    proveedor_comuna: str,
    proveedor_giro: str
):
    try:
        proveedor_data = {
            "proveedor_id": proveedor_id,
            "proveedor_nombre": proveedor_nombre,
            "proveedor_vendedor": proveedor_vendedor,
            "proveedor_contacto": proveedor_contacto,
            "proveedor_direccion": proveedor_direccion,
            "proveedor_comuna": proveedor_comuna,
            "proveedor_giro": proveedor_giro
        }
        data = supabase.table("proveedor").insert(proveedor_data).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al agregar el proveedor")
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.put("/proveedores/update/{proveedor_id}", response_model=dict)
async def actualizar_proveedor(proveedor_id: int, datos: ProveedorBase):
    try:
        proveedor_existente = supabase.table("proveedor").select("*").eq("proveedor_id", proveedor_id).execute()
        if not proveedor_existente.data:
            raise HTTPException(status_code=404, detail="El proveedor especificado no existe")
        
        proveedor_data = {}
        if datos.proveedor_nombre is not None:
            proveedor_data["proveedor_nombre"] = datos.proveedor_nombre
        if datos.proveedor_vendedor is not None:
            proveedor_data["proveedor_vendedor"] = datos.proveedor_vendedor
        if datos.proveedor_contacto is not None:
            proveedor_data["proveedor_contacto"] = datos.proveedor_contacto
        if datos.proveedor_direccion is not None:
            proveedor_data["proveedor_direccion"] = datos.proveedor_direccion
        if datos.proveedor_comuna is not None:
            proveedor_data["proveedor_comuna"] = datos.proveedor_comuna
        if datos.proveedor_giro is not None:
            proveedor_data["proveedor_giro"] = datos.proveedor_giro
        
        if not proveedor_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar")
        
        data = supabase.table("proveedor").update(proveedor_data).eq("proveedor_id", proveedor_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar el proveedor")
        
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.delete("/proveedores/delete/{proveedor_id}", response_model=dict)
async def eliminar_proveedor(proveedor_id: int):
    try:
        proveedor_existente = supabase.table("proveedor").select("*").eq("proveedor_id", proveedor_id).execute()
        if not proveedor_existente.data:
            raise HTTPException(status_code=404, detail="El proveedor especificado no existe")
        
        data = supabase.table("proveedor").delete().eq("proveedor_id", proveedor_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al eliminar el proveedor")
        
        return {"message": f"Proveedor con ID {proveedor_id} eliminado exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")