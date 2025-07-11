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
from urllib.parse import unquote

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
    cargo_nombre: str  

class UsuarioCreate(BaseModel):
    usuario_id: int
    usuario_nombre: str
    usuario_password: str
    cargo_nombre: str  

class Usuario(UsuarioBase):
    usuario_id: int

    class Config:
        from_attributes = True

class UsuarioUpdate(BaseModel):
    usuario_nombre: Optional[str] = None
    usuario_password: Optional[str] = None
    cargo_nombre: Optional[str] = None  

class CargoBase(BaseModel):
    cargo_nombre: str
    cargo_descripcion: str

class CargoCreate(CargoBase):
    cargo_id: int

class CargoUpdate(BaseModel):
    cargo_nombre: Optional[str] = None
    cargo_descripcion: Optional[str] = None

class Cargo(CargoBase):
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    cargo_nombre: str
    usuario_id: int

class TokenData(BaseModel):
    usuario_id: Optional[str] = None

class ProductoBase(BaseModel):
    producto_nombre: str
    producto_descripcion: str
    producto_proovedor: int
    producto_categoria: Optional[str] = None
    cantidad_total: Optional[int] = None

class ProductoCreate(ProductoBase):
    producto_id: int

class ProductoUpdate(BaseModel):
    producto_nombre: Optional[str] = None
    producto_descripcion: Optional[str] = None
    producto_proovedor: Optional[int] = None
    producto_categoria: Optional[str] = None

class MovimientoBase(BaseModel):
    movimiento_producto: int
    movimiento_descripcion: str
    bodega_origen: int
    bodega_destino: int
    cantidad: int
    movimiento_usuario: int

class MovimientoCreate(BaseModel):
    movimiento_id: int
    movimiento_producto: int
    movimiento_descripcion: str
    bodega_origen: int
    bodega_destino: int
    movimiento_usuario: int
    cantidad: int

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

class InventarioBase(BaseModel):
    producto_id: int
    producto_nombre: str
    bodega_id: int
    inventario_cantidad: int

class InventarioCreate(InventarioBase):
    pass

class InventarioUpdate(BaseModel):
    producto_nombre: Optional[str] = None
    bodega_id: Optional[int] = None
    inventario_cantidad: Optional[int] = None

class BodegaBase(BaseModel):
    bodega_nombre: str
    bodega_ubicacion: str

class BodegaCreate(BodegaBase):
    bodega_id: int 

class BodegaUpdate(BaseModel):
    bodega_nombre: Optional[str] = None
    bodega_ubicacion: Optional[str] = None

class CategoriaBase(BaseModel):
    categoria_nombre: str
    categoria_descripcion: str

class CategoriaCreate(CategoriaBase):
    categoria_nombre: str

class CategoriaUpdate(BaseModel):
    categoria_nombre: Optional[str] = None
    categoria_descripcion: Optional[str] = None

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
    
    # Crear el token de acceso
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["usuario_id"])}, expires_delta=access_token_expires
    )
    
    # Retornar el token junto con el cargo y el ID del usuario
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "usuario_id": user["usuario_id"],
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
    
@app.get("/productos/", response_model=list[dict])
async def listar_productos():
    try:
        productos = supabase.table("producto").select(
            "producto_id, producto_nombre, producto_descripcion, producto_proovedor, producto_categoria, cantidad_total"
        ).execute()
        if not productos.data:
            raise HTTPException(status_code=404, detail="No se encontraron productos")
        return productos.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los productos: {str(e)}")
    
@app.post("/productos/add", response_model=dict)
async def agregar_producto(
    producto_nombre: str,
    producto_descripcion: str,
    producto_proovedor: int,
    producto_categoria: Optional[str] = None
):
    try:
        # Obtener el último producto_id
        ultimo = supabase.table("producto").select("producto_id").order("producto_id", desc=True).limit(1).execute()
        nuevo_id = (ultimo.data[0]["producto_id"] + 1) if ultimo.data else 1

        producto_data = {
            "producto_id": nuevo_id,
            "producto_nombre": producto_nombre,
            "producto_descripcion": producto_descripcion,
            "producto_proovedor": producto_proovedor,
            "producto_categoria": producto_categoria
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
        if datos.producto_proovedor is not None:
            producto_data["producto_proovedor"] = datos.producto_proovedor
        if datos.producto_categoria is not None:
            producto_data["producto_categoria"] = datos.producto_categoria
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
            "movimiento_id, movimiento_producto, movimiento_descripcion, bodega_origen, cantidad, bodega_destino, movimiento_usuario"
        ).execute()
        if not movimientos.data:
            raise HTTPException(status_code=404, detail="No se encontraron movimientos")
        return movimientos.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los movimientos: {str(e)}")
    
@app.post("/movimientos/add", response_model=dict)
async def agregar_movimiento(
    movimiento_producto: int,
    movimiento_descripcion: str,
    bodega_origen: int,
    bodega_destino: int,
    cantidad: int,
    movimiento_usuario: int
):
    try:
        # Verificar si el producto existe en la bodega de origen
        inventario_origen = supabase.table("inventario").select("*").eq("producto_id", movimiento_producto).eq("bodega_id", bodega_origen).execute()
        if not inventario_origen.data:
            raise HTTPException(status_code=400, detail="El producto no existe en la bodega de origen")
        
        # Verificar si hay suficiente cantidad en la bodega de origen
        if inventario_origen.data[0]["inventario_cantidad"] < cantidad:
            raise HTTPException(status_code=400, detail="Cantidad insuficiente en la bodega de origen")
        
        # Verificar si el producto ya existe en la bodega de destino
        inventario_destino = supabase.table("inventario").select("*").eq("producto_id", movimiento_producto).eq("bodega_id", bodega_destino).execute()
        
        if inventario_destino.data:
            # Si existe, actualizar la cantidad en la bodega de destino
            nueva_cantidad_destino = inventario_destino.data[0]["inventario_cantidad"] + cantidad
            supabase.table("inventario").update({"inventario_cantidad": nueva_cantidad_destino}).eq("producto_id", movimiento_producto).eq("bodega_id", bodega_destino).execute()
        else:
            # Si no existe, crear un nuevo registro en la bodega de destino
            nuevo_inventario = {
                "producto_id": movimiento_producto,
                "producto_nombre": inventario_origen.data[0]["producto_nombre"],
                "bodega_id": bodega_destino,
                "inventario_cantidad": cantidad
            }

            # Insertar el nuevo registro en la tabla inventario
            nuevo_inventario_result = supabase.table("inventario").insert(nuevo_inventario).execute()

            # Verificar si la inserción fue exitosa
            if not nuevo_inventario_result.data:
                raise HTTPException(status_code=500, detail="Error al crear el registro en la bodega de destino")
        
        # Actualizar la cantidad en la bodega de origen
        nueva_cantidad_origen = inventario_origen.data[0]["inventario_cantidad"] - cantidad
        supabase.table("inventario").update({"inventario_cantidad": nueva_cantidad_origen}).eq("producto_id", movimiento_producto).eq("bodega_id", bodega_origen).execute()
        
        # Generar un ID único para el movimiento (si no es autogenerado por la base de datos)
        movimiento_id = supabase.table("movimientos").select("movimiento_id").order("movimiento_id", desc=True).limit(1).execute()
        nuevo_movimiento_id = (movimiento_id.data[0]["movimiento_id"] + 1) if movimiento_id.data else 1
        
        # Registrar el movimiento en la tabla de movimientos
        movimiento_data = {
            "movimiento_id": nuevo_movimiento_id,
            "movimiento_producto": movimiento_producto,
            "movimiento_descripcion": movimiento_descripcion,
            "bodega_origen": bodega_origen,
            "bodega_destino": bodega_destino,
            "movimiento_usuario": movimiento_usuario,
            "cantidad": cantidad
        }
        data = supabase.table("movimientos").insert(movimiento_data).execute()
        
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al registrar el movimiento")
        
        return {"message": "Movimiento registrado exitosamente", "movimiento": data.data[0]}
    except HTTPException as http_err:
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
    proveedor_nombre: str,
    proveedor_vendedor: str,
    proveedor_contacto: str,
    proveedor_direccion: str,
    proveedor_comuna: str,
    proveedor_giro: str
):
    try:
        # Obtener el último proveedor_id
        ultimo = supabase.table("proveedor").select("proveedor_id").order("proveedor_id", desc=True).limit(1).execute()
        nuevo_id = (ultimo.data[0]["proveedor_id"] + 1) if ultimo.data else 1

        proveedor_data = {
            "proveedor_id": nuevo_id,
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
    
@app.get("/inventario/", response_model=list[dict])
async def listar_inventario():
    try:
        inventario = supabase.table("inventario").select("*").execute()
        if not inventario.data:
            raise HTTPException(status_code=404, detail="No se encontraron registros en el inventario")
        return inventario.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener el inventario: {str(e)}")
    
@app.post("/inventario/add", response_model=dict)
async def agregar_inventario(
    producto_id: int,
    producto_nombre: str,
    bodega_id: int,
    inventario_cantidad: int
):
    try:
        # Verificar si ya existe un registro con el mismo producto y bodega
        inventario_existente = supabase.table("inventario").select("*").eq("producto_id", producto_id).eq("bodega_id", bodega_id).execute()
        if inventario_existente.data:
            # Si el producto ya existe, sumar la cantidad al registro existente
            cantidad_actual = inventario_existente.data[0]["inventario_cantidad"]
            nueva_cantidad = cantidad_actual + inventario_cantidad
            data = supabase.table("inventario").update({"inventario_cantidad": nueva_cantidad}).eq("producto_id", producto_id).eq("bodega_id", bodega_id).execute()
            if not data.data:
                raise HTTPException(status_code=500, detail="Error al actualizar la cantidad del inventario")
            return {"message": "Cantidad actualizada en el inventario", "inventario": data.data[0]}
        else:
            # Si no existe, crear un nuevo registro
            inventario_data = {
                "producto_id": producto_id,
                "producto_nombre": producto_nombre,
                "bodega_id": bodega_id,
                "inventario_cantidad": inventario_cantidad
            }
            data = supabase.table("inventario").insert(inventario_data).execute()
            if not data.data:
                raise HTTPException(status_code=500, detail="Error al agregar el registro al inventario")
            return {"message": "Registro agregado al inventario", "inventario": data.data[0]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.put("/inventario/update/{inventario_id}", response_model=dict)
async def actualizar_inventario(inventario_id: int, datos: InventarioUpdate):
    try:
        # Verificar si el registro existe
        inventario_existente = supabase.table("inventario").select("*").eq("inventario_id", inventario_id).execute()
        if not inventario_existente.data:
            raise HTTPException(status_code=404, detail="El registro especificado no existe en el inventario")
        
        # Preparar los datos para actualizar
        inventario_data = {}
        if datos.producto_nombre is not None:
            inventario_data["producto_nombre"] = datos.producto_nombre
        if datos.bodega_id is not None:
            inventario_data["bodega_id"] = datos.bodega_id
        if datos.inventario_cantidad is not None:
            inventario_data["inventario_cantidad"] = datos.inventario_cantidad
        
        if not inventario_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar")
        
        # Actualizar el registro
        data = supabase.table("inventario").update(inventario_data).eq("inventario_id", inventario_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar el registro del inventario")
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.put("/inventario/remove", response_model=dict)
async def eliminar_cantidad_inventario(
    producto_id: int,
    bodega_id: int,
    cantidad_a_eliminar: int
):
    try:
        # Verificar si el producto existe en la bodega
        inventario_existente = supabase.table("inventario").select("*").eq("producto_id", producto_id).eq("bodega_id", bodega_id).execute()
        if not inventario_existente.data:
            raise HTTPException(status_code=404, detail="El producto no existe en la bodega especificada")
        
        # Verificar si hay suficiente cantidad para eliminar
        cantidad_actual = inventario_existente.data[0]["inventario_cantidad"]
        if cantidad_actual < cantidad_a_eliminar:
            raise HTTPException(status_code=400, detail="Cantidad insuficiente en el inventario para realizar la operación")
        
        # Calcular la nueva cantidad
        nueva_cantidad = cantidad_actual - cantidad_a_eliminar
        
        # Actualizar el inventario con la nueva cantidad
        data = supabase.table("inventario").update({"inventario_cantidad": nueva_cantidad}).eq("producto_id", producto_id).eq("bodega_id", bodega_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar la cantidad del inventario")
        
        return {"message": "Cantidad eliminada del inventario exitosamente", "inventario": data.data[0]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.delete("/inventario/delete/{inventario_id}", response_model=dict)
async def eliminar_inventario(inventario_id: int):
    try:
        # Verificar si el registro existe
        inventario_existente = supabase.table("inventario").select("*").eq("inventario_id", inventario_id).execute()
        if not inventario_existente.data:
            raise HTTPException(status_code=404, detail="El registro especificado no existe en el inventario")
        
        # Eliminar el registro
        data = supabase.table("inventario").delete().eq("inventario_id", inventario_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al eliminar el registro del inventario")
        return {"message": f"Registro con ID {inventario_id} eliminado exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.get("/bodegas/", response_model=list[dict])
async def listar_bodegas():
    try:
        bodegas = supabase.table("bodega").select("*").execute()
        if not bodegas.data:
            raise HTTPException(status_code=404, detail="No se encontraron bodegas")
        return bodegas.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener las bodegas: {str(e)}")

@app.post("/bodegas/add", response_model=dict)
async def agregar_bodega(
    bodega_nombre: str,
    bodega_ubicacion: str
):
    try:
        # Obtener el último bodega_id
        ultimo = supabase.table("bodega").select("bodega_id").order("bodega_id", desc=True).limit(1).execute()
        nuevo_id = (ultimo.data[0]["bodega_id"] + 1) if ultimo.data else 1

        bodega_data = {
            "bodega_id": nuevo_id,
            "bodega_nombre": bodega_nombre,
            "bodega_ubicacion": bodega_ubicacion
        }
        data = supabase.table("bodega").insert(bodega_data).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al agregar la bodega")
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.put("/bodegas/update/{bodega_id}", response_model=dict)
async def actualizar_bodega(bodega_id: int, datos: BodegaBase):
    try:
        bodega_existente = supabase.table("bodega").select("*").eq("bodega_id", bodega_id).execute()
        if not bodega_existente.data:
            raise HTTPException(status_code=404, detail="La bodega especificada no existe")

        bodega_data = {}
        if datos.bodega_nombre is not None:
            bodega_data["bodega_nombre"] = datos.bodega_nombre
        if datos.bodega_ubicacion is not None:
            bodega_data["bodega_ubicacion"] = datos.bodega_ubicacion

        if not bodega_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar")

        data = supabase.table("bodega").update(bodega_data).eq("bodega_id", bodega_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar la bodega")

        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.delete("/bodegas/delete/{bodega_id}", response_model=dict)
async def eliminar_bodega(bodega_id: int):
    try:
        bodega_existente = supabase.table("bodega").select("*").eq("bodega_id", bodega_id).execute()
        if not bodega_existente.data:
            raise HTTPException(status_code=404, detail="La bodega especificada no existe")

        data = supabase.table("bodega").delete().eq("bodega_id", bodega_id).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al eliminar la bodega")

        return {"message": f"Bodega con ID {bodega_id} eliminada exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.get("/cargo/", response_model=list[dict])
async def listar_cargos():
    try:
        cargos = supabase.table("cargo").select("cargo_nombre, cargo_descripcion").execute()
        if not cargos.data:
            raise HTTPException(status_code=404, detail="No se encontraron cargos")
        return cargos.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los cargos: {str(e)}")
    
@app.post("/cargo/add", response_model=Cargo)
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
    
@app.put("/cargo/update/{cargo_nombre}", response_model=Cargo)
async def actualizar_cargo(cargo_nombre: str, datos: CargoUpdate):
    try:
        # Verificar si el cargo existe
        cargo_existente = supabase.table("cargo").select("*").eq("cargo_nombre", cargo_nombre).execute()
        if not cargo_existente.data:
            raise HTTPException(status_code=404, detail="Cargo no encontrado")

        # Actualizar el cargo
        cargo_data = {
            "cargo_nombre": datos.cargo_nombre,
            "cargo_descripcion": datos.cargo_descripcion
        }
        data = supabase.table("cargo").update(cargo_data).eq("cargo_nombre", cargo_nombre).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar el cargo")

        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.delete("/cargo/delete/{cargo_nombre}", response_model=dict)
async def eliminar_cargo(cargo_nombre: str):
    try:
        # Verificar si el cargo existe
        cargo_existente = supabase.table("cargo").select("*").eq("cargo_nombre", cargo_nombre).execute()
        if not cargo_existente.data:
            raise HTTPException(status_code=404, detail="Cargo no encontrado")
        
        # Eliminar el cargo
        data = supabase.table("cargo").delete().eq("cargo_nombre", cargo_nombre).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al eliminar el cargo")
        
        return {"message": f"Cargo '{cargo_nombre}' eliminado exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.get("/categoria/", response_model=list[dict])
async def listar_categorias():
    try:
        categorias = supabase.table("categoria").select("categoria_nombre, categoria_descripcion").execute()
        if not categorias.data:
            raise HTTPException(status_code=404, detail="No se encontraron categorías")
        return categorias.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener las categorías: {str(e)}")
    
@app.post("/categoria/add", response_model=CategoriaCreate)
async def agregar_categoria(
    categoria_nombre: str,
    categoria_descripcion: str
):
    try:
        # Verificar si la categoría ya existe
        categoria_existente = supabase.table("categoria").select("*").eq("categoria_nombre", categoria_nombre).execute()
        if categoria_existente.data:
            raise HTTPException(status_code=400, detail="La categoría especificada ya existe")
        
        # Insertar nueva categoría
        categoria_data = {
            "categoria_nombre": categoria_nombre,
            "categoria_descripcion": categoria_descripcion
        }
        data = supabase.table("categoria").insert(categoria_data).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al agregar la categoría")
        
        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    
@app.put("/categoria/update/{categoria_nombre}", response_model=CategoriaUpdate)
async def actualizar_categoria(categoria_nombre: str, datos: CategoriaUpdate):
    try:
        # Verificar si la categoría existe
        categoria_existente = supabase.table("categoria").select("*").eq("categoria_nombre", categoria_nombre).execute()
        if not categoria_existente.data:
            raise HTTPException(status_code=404, detail="Categoría no encontrada")

        # Actualizar la categoría
        categoria_data = {}
        if datos.categoria_nombre is not None:
            categoria_data["categoria_nombre"] = datos.categoria_nombre
        if datos.categoria_descripcion is not None:
            categoria_data["categoria_descripcion"] = datos.categoria_descripcion

        if not categoria_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar")

        data = supabase.table("categoria").update(categoria_data).eq("categoria_nombre", categoria_nombre).execute()
        if not data.data:
            raise HTTPException(status_code=500, detail="Error al actualizar la categoría")

        return data.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.delete("/categoria/delete/{categoria_nombre}")
async def eliminar_categoria(categoria_nombre: str):
    try:
        # Decodificar el nombre de la categoría (convierte %20 en espacios)
        nombre_decodificado = unquote(categoria_nombre)
        
        # Verificar existencia (comparación exacta incluyendo espacios)
        categoria_existente = supabase.table("categoria") \
            .select("*") \
            .eq("categoria_nombre", nombre_decodificado) \
            .execute()

        if not categoria_existente.data:
            raise HTTPException(status_code=404, detail="Categoría no encontrada")

        # Eliminar
        supabase.table("categoria") \
            .delete() \
            .eq("categoria_nombre", nombre_decodificado) \
            .execute()

        return {"message": f"Categoría '{nombre_decodificado}' eliminada exitosamente"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



