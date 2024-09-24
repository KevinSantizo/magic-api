#Authentication imports
import os
import requests
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any

#Socket imports 
import json
import socketio
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel 

router = APIRouter(
    tags=["bothControl"],
)


#Authentication
class AuthenticationError(Exception):
    """Exception raised for errors in the authentication process."""
    pass

class AuthorizationError(Exception):
    """Exception raised for errors in the authorization process."""
    pass

def authorize(request: Dict[str, Any]) -> str:
    """
    Authorizes a user and returns a JWT token.
    
    Args:
        request (Dict[str, Any]): The request object containing headers.
        
    Returns:
        str: The JWT token.
        
    Raises:
        AuthenticationError: If authentication fails at any point.
    """
    try:
        public_key = request['headers']['public_key']
        secret_key = request['headers']['secret_key']
        metadata = request['headers']['metadata']
    except KeyError:
        raise AuthorizationError('Missing required headers')
    try:
        # DJANGO_URL = os.environ['DJANGO_URL']
        # django_api = ApiService(DJANGO_URL)
        # url = f'/api/users/authenticate/'
        # response = django_api.get(url, headers={'public_key': public_key, 'secret_key': secret_key})
        # data = response.json()
        data = {'id': 14}
    except KeyError:
        raise AuthenticationError('DJANGO_URL not found in environment variables')
    except requests.exceptions.RequestException as e:
        raise AuthenticationError(f'Error occurred while making the request: {str(e)}')
    except ValueError as e:
        raise AuthenticationError(f'Error decoding JSON response: {str(e)}')

    try:
        expiration = datetime.now() + timedelta(days=1)
        jwt_key = os.environ['JWT_KEY']
        web_token = jwt.encode({'client_id': data['id'], 'metadata': metadata, 'exp': expiration}, jwt_key, algorithm='HS256')
        return web_token
    except KeyError:
        raise AuthenticationError('JWT_KEY not found in environment variables')
    except Exception as e:
        raise AuthenticationError(f'Error creating JWT token: {str(e)}')
    
    
def verify(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verifies the JWT token from the request headers.
    
    Args:
        request (Dict[str, Any]): The request object containing headers.

    Returns:
        bool: True if the token is valid, False otherwise.
        
    Raises:
        AuthorizationError: If authorization fails at any point.
    """
    try:
        jwt_key = os.environ['JWT_KEY']
    except KeyError:
        raise AuthorizationError('JWT_KEY not found in environment variables')
    try:
        authorization_token = request['headers']['Authorization']
    except KeyError:
        raise AuthorizationError('Authorization header is missing')
    try:
        return jwt.decode(authorization_token, jwt_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise AuthorizationError('Token has expired')
    except jwt.DecodeError:
        raise AuthorizationError('Invalid token')
    except jwt.InvalidSignatureError:
        raise AuthorizationError('Invalid signature')
    except Exception as e:
        raise AuthorizationError(f'Error verifying token: {str(e)}')

###

# Crear una instancia de FastAPI
app = FastAPI()

# Configuración de CORS
origins = ['*']
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


# Crear un servidor Socket.IO con CORS permitido para todos los orígenes
sio = socketio.AsyncServer(cors_allowed_origins='*', async_mode='asgi', ping_interval=3, ping_timeout=3)


# Envolver con la aplicación ASGI
socket_app = socketio.ASGIApp(sio, other_asgi_app=app, socketio_path='/socket.io')
 

@app.get('/')
async def read_root():
    #Endpoint para verificar que el servidor está en funcionamiento.
    return {'message': 'Server is now running'}


@sio.event
async def connect(sid, environ, auth):
    #Evento para manejar nuevas conexiones.
    if not verify({'headers': auth}):
        raise ConnectionRefusedError('Authentication failed')
    print(f'New Client Connected: {sid}')


@sio.event
async def subscribe(sid, channel, auth):
    #Evento para manejar suscripciones a canales.

    if not verify({'headers': auth}):
        raise ConnectionRefusedError('Authentication failed') 
    print(f'Client {sid} subscribed to channel: {channel}')
    await sio.enter_room(sid, channel)
    await sio.emit('message', {'message': f'Subscribed to {channel}'}, to=sid)


@sio.event
async def publish(sid, data, auth):
    """
    Event for handling message publishing. 
    """

    if not verify({'headers': auth}):
        raise ConnectionRefusedError('Authentication failed')
    sendable_message = data.get('message', '')
    if isinstance(sendable_message, str) and sendable_message.startswith("'") and sendable_message.endswith("'"):
        sendable_message = sendable_message[1:-1]
        try:
            sendable_message = json.loads(sendable_message)
        except json.JSONDecodeError:
            pass
     
    message_data = {
        'senderId': sid,
        'message': sendable_message
    }
    await sio.emit('message', message_data, room=data.get('channel'))
    print(f'{sendable_message} sent to {data.get("channel")}')


# Both control

def check_errors(event):
    if 'type' in event[1] and event[1]['type'] == 'error':
        return True
    return False

 
class ChannelRequest(BaseModel):
    channel: str
    command: str


# 
@router.post('/control/')
async def control(request: ChannelRequest): 
    await sio.emit('subscribe', request.channel)
    match request.command:
        case 'exit': 
            await sio.emit('publish', {"channel": f"{request.channel}-cmd", "message": {"type": "navigation", "screen": "end-screen"}})
            await sio.emit('publish', {"channel": f"{request.channel}", "message": {"type": "navigation", "screen": "end-screen"}})
            await sio.emit('publish', {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "close"}})
        
        case 'call_min':
            await sio.emit('publish', {"channel": f"{request.channel}-cmd", "message": {"type": "action", "vital-sign": "vol-"}})
            await sio.emit('publish', {"channel": f"{request.channel}", "message": {"type": "action", "vital-sign": "vol-"}})
        
        case 'call_up':
            await sio.emit('publish', {"channel": f"{request.channel}-cmd", "message": {"type": "action", "vital-sign": "vol+"}})
            await sio.emit('publish', {"channel": f"{request.channel}", "message": {"type": "action", "vital-sign": "vol+"}})
        
        case 'call_mute':
            await sio.emit('publish', {"channel": f"{request.channel}-cmd", "message": {"type": "action", "vital-sign": "mute"}})
            await sio.emit('publish', {"channel": f"{request.channel}", "message": {"type": "action", "vital-sign": "mute"}})

        case 'call_unmute':
            await sio.emit('publish', {"channel": f"{request.channel}-cmd", "message": {"type": "action", "vital-sign": "unmute"}})
            await sio.emit('publish', {"channel": f"{request.channel}", "message": {"type": "action", "vital-sign": "unmute"}})
        
        case 'emergency_on':
            await sio.emit('publish', {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "e-stop"}})
            await sio.emit('publish', {"channel": f"{request.channel}", "message": {"type": "command", "vital-sign": "e-stop"}})
        
        case 'emergency_off':
            await sio.emit('publish', {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "N-e-stop"}})
            await sio.emit('publish', {"channel": f"{request.channel}", "message": {"type": "command", "vital-sign": "N-e-stop"}})
        
        case _:
            return {'error': 'command not recognized'}

    return {'status': 'success'}

 

# Vital Signs 

@router.post("/instruments/")
async def instruments(request: ChannelRequest): 
    await sio.emit("subscribe", request.channel)
    match request.command:
        case 'height':  
            await sio.emit("publish", {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "height"}}) 
            try:
                event = await sio.receive(timeout=3) 
            except: 
                return {"sensor": "Sensor unavailable"}
            if check_errors(event):
                return {"error": event[1]['sensor']}
            return {"height": event[1]['message']['valor']}

        case 'weight':  
            await sio.emit("publish", {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "weight"}}) 
            try:
                event = await sio.receive(timeout=3) 
            except: 
                return {"sensor": "Sensor unavailable"}
            if check_errors(event):
                return {"error": event[1]['sensor']}
            return {"weight": event[1]['message']['valor']}

        case 'temperature':  
            await sio.emit("publish", {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "temperature"}}) 
            try:
                event = await sio.receive(timeout=3) 
            except: 
                return {"sensor": "Sensor unavailable"}
            if check_errors(event):
                return {"error": event[1]['sensor']}
            return {"temperature": event[1]['message']['valor']}
        
        case 'oximetry':  
            await sio.emit("publish", {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "oxygen"}}) 
            try:
                event1 = await sio.receive(timeout=5)
                event2 = await sio.receive(timeout=2)
            except:
                return {"error": "Sensor unavailable"}
            data = {"bpm": 0, "SpO2": 0}
            if check_errors(event1):
                return {"error": event1[1]['sensor']}
            elif check_errors(event2):
                return {"error": event2[1]['sensor']}
            for e in [event1, event2]:
                if e[1]['message']['vs'] == 'bpm':
                    data['bpm'] = e[1]['message']['valor']
                elif e[1]['message']['vs'] == 'SpO2':
                    data['SpO2'] = e[1]['message']['valor']
            return data
        
        case 'blood_pressure':  
            await sio.emit("publish", {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "blood_pressure"}}) 
            try:
                event1 = await sio.receive(timeout=5)
                event2 = await sio.receive(timeout=2)
            except:
                return {"error": "Sensor unavailable"}
            data = {"systolic": 0, "diastolic": 0}
            if check_errors(event1):
                return {"error": event1[1]['sensor']}
            elif check_errors(event2):
                return {"error": event2[1]['sensor']}
            for e in [event1, event2]:
                if e[1]['message']['vs'] == 'sis':
                    data['systolic'] = e[1]['message']['valor']
                elif e[1]['message']['vs'] == 'dias':
                    data['diastolic'] = e[1]['message']['valor']
            return data
        
        case _:
            return {'error': 'command not recognized'}
 
 
 # Esteto
@router.post("/stetho/")
async def stetho(request: ChannelRequest):
    await sio.emit("subscribe", request.channel)
    match request.command:
        case 'activate': 
            await sio.emit("publish", {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "mic"}})
            try:
                event = await sio.receive(timeout=3)
            except:
                return {"error": "Sensor unavailable"}
            if check_errors(event):
                return {"error": event[1]['sensor']}
            if "type" in event[1]['message'] and event[1]['message']['type'] == 'alarm' and event[1]['message']['mic'] == "cámara":
                return {"message": "Stethoscope activated"}
            return {"error": "Stethoscope not activated"}

        case 'deactivate':
            await sio.emit("publish", {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "mic"}})
            try:
                event = await sio.receive(timeout=2)
            except:
                return {"error": "Sensor unavailable"}
            if check_errors(event):
                return {"error": event[1]['sensor']}
            if "type" in event[1]['message'] and event[1]['message']['type'] == 'alarm' and event[1]['message']['mic'] == "cámara":
                return {"message": "Stethoscope deactivated"}
            return {"error": "Stethoscope not deactivated"}

        case 'record':
            await sio.emit("publish", {"channel": f"{request.channel}-cmd", "message": {"type": "command", "vital-sign": "esteto"}})
            try:
                event = await sio.receive(timeout=2)
            except:
                return {"error": "Sensor unavailable"}
            if check_errors(event):
                return {"error": event[1]['sensor']}
            if "type" in event[1]['message'] and event[1]['message']['type'] == 'alarm' and event[1]['message']['esteto'] == "done":
                return {"message": "Stethoscope audio recorded"}
            return {"error": "Stethoscope audio not recorded"}
        
        case _:
            return {'error': 'command not recognized'}

app.include_router(router)

@sio.event
async def disconnect(sid):
    #Evento para manejar desconexiones.
    print(f'Client Disconnected: {sid}')

if __name__=='__main__':
    uvicorn.run('socket_io:socket_app', host='0.0.0.0', port=2096, lifespan='on', reload=True)
