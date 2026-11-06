#!/usr/bin/env python3
"""Pruebas locales; ejecutar con firmad encendido en otra terminal."""
import base64
import json
import socket
from cliente import consulta


def check(label, ok):
    print(('OK  ' if ok else 'FALLO  ') + label)
    if not ok:
        raise AssertionError(label)


msg = b'Informe academico: 25 solicitudes aprobadas.'
req = {'request_id': 'test-1', 'op': 'SIGN', 'key_id': 'demo-local',
       'data_b64': base64.b64encode(msg).decode()}
response = consulta(req)
check('Firma digital generada', response.get('status') == 'OK' and bool(response.get('signature_b64')))

verify = {**req, 'op': 'VERIFY', 'signature_b64': response['signature_b64']}
check('Firma autentica y documento original', consulta(verify).get('valid') is True)

verify['data_b64'] = base64.b64encode(b'Informe academico: 50 solicitudes aprobadas.').decode()
check('Cambio de documento detectado', consulta(verify).get('valid') is False)

check('Clave no registrada', consulta({**req, 'key_id': 'otra-clave'}).get('code') == 'KEY_NOT_FOUND')
check('Base64 invalido', consulta({**req, 'data_b64': '@@@@'}).get('code') == 'BAD_REQUEST')
check('Operacion no valida', consulta({**req, 'op': 'DELETE'}).get('code') == 'BAD_REQUEST')
check('Firma omitida en VERIFY', consulta({**req, 'op': 'VERIFY'}).get('code') == 'BAD_REQUEST')
with socket.create_connection(('127.0.0.1', 5050), timeout=5) as connection:
    connection.sendall(b'{no es json}\n')
    with connection.makefile('rb') as stream:
        invalid = json.loads(stream.readline())
check('JSON mal formado', invalid.get('code') == 'BAD_REQUEST')
print('8 PRUEBAS COMPLETADAS SATISFACTORIAMENTE')
