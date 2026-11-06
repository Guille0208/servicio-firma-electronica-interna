#!/usr/bin/env python3
"""Cliente de consola para el servicio interno firmad (prototipo local)."""
import argparse
import base64
import json
import socket
import sys
from pathlib import Path

HOST = '127.0.0.1'
PORT = 5050
MAX_FILE = 720 * 1024  # margen para JSON+Base64 dentro de un mensaje de 1 MiB


def consulta(payload):
    data = (json.dumps(payload, separators=(',', ':')) + '\n').encode('utf-8')
    if len(data) > 1024 * 1024:
        raise ValueError('Solicitud demasiado grande: limite de 1 MiB')
    with socket.create_connection((HOST, PORT), timeout=5) as conn:
        conn.settimeout(5)
        conn.sendall(data)
        with conn.makefile('rb') as f:
            line = f.readline(1024 * 1024)
    if not line:
        raise RuntimeError('El servidor no devolvio respuesta')
    return json.loads(line)


def main():
    parser = argparse.ArgumentParser(description='Cliente de firma digital Ed25519')
    sub = parser.add_subparsers(dest='op', required=True)
    sign = sub.add_parser('firmar', help='Firmar archivo y guardar su firma separada')
    sign.add_argument('archivo', type=Path)
    sign.add_argument('--salida', type=Path, default=Path('firma.json'))
    verify = sub.add_parser('verificar', help='Verificar firma respecto a un archivo')
    verify.add_argument('archivo', type=Path)
    verify.add_argument('--firma', type=Path, default=Path('firma.json'))
    args = parser.parse_args()
    content = args.archivo.read_bytes()
    if len(content) > MAX_FILE:
        raise ValueError('Archivo demasiado grande para el prototipo (max. 720 KiB)')
    request = {'request_id': 'ej-local', 'op': 'SIGN' if args.op == 'firmar' else 'VERIFY',
               'key_id': 'demo-local', 'data_b64': base64.b64encode(content).decode('ascii')}
    if args.op == 'verificar':
        signature = json.loads(args.firma.read_text(encoding='utf-8'))
        request['signature_b64'] = signature['signature_b64']
    response = consulta(request)
    print(json.dumps(response, ensure_ascii=False, indent=2))
    if response.get('status') != 'OK':
        return 1
    if args.op == 'firmar':
        args.salida.write_text(json.dumps({'key_id': 'demo-local', 'alg': 'Ed25519',
                                           'signature_b64': response['signature_b64']}, indent=2), encoding='utf-8')
        print('Firma guardada en:', args.salida)
    else:
        print('RESULTADO:', 'FIRMA VALIDA' if response.get('valid') else 'FIRMA INVALIDA')
        if not response.get('valid'):
            return 2
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print('Error:', exc, file=sys.stderr)
        sys.exit(1)
