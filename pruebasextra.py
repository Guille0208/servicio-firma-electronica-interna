#!/usr/bin/env python3
import base64, json, os, socket, subprocess, sys, time
from pathlib import Path
os.chdir(Path(__file__).resolve().parent)
results=[]
def request(payload, fragment=False, eof=False):
    raw=(json.dumps(payload).encode()+b'\n') if isinstance(payload,dict) else payload
    with socket.create_connection(('127.0.0.1',5050),timeout=8) as s:
        if fragment:
            for i in range(0,len(raw),3): s.sendall(raw[i:i+3])
        else: s.sendall(raw)
        if eof: s.shutdown(socket.SHUT_WR)
        data=b''
        while b'\n' not in data:
            chunk=s.recv(4096)
            if not chunk: break
            data+=chunk
        return json.loads(data.split(b'\n')[0])
def run(name,fn):
    try:
        assert fn(), 'resultado inesperado'
        results.append(dict(prueba=name,resultado='OK'))
        print('OK',name,flush=True)
    except Exception as exc:
        results.append(dict(prueba=name,resultado='FALLO',detalle=str(exc)))
        print('FALLO',name,str(exc),flush=True)
def sign(data=''):
    return dict(request_id='extra',op='SIGN',key_id='demo-local',data_b64=data)
def bad(p,code='BAD_REQUEST',**kw):
    return request(p,**kw).get('code')==code
run('Objeto sin campos',lambda: bad({}))
run('JSON array',lambda: bad(b'[]\n'))
run('JSON con NUL escapado',lambda: bad(json.dumps(dict(op='SIGN'+chr(0)+'X')).encode()+bytes((10,))))
run('Base64 no canonico',lambda: bad(sign('AB==')))
run('Trama incompleta al cerrar escritura',lambda: bad(b'{',eof=True))
run('Solicitud fragmentada TCP',lambda: request(sign(),fragment=True).get('status')=='OK')
empty=request(sign())
run('Firma de documento vacio',lambda: empty.get('status')=='OK' and len(base64.b64decode(empty['signature_b64']))==64)
run('Verificacion de documento vacio',lambda: request(dict(sign(),op='VERIFY',signature_b64=empty['signature_b64'])).get('valid') is True)
run('Limite de mensaje de 1 MiB',lambda: bad(b'x'*(1048576+1)+b'\n','TOO_LARGE'))
run('Tiempo de espera de lectura',lambda: bad(b'{','TIMEOUT'))
pid=int(subprocess.check_output(['pgrep','-x','firmad']).split()[0])
fds=Path('/proc')/str(pid)/'fd'
before=len(list(fds.iterdir()))
run('100 solicitudes consecutivas',lambda: all(request(sign('AA==')).get('status')=='OK' for _ in range(100)))
after=len(list(fds.iterdir()))
run('Descriptores estables tras 100 solicitudes',lambda: before==after)
original=Path('ejemplo_informe.txt')
signed=json.loads(Path('firma.json').read_text())
Path('firma.bin').write_bytes(base64.b64decode(signed['signature_b64']))
run('Verificacion independiente con OpenSSL',lambda: subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey','keys/public.pem','-rawin','-in',str(original),'-sigfile','firma.bin'],capture_output=True).returncode==0)
Path('documento_alterado.txt').write_bytes(original.read_bytes()+b'\nDocumento alterado para la prueba.\n')
altered=base64.b64encode(Path('documento_alterado.txt').read_bytes()).decode()
run('Copia alterada conservando original',lambda: request(dict(sign(altered),op='VERIFY',signature_b64=signed['signature_b64'])).get('valid') is False)
report=dict(fecha=time.strftime('%Y-%m-%d %H:%M:%S %z'),pid=pid,fd_antes=before,fd_despues=after,pruebas=results)
Path('resultados_extra.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(sum(r['resultado']=='OK' for r in results),'/',len(results),'PRUEBAS ADICIONALES OK')
sys.exit(any(r['resultado']!='OK' for r in results))
