#!/usr/bin/env python3
"""Host-only refresh of a small attributed official DGEG offline snapshot.

Only public station-search GETs are issued. No car data, credentials, GPS or
USB device is read. Write to a new workspace directory to preserve old data.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import urllib.parse
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
ENDPOINT='https://precoscombustiveis.dgeg.gov.pt/api/PrecoComb/PesquisarPostos'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--district',type=int,default=11,help='DGEG district ID; default 11 is Lisboa district, not a GPS location')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve()
    if not (1<=a.district<=18 and out.is_relative_to(ROOT/'artifacts/phase20') and not out.exists()):
        p.error('Use district ID 1..18 and a new Phase20 workspace directory')
    out.mkdir(parents=True)
    for fuel,name,fetch in [(2101,'stations-response.json','fetch.json'),(3201,'petrol-response.json','petrol-fetch.json')]:
        query=urllib.parse.urlencode(dict(idsTiposComb=str(fuel),idMarca='',idTipoPosto='',idDistrito=str(a.district),
                                           idsMunicipios='',qtdPorPagina='5',pagina='1'))
        url=ENDPOINT+'?'+query
        request=urllib.request.Request(url,headers={'Accept':'application/json','User-Agent':'SMEG-offline-dashboard/1.0'})
        with urllib.request.urlopen(request,timeout=25)as response:
            if urllib.parse.urlparse(response.url).hostname!='precoscombustiveis.dgeg.gov.pt':
                raise ValueError('Unexpected API redirect host')
            raw=response.read(2*1024*1024+1)
        if len(raw)>2*1024*1024:raise ValueError('Unexpected API response size')
        d=json.loads(raw)
        if d.get('status')is not True or not isinstance(d.get('resultado'),list)or len(d['resultado'])!=5:
            raise ValueError('Official API did not return the requested five records')
        (out/name).write_bytes(raw)
        (out/fetch).write_text(json.dumps(dict(url=url,fetched_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            response_sha256=hashlib.sha256(raw).hexdigest(),district=a.district),indent=2)+'\n')
    print(json.dumps(dict(cache=str(out),source='DGEG',host_network_only=True)))

if __name__=='__main__':main()
