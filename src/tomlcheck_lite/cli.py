from __future__ import annotations
import argparse, base64, collections, csv, datetime, hashlib, json, os, re, sys, time, unicodedata
from pathlib import Path

def run(args):
 k='tomlcheck'; p=Path(args.path) if hasattr(args,'path') else None
 if k=='bytes':
  b=p.read_bytes(); print(f"bytes: {len(b)}\nlines: {b.count(bytes([10]))}\nwords: {len(b.split())}")
 elif k=='dedupe':
  seen=set(); out=[]
  for s in sys.stdin: 
   if s not in seen: seen.add(s); out.append(s)
  sys.stdout.writelines(out)
 elif k in ('head','tail'):
  lines=p.read_text().splitlines(True); n=args.count; sys.stdout.writelines(lines[:n] if k=='head' else lines[-n:])
 elif k=='jsonpretty': print(json.dumps(json.loads(p.read_text()),indent=2,sort_keys=args.sort))
 elif k=='csvpeek':
  with p.open(newline='') as f:
   rows=csv.reader(f); print(json.dumps({'header':next(rows,[]),'sample':list(__import__('itertools').islice(rows,args.rows))},ensure_ascii=False))
 elif k=='filehash':
  h=hashlib.new(args.algorithm)
  with p.open('rb') as f:
   for b in iter(lambda:f.read(131072),b''): h.update(b)
  print(h.hexdigest())
 elif k=='tree':
  base=p; print(base)
  for x in sorted(base.rglob('*')): print('  '*len(x.relative_to(base).parts)+x.name+('/' if x.is_dir() else ''))
 elif k=='emptydirs':
  found=sorted((x for x in p.rglob('*') if x.is_dir() and not any(x.iterdir())),key=lambda x:len(x.parts),reverse=True)
  for x in found: print(x)
  if args.delete:
   for x in found: x.rmdir()
 elif k=='extcount':
  c=collections.Counter(x.suffix.lower() or '[no extension]' for x in p.rglob('*') if x.is_file())
  for ext,n in sorted(c.items()): print(f'{ext} {n}')
 elif k=='newlinefix':
  text=p.read_text(); p.write_text(text.replace('\r\n','\n').replace('\r','\n'))
 elif k=='tabexpand': sys.stdout.write((p.read_text() if p else sys.stdin.read()).expandtabs(args.width))
 elif k=='slugify':
  s=args.text or sys.stdin.read(); s=unicodedata.normalize('NFKD',s).encode('ascii','ignore').decode().lower(); print(re.sub(r'[^a-z0-9]+','-',s).strip('-'))
 elif k=='wordfreq':
  text=p.read_text() if p else sys.stdin.read(); c=collections.Counter(re.findall(r"[\w']+",text.casefold()))
  for w,n in c.most_common(args.limit): print(f'{w} {n}')
 elif k=='urlencode':
  from urllib.parse import quote,unquote
  s=args.text or sys.stdin.read(); print(unquote(s) if args.decode else quote(s,safe=''))
 elif k=='base64file':
  b=p.read_bytes()
  if args.decode: sys.stdout.buffer.write(base64.b64decode(b,validate=True))
  else: sys.stdout.buffer.write(base64.b64encode(b)+b'\n')
 elif k=='rot13': sys.stdout.write((args.text or sys.stdin.read()).translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')))
 elif k=='jsonkeys':
  def walk(v,prefix=''):
   if isinstance(v,dict):
    for key,val in v.items(): yield from walk(val,f'{prefix}.{key}' if prefix else str(key))
   elif isinstance(v,list):
    for i,val in enumerate(v): yield from walk(val,f'{prefix}[{i}]')
   else: yield prefix
  print('\n'.join(walk(json.loads(p.read_text()))))
 elif k=='csvtojson':
  with p.open(newline='') as f: print(json.dumps(list(csv.DictReader(f)),indent=2))
 elif k=='jsonlcheck':
  bad=0
  for i,line in enumerate(p.read_text().splitlines(),1):
   if not line.strip(): continue
   try: json.loads(line)
   except json.JSONDecodeError as e: print(f'{i}: {e.msg}'); bad+=1
  return 1 if bad else 0
 elif k=='yamlpeek':
  try: import yaml
  except ImportError: raise SystemExit('Install PyYAML to use YAML parsing')
  print(json.dumps(yaml.safe_load(p.read_text()),indent=2,default=str))
 elif k=='envdiff':
  def load(x): return dict(line.split('=',1) for line in x.read_text().splitlines() if '=' in line and not line.lstrip().startswith('#'))
  a,b=map(load,(p,Path(args.other)))
  for key in sorted(a.keys()|b.keys()):
   if a.get(key)!=b.get(key): print(f'{key}: {a.get(key,"<missing>")} -> {b.get(key,"<missing>")}')
 elif k=='pathcheck':
  for s in args.paths:
   q=Path(s); print(f'{q}: exists={q.exists()} file={q.is_file()} dir={q.is_dir()} size={q.stat().st_size if q.is_file() else "-"}')
 elif k=='dupscan':
  hashes=collections.defaultdict(list)
  for f in p.rglob('*'):
   if f.is_file(): hashes[hashlib.sha256(f.read_bytes()).hexdigest()].append(str(f))
  for paths in hashes.values():
   if len(paths)>1: print('\n'.join(paths)+'\n')
 elif k=='mdtoc':
  for line in p.read_text().splitlines():
   m=re.match(r'^(#{1,6})\s+(.+?)\s*#*$',line)
   if m:
    title=m.group(2); anchor=re.sub(r'[^\w-]','',re.sub(r'\s+','-',title.lower())); print('  '* (len(m.group(1))-1)+f'- [{title}](#{anchor})')
 elif k=='stripansi': print(re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',(p.read_text() if p else sys.stdin.read())),end='')
 elif k=='logslice':
  for i,line in enumerate(p.read_text().splitlines(),1):
   if args.start<=i<=args.end: print(line)
 elif k=='regexfind':
  rx=re.compile(args.pattern); paths=[p] if p.is_file() else p.rglob('*')
  for f in paths:
   if f.is_file():
    for i,line in enumerate(f.read_text(errors='replace').splitlines(),1):
     if rx.search(line): print(f'{f}:{i}:{line}')
 elif k=='datefmt': print(datetime.datetime.fromisoformat(args.date.replace('Z','+00:00')).strftime(args.format))
 elif k=='tomlcheck':
  import tomllib; data=tomllib.loads(p.read_text()); print('valid TOML'); return 0
 elif k=='xmlpretty':
  import xml.dom.minidom as dom; print(dom.parse(str(p)).toprettyxml())
 elif k=='fileage': print(max(0,int(time.time()-p.stat().st_mtime)))
 elif k=='secretscan':
  text=p.read_text(errors='replace'); patterns={'AWS access key':r'AKIA[0-9A-Z]{16}','private key':r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----','token-like assignment':r'(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*[\"\']?[A-Za-z0-9_./+-]{12,}'}
  hits=[(label,m.start()) for label,rx in patterns.items() for m in re.finditer(rx,text)]
  for label,pos in hits: print(f'{label} at offset {pos}')
  return 1 if hits else 0
 return 0

def main():
 ap=argparse.ArgumentParser(description='Validate TOML configuration files.')
 if 'tomlcheck' in ('dedupe','rot13','stripansi'): pass
 elif 'tomlcheck' in ('tabexpand','wordfreq','urlencode'): ap.add_argument('path',nargs='?');
 elif 'tomlcheck'=='slugify': ap.add_argument('text',nargs='?')
 elif 'tomlcheck'=='pathcheck': ap.add_argument('paths',nargs='+')
 elif 'tomlcheck'=='datefmt': ap.add_argument('date'); ap.add_argument('-f','--format',default='%Y-%m-%d %H:%M:%S %z')
 else: ap.add_argument('path')
 if 'tomlcheck' in ('head','tail'): ap.add_argument('-n','--count',type=int,default=10)
 if 'tomlcheck'=='jsonpretty': ap.add_argument('--sort',action='store_true')
 if 'tomlcheck'=='csvpeek': ap.add_argument('-n','--rows',type=int,default=5)
 if 'tomlcheck'=='filehash': ap.add_argument('-a','--algorithm',default='sha256',choices=hashlib.algorithms_available)
 if 'tomlcheck'=='emptydirs': ap.add_argument('--delete',action='store_true')
 if 'tomlcheck'=='tabexpand': ap.add_argument('-w','--width',type=int,default=8)
 if 'tomlcheck'=='wordfreq': ap.add_argument('-n','--limit',type=int,default=20)
 if 'tomlcheck'=='urlencode': ap.add_argument('--decode',action='store_true'); ap.add_argument('text',nargs='?')
 if 'tomlcheck'=='base64file': ap.add_argument('--decode',action='store_true')
 if 'tomlcheck'=='slugify': ap.add_argument('text',nargs='?')
 if 'tomlcheck'=='envdiff': ap.add_argument('other')
 if 'tomlcheck'=='logslice': ap.add_argument('start',type=int); ap.add_argument('end',type=int)
 if 'tomlcheck'=='regexfind': ap.add_argument('pattern')
 result=run(ap.parse_args()); return result or 0
if __name__=='__main__': raise SystemExit(main())
