import subprocess,sys
from pathlib import Path
def test_help():
 env={**__import__("os").environ,"PYTHONPATH":str(Path(__file__).parents[1]/"src")}
 r=subprocess.run([sys.executable,"-m","tomlcheck_lite","--help"],capture_output=True,text=True,env=env)
 assert r.returncode==0, r.stderr
