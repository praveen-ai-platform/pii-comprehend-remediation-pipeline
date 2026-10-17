"""Build Linux x86_64 dependencies even when packaging from Windows."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root=Path(__file__).resolve().parents[1]
(root/'dist').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as staging:
    subprocess.run([sys.executable,'-m','pip','install','-r',str(root/'requirements.lock'),
        '--target',staging,'--platform','manylinux2014_x86_64','--implementation','cp',
        '--python-version','3.13','--abi','cp313','--only-binary=:all:','--no-compile'],check=True)
    shutil.copytree(root/'src',Path(staging)/'src',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    shutil.make_archive(str(root/'dist'/'lambda'),'zip',staging)
print('Built dist/lambda.zip for Lambda Python 3.13 x86_64')
