import platform,sys,os,subprocess
import pydantic,cryptography
print('Python:',sys.version.replace('\n',' ')); print('Platform:',platform.platform()); print('Machine:',platform.machine()); print('Pydantic:',pydantic.__version__); print('cryptography:',cryptography.__version__)
for cmd in [['lscpu'],['free','-h']]:
 try: print('\n$',*cmd); print(subprocess.check_output(cmd,text=True))
 except Exception as e: print('unavailable:',e)
