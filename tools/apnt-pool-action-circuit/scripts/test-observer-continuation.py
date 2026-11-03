#!/usr/bin/python3
"""Pinned-Node FD8 constructor, own synthetic subtree and real libproc only."""
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
import select
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
SCRIPTS=ROOT/'tools/apnt-pool-action-circuit/scripts'
OBSERVER=SCRIPTS/'mig01-macos-observer.c'
BOOTSTRAP=ROOT/'tools/pool-action-modules/private-runner-bootstrap.mjs'
NODE=str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.nvm/versions/node/v22.22.3/bin/node')


class ContinuationObserver(unittest.TestCase):
    def test_exact_node_constructor_has_observable_fd8_transport(self):
        self.assertEqual(subprocess.check_output([NODE,'--version']).strip(),b'v22.22.3')
        stdio=re.findall(r'stdio: (\["inherit"[^\n]+\])',BOOTSTRAP.read_text())
        self.assertEqual(len(stdio),1)
        with tempfile.TemporaryDirectory(prefix='other-provers-fd8-',dir='/private/tmp') as directory:
            base=Path(directory);probe=base/'probe.c';binary=base/'probe';node=base/'constructor.mjs';fixture=base/'source'
            fixture.write_text('synthetic observer source')
            probe.write_text('#define main observer_main\n#include '+json.dumps(str(OBSERVER))+r'''
#undef main
int main(int argc,char **argv){
    if(argc!=3 || stat(argv[2],&source) || stat("/dev/null",&null_device))return 2;
    pid_t pid=atoi(argv[1]);struct proc_bsdinfo identity;
    errno=0;int identity_bytes=proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&identity,sizeof(identity)),identity_error=errno;
    if(identity_bytes!=(int)sizeof(identity))return 3;
    struct proc_fdinfo fds[128];errno=0;int bytes=proc_pidinfo(pid,PROC_PIDLISTFDS,0,fds,sizeof(fds)),fd_error=errno;
    if(bytes<=0 || bytes>=(int)sizeof(fds) || bytes%(int)sizeof(fds[0]))return 4;
    unsigned present=0,nulls=0;const char *kind="absent";int fd8_identity=0;
    for(int i=0;i<bytes/(int)sizeof(fds[0]);i++){
        int fd=fds[i].proc_fd;if(fd>=3 && fd<=7){present|=1u<<(fd-3);if(is_null(pid,fd))nulls|=1u<<(fd-3);}
        if(fd==8){
            if(fds[i].proc_fdtype==PROX_FDTYPE_PIPE){struct pipe_fdinfo value;kind="pipe";fd8_identity=proc_pidfdinfo(pid,8,PROC_PIDFDPIPEINFO,&value,sizeof(value))==(int)sizeof(value);}
            else if(fds[i].proc_fdtype==PROX_FDTYPE_SOCKET){struct socket_fdinfo value;kind="socket";fd8_identity=proc_pidfdinfo(pid,8,PROC_PIDFDSOCKETINFO,&value,sizeof(value))==(int)sizeof(value);}
            else kind="other";
        }
    }
    inspect(pid,0);
    printf("{\"identityBytes\":%d,\"identityErrno\":%d,\"bashMatched\":%s,\"descriptorBytes\":%d,\"descriptorErrno\":%d,\"unusedPresentMask\":%u,\"unusedNullMask\":%u,\"fd8Type\":\"%s\",\"fd8IdentityRead\":%s,\"observedFd8\":%u,\"compared\":%u,\"different\":%u,\"sourceMatches\":%u,\"observerRefused\":%s}\n",
        identity_bytes,identity_error,!strcmp(identity.pbi_comm,"bash")?"true":"false",bytes,fd_error,present,nulls,kind,fd8_identity?"true":"false",pipes8+sockets8,identities8,different8,source_descriptors,refused?"true":"false");
    return 0;
}
''')
            built=subprocess.run(['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(probe),'-lproc','-o',str(binary)],capture_output=True,timeout=30)
            self.assertEqual((built.returncode,len(built.stdout),len(built.stderr)),(0,0,0))
            node.write_text("import {spawn} from 'node:child_process';\n"
                "const child=spawn('/bin/bash',['-c','IFS= read -r value <&8'],{stdio:"+stdio[0]+"});\n"
                "child.once('spawn',()=>process.stdout.write(JSON.stringify({pid:child.pid})+'\\n'));\n"
                "process.stdin.once('data',()=>{child.stdio[8].end('synthetic snapshot\\n');process.stdin.pause()});\n"
                "child.once('close',code=>{process.exitCode=code===0?0:1;process.stdin.destroy()});\n"
                "process.on('SIGTERM',()=>child.kill('SIGTERM'));\n")
            parent=subprocess.Popen([NODE,str(node)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                self.assertTrue(select.select([parent.stdout],[],[],5)[0]);identity=json.loads(parent.stdout.readline())
                actual=subprocess.run([str(binary),str(identity['pid']),str(fixture)],capture_output=True,timeout=5)
                self.assertEqual((actual.returncode,len(actual.stderr)),(0,0))
                value=json.loads(actual.stdout)
                print('node-continuation='+json.dumps({'sourceSha256':hashlib.sha256(OBSERVER.read_bytes()).hexdigest(),
                    'probeSha256':hashlib.sha256(probe.read_bytes()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'constructorSha256':hashlib.sha256(BOOTSTRAP.read_bytes()).hexdigest(),'observation':value}))
                self.assertTrue(value['bashMatched'] and value['fd8IdentityRead'])
                self.assertIn(value['fd8Type'],('pipe','socket'))
                self.assertGreater(value['observedFd8'],0)
                self.assertEqual((value['compared'],value['different'],value['sourceMatches'],value['observerRefused']),(1,1,0,False))
            finally:
                stdout,stderr=parent.communicate(b'stop',timeout=5)
                self.assertEqual((parent.returncode,len(stdout),len(stderr)),(0,0,0))


if __name__=='__main__':unittest.main()
