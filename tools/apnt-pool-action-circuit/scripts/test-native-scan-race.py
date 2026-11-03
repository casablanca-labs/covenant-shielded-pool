#!/usr/bin/python3
"""Bounded size/fetch growth stress via API doubles, never host process reads."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
READER = ROOT / 'tools/pool-action-modules/private-runner-process.c'


class TableRace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='other-provers-table-', dir='/private/tmp')
        cls.base = Path(cls.scratch.name)
        cls.original = READER.read_text()
        cls.binary = cls.build(cls.original, 'original')

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    @classmethod
    def build(cls, source, label):
        production = cls.base / (label + '-reader.c'); production.write_text(source)
        wrapper = cls.base / (label + '.c')
        wrapper.write_text(r'''
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <libproc.h>
static int race_sysctl(int *, unsigned, void *, size_t *, void *, size_t);
#define sysctl race_sysctl
#define main reader_main
#include ''' + json.dumps(str(production)) + r'''
#undef main
static int growth, malformed, denied, sizes, fetches, identities;
static int race_sysctl(int *mib,unsigned n,void *out,size_t *size,void *in,size_t insize) {
    (void)n;(void)in;(void)insize;
    if(mib[1]==KERN_ARGMAX){*(int *)out=4096;*size=sizeof(int);return 0;}
    if(mib[1]==KERN_PROC && mib[2]==KERN_PROC_ALL){
        if(!out){sizes++;if(denied){errno=EPERM;return -1;}
            *size=(size_t)(2+(sizes-1)*65)*sizeof(struct kinfo_proc);return 0;}
        fetches++;
        struct kinfo_proc *table=out;
        int rows=2+(sizes-1)*65;
        for(int i=0;i<rows;i++){memset(table+i,0,sizeof(*table));table[i].kp_proc.p_pid=499+i;
            table[i].kp_proc.p_stat=SRUN;table[i].kp_eproc.e_ucred.cr_uid=geteuid();}
        if(fetches<=growth){*size+=sizeof(*table);errno=ENOMEM;return -1;}
        *size=(size_t)rows*sizeof(*table)-(malformed?1:0);return 0;
    }
    if(mib[1]==KERN_PROCARGS2){
        identities++;int count=1;memcpy(out,&count,sizeof(count));
        const char args[]="/synthetic/worker\0\0worker\0SYNTHETIC_ENV_CANARY\0";
        memcpy((char *)out+sizeof(count),args,sizeof(args));*size=sizeof(count)+sizeof(args);return 0;
    }
    errno=EIO;return -1;
}
int main(int argc,char **argv){
    if(argc!=2)return 2;
    int retained=dup(STDOUT_FILENO);
    if(retained<0 || !freopen("/dev/null","w",stdout))return 3;
    int bad=0,recovered=0,exhausted=0,total_sizes=0,total_fetches=0,max_fetches=0,last=0;
    int stress=!strcmp(argv[1],"stress"),iterations=stress?1000:1;
    for(int i=0;i<iterations;i++){
        growth=stress?i%5:!strcmp(argv[1],"once")?1:!strcmp(argv[1],"three")?3:!strcmp(argv[1],"exhausted")?4:0;
        malformed=!strcmp(argv[1],"malformed");denied=!strcmp(argv[1],"denied");
        sizes=fetches=identities=0;errno=0;
        last=global_scan(0);
        int expected=growth>=4 || malformed || denied;
        int attempts=denied?0:growth>=4?4:growth+1;
        if(stress && (last!=expected || fetches!=attempts || sizes!=attempts))bad++;
        if(stress && identities!=(expected?0:2+growth*65))bad++;
        if(last)exhausted++;else recovered++;
        total_sizes+=sizes;total_fetches+=fetches;if(fetches>max_fetches)max_fetches=fetches;
    }
    if(fflush(stdout) || dup2(retained,STDOUT_FILENO)<0)return 4;close(retained);
    printf("{\"status\":%d,\"iterations\":%d,\"recovered\":%d,\"exhausted\":%d,\"unexpected\":%d,\"sizeCalls\":%d,\"fetchCalls\":%d,\"maxFetchCalls\":%d,\"identityCalls\":%d}\n",
        last,iterations,recovered,exhausted,bad,total_sizes,total_fetches,max_fetches,identities);
    return 0;
}
''')
        binary = cls.base / label
        command = ['/usr/bin/clang','-O2','-Wall','-Wextra','-Werror',str(wrapper),'-lproc','-o',str(binary)]
        result = subprocess.run(command,capture_output=True,timeout=60)
        if result.returncode: raise RuntimeError('table-control-build-refused')
        print('fresh-unit-build='+json.dumps({'label':'table-'+label,'sourceSha256':hashlib.sha256(wrapper.read_bytes()).hexdigest(),
                                            'productionSha256':hashlib.sha256(source.encode()).hexdigest(),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        return binary

    def observe(self, mode, binary=None):
        result = subprocess.run([str(binary or self.binary),mode],capture_output=True,timeout=30)
        self.assertEqual((result.returncode,len(result.stderr)),(0,0))
        value = json.loads(result.stdout)
        self.assertEqual(set(value),{'status','iterations','recovered','exhausted','unexpected','sizeCalls','fetchCalls','maxFetchCalls','identityCalls'})
        self.assertTrue(all(type(v) is int and v>=0 for v in value.values()))
        return value

    def test_recovery_on_first_and_last_allowed_retry(self):
        for mode,attempts,identities in (('once',2,67),('three',4,197)):
            value=self.observe(mode)
            self.assertEqual((value['status'],value['sizeCalls'],value['fetchCalls'],value['identityCalls']),
                             (0,attempts,attempts,identities))

    def test_exhaustion_and_malformed_or_denied_table_never_reach_identity(self):
        for mode,sizes,fetches in (('exhausted',4,4),('malformed',1,1),('denied',1,0)):
            value=self.observe(mode)
            self.assertEqual((value['status'],value['sizeCalls'],value['fetchCalls'],value['identityCalls']),
                             (1,sizes,fetches,0))

    def test_thousand_growth_sequences_are_bounded_and_complete(self):
        value=self.observe('stress')
        self.assertEqual((value['iterations'],value['recovered'],value['exhausted'],value['unexpected'],
                          value['sizeCalls'],value['fetchCalls'],value['maxFetchCalls']),
                         (1000,800,200,0,2800,2800,4))
        print('table-stress='+json.dumps(value,sort_keys=True))

    def test_retry_and_table_shape_mutations_fire_then_restore(self):
        mutations=[('attempt < 4','attempt < 1','once',0),
                   ('if (size && size < capacity && size % sizeof(*table) == 0) ready = 1;',
                    'if (1) ready = 1;','malformed',1)]
        for index,(before,after,mode,expected) in enumerate(mutations):
            self.assertEqual(self.original.count(before),1)
            binary=self.build(self.original.replace(before,after),'mutant-'+str(index))
            self.assertNotEqual(self.observe(mode,binary)['status'],expected)
            self.assertEqual(self.observe(mode)['status'],expected)


if __name__=='__main__':
    unittest.main()
