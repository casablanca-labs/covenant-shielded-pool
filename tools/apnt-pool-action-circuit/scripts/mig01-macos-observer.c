/* TEST ONLY: bounded metadata observer for this driver's child subtree.
 * Never reads argv, paths from process info, file contents or another wallet.
 * stdout is a closed count record. Requires an ordinary unsandboxed terminal.
 */
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

static struct stat source, request_source, null_device;
static unsigned pipes8, sockets8, source_descriptors, null_bridges, inherited_lock_bridges, refused;
static unsigned identities8, different8, matching8;
static unsigned samples, processes;
static int has_request, canary_mode;
/* R-2442: the ordinary stock runner used 4,074 cumulative distinct PIDs.
 * Closed provenance: ENG-1671-R2442-EVIDENCE-20261019/
 * mig01-baseline-provenance.json (added in R-2450).
 * Keep bounded
 * bookkeeping with >4x that measured normal capacity, rather than exhausting
 * it during a valid observation. A full set still refuses, never truncates. */
#define OBSERVED_PID_CAPACITY 16384
static pid_t seen8[OBSERVED_PID_CAPACITY], seen_bridge[OBSERVED_PID_CAPACITY];
static pid_t seen_process[OBSERVED_PID_CAPACITY];
static unsigned n8, nb;
static unsigned np;
static const char *refusal_reason;
static int refusal_errno;
static void refuse(const char *reason, int error) {
  if(!refused) {refusal_reason=reason;refusal_errno=error;}
  refused=1;
}
static void refusal_diagnostic(void) {
  if(refused) fprintf(stderr,"{\"reason\":\"%s\",\"errno\":%d}\n",refusal_reason,refusal_errno);
}
static int seen(pid_t *array, unsigned *count, pid_t pid) {
  for (unsigned i=0;i<*count;i++) if(array[i]==pid) return 1;
  if(*count>=OBSERVED_PID_CAPACITY) {refuse("process-capacity",0);return 1;} array[(*count)++]=pid;return 0;
}
static int vnode(pid_t pid, int fd, struct vnode_fdinfo *value) {
  return proc_pidfdinfo(pid,fd,PROC_PIDFDVNODEINFO,value,sizeof(*value))==(int)sizeof(*value);
}
static int is_null(pid_t pid, int fd) {
  struct vnode_fdinfo value;
  return vnode(pid,fd,&value) && value.pvi.vi_stat.vst_dev==(uint32_t)null_device.st_dev
    && value.pvi.vi_stat.vst_ino==(uint64_t)null_device.st_ino;
}
static void inspect(pid_t pid, unsigned depth) {
  if(depth>8) {refuse("depth",0);return;}
  struct proc_bsdinfo identity;
  if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&identity,sizeof(identity))!=(int)sizeof(identity)) return;
  if(identity.pbi_uid!=getuid()) {refuse("uid",0);return;}
  if(!seen(seen_process,&np,pid)) processes++;
  struct proc_fdinfo descriptors[1024];
  int bytes=proc_pidinfo(pid,PROC_PIDLISTFDS,0,descriptors,sizeof(descriptors));
  if(bytes<0 || bytes>=(int)sizeof(descriptors) || bytes%(int)sizeof(descriptors[0])!=0) {refuse("descriptor-list",bytes<0?errno:0);return;}
  int fd3transport=0;
  /* Node's ignore entries above stdio close 3..7 in the Bash continuation.
   * Require their absence in the successful descriptor enumeration; a failed
   * vnode query is not evidence of closure. Node's own FD8 is no oracle. */
  int unused_closed=1;
  for(int i=0;i<bytes/(int)sizeof(descriptors[0]);i++)
    if(descriptors[i].proc_fd>=3 && descriptors[i].proc_fd<=7) unused_closed=0;
  int snapshot_consumer=(!strcmp(identity.pbi_comm,"bash") && unused_closed) || (canary_mode && pid==getpid());
  for(int i=0;i<bytes/(int)sizeof(descriptors[0]);i++) {
    int fd=descriptors[i].proc_fd; uint32_t type=descriptors[i].proc_fdtype;
    if(type==PROX_FDTYPE_VNODE) {
      struct vnode_fdinfo value;
      if(vnode(pid,fd,&value) && value.pvi.vi_stat.vst_dev==(uint32_t)source.st_dev
        && value.pvi.vi_stat.vst_ino==(uint64_t)source.st_ino) source_descriptors++;
      if(has_request && vnode(pid,fd,&value) && value.pvi.vi_stat.vst_dev==(uint32_t)request_source.st_dev
        && value.pvi.vi_stat.vst_ino==(uint64_t)request_source.st_ino) source_descriptors++;
    }
    if(fd==3 && (type==PROX_FDTYPE_PIPE || type==PROX_FDTYPE_SOCKET)) fd3transport=1;
    if(fd==8 && snapshot_consumer && (type==PROX_FDTYPE_PIPE || type==PROX_FDTYPE_SOCKET) && !seen(seen8,&n8,pid)) {
      struct vinfo_stat transport; int obtained=0;
      if(type==PROX_FDTYPE_PIPE) {
        struct pipe_fdinfo value;
        if(proc_pidfdinfo(pid,8,PROC_PIDFDPIPEINFO,&value,sizeof(value))==(int)sizeof(value)) {transport=value.pipeinfo.pipe_stat;obtained=1;}
        pipes8++;
      } else {
        struct socket_fdinfo value;
        if(proc_pidfdinfo(pid,8,PROC_PIDFDSOCKETINFO,&value,sizeof(value))==(int)sizeof(value)) {transport=value.psi.soi_stat;obtained=1;}
        sockets8++;
      }
      if(obtained) {
        identities8++;
        int matches=S_ISREG(transport.vst_mode) && ((transport.vst_dev==(uint32_t)source.st_dev && transport.vst_ino==(uint64_t)source.st_ino)
          || (has_request && transport.vst_dev==(uint32_t)request_source.st_dev && transport.vst_ino==(uint64_t)request_source.st_ino));
        if(matches) matching8++; else different8++;
      }
    }
  }
  if(!strcmp(identity.pbi_comm,"node") && fd3transport && is_null(pid,0) && is_null(pid,1)
    && !seen(seen_bridge,&nb,pid)) {
    if(is_null(pid,2)) null_bridges++;
    char lockpath[128];struct stat lock;struct vnode_fdinfo value;
    snprintf(lockpath,sizeof(lockpath),"/private/tmp/apnt-gnark-r2-proof-%u.lock",(unsigned)getuid());
    if(stat(lockpath,&lock)==0 && vnode(pid,9,&value) && value.pvi.vi_stat.vst_dev==(uint32_t)lock.st_dev
      && value.pvi.vi_stat.vst_ino==(uint64_t)lock.st_ino) inherited_lock_bridges++;
  }
  /* Unlike PROC_PIDLISTFDS, proc_listchildpids returns a PID count. A full
   * array cannot establish that the subtree is complete, so still refuse. */
  pid_t children[256]; int childcount=proc_listchildpids(pid,children,sizeof(children));
  if(childcount<0 || childcount>=(int)(sizeof(children)/sizeof(children[0]))) {refuse("child-list",childcount<0?errno:0);return;}
  for(int i=0;i<childcount;i++) if(children[i]>1) inspect(children[i],depth+1);
}
int main(int argc,char **argv) {
  if((argc!=3 && argc!=4) || stat(argv[2],&source)!=0 || !S_ISREG(source.st_mode) || stat("/dev/null",&null_device)!=0) return 2;
  if(argc==4) {if(stat(argv[3],&request_source)!=0 || !S_ISREG(request_source.st_mode)) return 2;has_request=1;}
  if(!strcmp(argv[1],"--canary")) {
    int original=open(argv[2],O_RDONLY|O_NOFOLLOW), pair[2];struct stat opened,transport;
    if(original<0 || socketpair(AF_UNIX,SOCK_STREAM,0,pair)!=0 || fstat(original,&opened)!=0 || fstat(pair[0],&transport)!=0) return 2;
    int matches=opened.st_dev==source.st_dev && opened.st_ino==source.st_ino;
    int different=transport.st_dev!=source.st_dev || transport.st_ino!=source.st_ino || !S_ISREG(transport.st_mode);
    if(dup2(pair[0],8)<0) return 2;
    canary_mode=1;inspect(getpid(),0);
    int source_fires=matches && source_descriptors>0 && !refused;
    int transport_differs=different && identities8>0 && different8==identities8 && matching8==0 && !refused;
    close(original);if(pair[0]!=8)close(pair[0]);if(pair[1]!=8)close(pair[1]);close(8);
    refusal_diagnostic();
    printf("{\"sourceFstatDetectorFires\":%s,\"transportFstatDiffers\":%s}\n",source_fires?"true":"false",transport_differs?"true":"false");return source_fires&&transport_differs?0:1;
  }
  char *end=NULL;long input=strtol(argv[1],&end,10);if(!end || *end || input<=1 || input>INT32_MAX) return 2;
  pid_t root=(pid_t)input;fcntl(STDIN_FILENO,F_SETFL,O_NONBLOCK);
  struct timespec start,now;clock_gettime(CLOCK_MONOTONIC,&start);
  for(;;) {
    char stop;if(read(STDIN_FILENO,&stop,1)>0) break;
    samples++;inspect(root,0);clock_gettime(CLOCK_MONOTONIC,&now);if(now.tv_sec-start.tv_sec>180) {refuse("timeout",0);break;}
    usleep(500);
  }
  refusal_diagnostic();
  printf("{\"samples\":%u,\"observedProcesses\":%u,\"fd8PipeProcesses\":%u,\"fd8SocketProcesses\":%u,\"fd8IdentitiesCompared\":%u,\"fd8IdentitiesDifferent\":%u,\"fd8SourceIdentityMatches\":%u,\"sourceDescriptorMatches\":%u,\"nullStdioPrivateBridgeProcesses\":%u,\"inheritedProverLockBridges\":%u,\"observerRefused\":%s}\n",
    samples,processes,pipes8,sockets8,identities8,different8,matching8,source_descriptors,null_bridges,inherited_lock_bridges,refused?"true":"false");return refused?77:0;
}
