// DYLD_INSERT_LIBRARIES hook for HardwareManager
// Intercepts ALL mbedtls cipher functions + socket I/O
// to identify which cipher encrypts DMX frames.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <mach/exception_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#include <mach/i386/thread_status.h>

#define DYLD_INTERPOSE(_replacement, _replacee) \
  __attribute__((used)) static struct { \
    const void* replacement; \
    const void* replacee; \
  } _interpose_##_replacee \
  __attribute__((section("__DATA,__interpose"))) = { \
    (const void*)(unsigned long)&_replacement, \
    (const void*)(unsigned long)&_replacee \
  };

static FILE *logf = NULL;
static int msg_count = 0;

static void hex_dump(FILE *f, const unsigned char *data, size_t len) {
  for (size_t i = 0; i < len; i += 16) {
    fprintf(f, "  %04zx  ", i);
    for (size_t j = 0; j < 16; j++) {
      if (i + j < len) fprintf(f, "%02x ", data[i + j]);
      else fprintf(f, "   ");
    }
    fprintf(f, " ");
    for (size_t j = 0; j < 16 && i + j < len; j++) {
      unsigned char c = data[i + j];
      fprintf(f, "%c", (c >= 32 && c < 127) ? c : '.');
    }
    fprintf(f, "\n");
  }
}

// =====================================================================
// Inline hook of the AES-128 key+IV setup function (Pro2 0x10040b3c0)
// At entry: rsi = ptr to raw 16-byte AES-128 key, rdx = ptr to 16-byte IV,
//           rdi = crypto context. We dump key+IV, then one-shot unpatch
//           and re-enter the function cleanly.
// =====================================================================

#define SETUP_FN_FILEVMADDR 0x10040b3c0ULL

// Expected first 14 bytes of the function prologue (verified before patching
// so we never corrupt an unrelated process e.g. the Qt-less CEF helper):
//  55              push %rbp
//  48 89 e5        mov  %rsp,%rbp
//  41 56           push %r14
//  53              push %rbx
//  49 89 d6        mov  %rdx,%r14
//  48 89 fb        mov  %rdi,%rbx
//  e8 ..           call 0x10040b2c0
static const unsigned char SETUP_FN_EXPECT[14] = {
  0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x49,0x89,0xd6,0x48,0x89,0xfb,0xe8
};

void *g_target = NULL;                  // runtime addr of setup fn (used by asm)
static unsigned char g_orig[16];        // saved original prologue bytes
static int g_fired = 0;

extern void hook_stub(void);            // asm trampoline (below)

// Naked trampoline: entered via JMP from the patched prologue, so the
// register state is exactly the function's entry state. Save everything,
// call the C capture+unpatch routine, restore, then jump to the (now
// un-patched) original entry so the function runs normally.
__asm__(
".text\n"
".globl _hook_stub\n"
"_hook_stub:\n"
"  pushq %rax\n  pushq %rcx\n  pushq %rdx\n  pushq %rbx\n  pushq %rbp\n"
"  pushq %rsi\n  pushq %rdi\n  pushq %r8\n  pushq %r9\n  pushq %r10\n"
"  pushq %r11\n pushq %r12\n  pushq %r13\n  pushq %r14\n  pushq %r15\n"
"  movq %rsi, %rdi\n"   /* arg1 = original rsi = key ptr  */
"  movq %rdx, %rsi\n"   /* arg2 = original rdx = iv ptr   */
"  call _capture_and_unpatch\n"
"  popq %r15\n  popq %r14\n  popq %r13\n  popq %r12\n  popq %r11\n"
"  popq %r10\n  popq %r9\n  popq %r8\n  popq %rdi\n  popq %rsi\n"
"  popq %rbp\n  popq %rbx\n  popq %rdx\n  popq %rcx\n  popq %rax\n"
"  jmpq *_g_target(%rip)\n"
);

// Make a code page writable on macOS. Plain mprotect() is denied on __TEXT
// (especially under Rosetta), so use mach_vm_protect with VM_PROT_COPY which
// forces a private copy-on-write page we are allowed to modify.
// Try plain RW first (no VM_PROT_COPY): we MUST modify the original
// file-backed page, because Rosetta's x86->arm64 translator reads that
// mapping. VM_PROT_COPY makes a private page Rosetta never sees, so the
// patch would silently have no effect. COPY is only a last resort.
static int make_writable(uint64_t addr, size_t len) {
  uintptr_t pg = addr & ~0xFFFULL;
  mach_vm_size_t span = ((addr + len) - pg + 0xFFF) & ~0xFFFULL;
  kern_return_t kr = mach_vm_protect(mach_task_self(), pg, span, FALSE,
      VM_PROT_READ | VM_PROT_WRITE);
  if (kr == KERN_SUCCESS) {
    fprintf(stderr, "[HOOK] make_writable: RW (no-copy) OK\n");
    return 0;
  }
  fprintf(stderr, "[HOOK] make_writable: RW failed kr=%d, trying COPY "
          "(note: COPY won't be seen by Rosetta translator)\n", kr);
  kr = mach_vm_protect(mach_task_self(), pg, span, FALSE,
      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  return kr == KERN_SUCCESS ? 0 : (int)kr;
}

static int make_exec(uint64_t addr, size_t len) {
  uintptr_t pg = addr & ~0xFFFULL;
  mach_vm_size_t span = ((addr + len) - pg + 0xFFF) & ~0xFFFULL;
  kern_return_t kr = mach_vm_protect(mach_task_self(), pg, span, FALSE,
      VM_PROT_READ | VM_PROT_EXECUTE);
  return kr == KERN_SUCCESS ? 0 : (int)kr;
}

void capture_and_unpatch(const unsigned char *key, const unsigned char *iv) {
  if (g_fired) return;
  g_fired = 1;

  fprintf(stderr, "\n[HOOK] ====================================\n");
  fprintf(stderr, "[HOOK] *** AES-128 KEY+IV CAPTURED (setup fn) ***\n");
  fprintf(stderr, "[HOOK] KEY (16 bytes):\n");
  hex_dump(stderr, key, 16);
  fprintf(stderr, "[HOOK] IV (16 bytes):\n");
  hex_dump(stderr, iv, 16);
  fprintf(stderr, "[HOOK] ====================================\n");
  if (logf) {
    fprintf(logf, "\n[KEY] *** AES-128 KEY+IV CAPTURED via inline hook ***\n");
    fprintf(logf, "[KEY] KEY(16):\n");
    hex_dump(logf, key, 16);
    fprintf(logf, "[KEY] IV(16):\n");
    hex_dump(logf, iv, 16);
  }

  // One-shot: restore original bytes so the function runs normally forever.
  uint64_t t = (uint64_t)g_target;
  make_writable(t, 16);
  memcpy((void *)t, g_orig, 16);
  sys_icache_invalidate((void *)t, 16);
  make_exec(t, 16);
}

static void install_setup_hook(void) {
  intptr_t slide = _dyld_get_image_vmaddr_slide(0);
  uint64_t t = SETUP_FN_FILEVMADDR + (uint64_t)slide;
  unsigned char *p = (unsigned char *)t;

  // Verify the target is mapped and matches the expected prologue.
  // mach_vm_read_overwrite avoids crashing if the page is unmapped
  // (e.g. in the CEF helper process which lacks this code).
  unsigned char probe[16];
  mach_vm_size_t got = 16;
  if (mach_vm_read_overwrite(mach_task_self(), t, 16,
                             (mach_vm_address_t)probe, &got) != KERN_SUCCESS
      || got < 14) {
    fprintf(stderr, "[HOOK] setup-hook: target 0x%llx not readable, skip\n",
            (unsigned long long)t);
    return;
  }
  if (memcmp(probe, SETUP_FN_EXPECT, 14) != 0) {
    fprintf(stderr, "[HOOK] setup-hook: prologue mismatch at 0x%llx, skip "
            "(got %02x %02x %02x %02x ...)\n", (unsigned long long)t,
            probe[0], probe[1], probe[2], probe[3]);
    return;
  }

  g_target = (void *)t;
  memcpy(g_orig, p, 16);

  // 14-byte absolute jump: FF 25 00 00 00 00 | <8-byte abs addr of stub>
  unsigned char patch[14];
  patch[0] = 0xFF; patch[1] = 0x25;
  patch[2] = patch[3] = patch[4] = patch[5] = 0x00;
  uint64_t h = (uint64_t)&hook_stub;
  memcpy(patch + 6, &h, 8);

  int wr = make_writable(t, 16);
  if (wr != 0) {
    fprintf(stderr, "[HOOK] setup-hook: make_writable failed kr=%d, skip\n", wr);
    return;
  }
  memcpy(p, patch, 14);
  sys_icache_invalidate(p, 14);
  make_exec(t, 16);

  // Read back to confirm the patch actually landed in the mapping.
  fprintf(stderr, "[HOOK] readback after patch: "
          "%02x %02x %02x %02x %02x %02x %02x %02x\n",
          p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

  fprintf(stderr, "[HOOK] *** SETUP HOOK INSTALLED at 0x%llx "
          "(stub=%p, slide=0x%lx) ***\n",
          (unsigned long long)t, (void *)&hook_stub, (long)slide);
  if (logf)
    fprintf(logf, "[HOOK] setup hook installed at 0x%llx\n",
            (unsigned long long)t);
}

// =====================================================================
// Mach exception-port + hardware breakpoint on the AES-128 setup fn.
// No __TEXT write (Rosetta/ad-hoc-sign safe). On the breakpoint we read
// the x86 thread state: rsi=raw key ptr, rdx=IV ptr, rdi=ctx.
// =====================================================================

static uint64_t g_bp_addr = 0;       // runtime addr of 0x10040b3c0
static mach_port_t g_exc_port = MACH_PORT_NULL;
static volatile int g_bp_fired = 0;

// EXCEPTION_DEFAULT + MACH_EXCEPTION_CODES message structs (hand-rolled,
// avoids needing MIG-generated mach_exc_server).
#pragma pack(4)
typedef struct {
  mach_msg_header_t Head;
  mach_msg_body_t msgh_body;
  mach_msg_port_descriptor_t thread;
  mach_msg_port_descriptor_t task;
  NDR_record_t NDR;
  exception_type_t exception;
  mach_msg_type_number_t codeCnt;
  int64_t code[2];
  char trailer[64];
} exc_request_t;
typedef struct {
  mach_msg_header_t Head;
  NDR_record_t NDR;
  kern_return_t RetCode;
} exc_reply_t;
#pragma pack()

static void set_dr_all_threads(uint64_t bp) {
  thread_act_array_t threads;
  mach_msg_type_number_t count = 0;
  if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS)
    return;
  mach_port_t me = mach_thread_self();
  for (unsigned i = 0; i < count; i++) {
    if (threads[i] == me) continue;
    x86_debug_state64_t ds;
    mach_msg_type_number_t dc = x86_DEBUG_STATE64_COUNT;
    if (thread_get_state(threads[i], x86_DEBUG_STATE64,
                         (thread_state_t)&ds, &dc) != KERN_SUCCESS)
      continue;
    ds.__dr0 = bp;
    // DR7: L0=1 (bit0). R/W0=00 (exec), LEN0=00  -> low byte 0x01.
    ds.__dr7 = (ds.__dr7 & ~0xFULL) | 0x1ULL;
    thread_set_state(threads[i], x86_DEBUG_STATE64,
                     (thread_state_t)&ds, x86_DEBUG_STATE64_COUNT);
  }
  mach_port_deallocate(mach_task_self(), me);
  vm_deallocate(mach_task_self(), (vm_address_t)threads,
                count * sizeof(thread_act_t));
}

static void clear_dr_thread(mach_port_t th) {
  x86_debug_state64_t ds;
  mach_msg_type_number_t dc = x86_DEBUG_STATE64_COUNT;
  if (thread_get_state(th, x86_DEBUG_STATE64,
                       (thread_state_t)&ds, &dc) != KERN_SUCCESS)
    return;
  ds.__dr0 = 0;
  ds.__dr7 &= ~0xFULL;
  thread_set_state(th, x86_DEBUG_STATE64,
                   (thread_state_t)&ds, x86_DEBUG_STATE64_COUNT);
}

static void capture_from_thread(mach_port_t th) {
  if (g_bp_fired) return;

  x86_thread_state64_t ts;
  mach_msg_type_number_t tc = x86_THREAD_STATE64_COUNT;
  if (thread_get_state(th, x86_THREAD_STATE64,
                       (thread_state_t)&ts, &tc) != KERN_SUCCESS) {
    fprintf(stderr, "[HOOK] bp: thread_get_state failed\n");
    return;
  }

  uint64_t rip = ts.__rip, rsi = ts.__rsi, rdx = ts.__rdx, rdi = ts.__rdi;
  fprintf(stderr, "\n[HOOK] *** BREAKPOINT HIT  rip=0x%llx ***\n",
          (unsigned long long)rip);
  fprintf(stderr, "[HOOK] rsi(key)=0x%llx rdx(iv)=0x%llx rdi(ctx)=0x%llx\n",
          (unsigned long long)rsi, (unsigned long long)rdx,
          (unsigned long long)rdi);

  unsigned char key[16], iv[16];
  mach_vm_size_t n = 16;
  int ok_k = (rsi && mach_vm_read_overwrite(mach_task_self(), rsi, 16,
                  (mach_vm_address_t)key, &n) == KERN_SUCCESS);
  n = 16;
  int ok_i = (rdx && mach_vm_read_overwrite(mach_task_self(), rdx, 16,
                  (mach_vm_address_t)iv, &n) == KERN_SUCCESS);

  if (ok_k) {
    fprintf(stderr, "[HOOK] *** AES-128 KEY (16) ***\n");
    hex_dump(stderr, key, 16);
  }
  if (ok_i) {
    fprintf(stderr, "[HOOK] *** IV (16) ***\n");
    hex_dump(stderr, iv, 16);
  }
  if (logf) {
    fprintf(logf, "\n[KEY] *** CAPTURED via HW breakpoint  rip=0x%llx ***\n",
            (unsigned long long)rip);
    if (ok_k) { fprintf(logf, "[KEY] KEY(16):\n"); hex_dump(logf, key, 16); }
    if (ok_i) { fprintf(logf, "[KEY] IV(16):\n");  hex_dump(logf, iv, 16); }
    // Also dump the crypto context (rdi) for offset analysis.
    if (rdi) {
      unsigned char ctx[256]; n = 256;
      if (mach_vm_read_overwrite(mach_task_self(), rdi, 256,
              (mach_vm_address_t)ctx, &n) == KERN_SUCCESS) {
        fprintf(logf, "[KEY] ctx(rdi) first 256:\n");
        hex_dump(logf, ctx, 256);
      }
    }
  }

  g_bp_fired = 1;
  clear_dr_thread(th);   // one-shot: don't re-trap this thread
}

static void *exc_server_thread(void *arg) {
  (void)arg;
  for (;;) {
    exc_request_t req;
    memset(&req, 0, sizeof(req));
    kern_return_t kr = mach_msg(&req.Head, MACH_RCV_MSG, 0, sizeof(req),
                                g_exc_port, MACH_MSG_TIMEOUT_NONE,
                                MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) continue;

    mach_port_t th = req.thread.name;   // faulting thread send right
    capture_from_thread(th);

    exc_reply_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.Head.msgh_bits =
        MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.Head.msgh_bits), 0);
    rep.Head.msgh_size = sizeof(rep);
    rep.Head.msgh_remote_port = req.Head.msgh_remote_port;
    rep.Head.msgh_local_port = MACH_PORT_NULL;
    rep.Head.msgh_id = req.Head.msgh_id + 100;
    rep.NDR = req.NDR;
    rep.RetCode = KERN_SUCCESS;   // resume thread; DR cleared so no re-trap
    mach_msg(&rep.Head, MACH_SEND_MSG, sizeof(rep), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

    if (req.thread.name)
      mach_port_deallocate(mach_task_self(), req.thread.name);
    if (req.task.name)
      mach_port_deallocate(mach_task_self(), req.task.name);
  }
  return NULL;
}

static void *rearm_thread(void *arg) {
  (void)arg;
  // Crypto runs on a thread spawned after we load; re-apply DR to all
  // threads until the breakpoint fires once.
  for (int i = 0; i < 4000 && !g_bp_fired; i++) {
    set_dr_all_threads(g_bp_addr);
    usleep(200000);  // 200ms
  }
  fprintf(stderr, "[HOOK] rearm thread exiting (fired=%d)\n", g_bp_fired);
  return NULL;
}

static void install_exc_breakpoint(void) {
  intptr_t slide = _dyld_get_image_vmaddr_slide(0);
  uint64_t t = SETUP_FN_FILEVMADDR + (uint64_t)slide;

  // Verify target is mapped & matches expected prologue (so we don't
  // arm garbage in the Qt-less CEF helper process).
  unsigned char probe[16];
  mach_vm_size_t got = 16;
  if (mach_vm_read_overwrite(mach_task_self(), t, 16,
                             (mach_vm_address_t)probe, &got) != KERN_SUCCESS
      || got < 14 || memcmp(probe, SETUP_FN_EXPECT, 14) != 0) {
    fprintf(stderr, "[HOOK] exc-bp: target 0x%llx not the expected fn, skip\n",
            (unsigned long long)t);
    return;
  }
  g_bp_addr = t;

  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                         &g_exc_port) != KERN_SUCCESS) {
    fprintf(stderr, "[HOOK] exc-bp: port alloc failed\n");
    return;
  }
  mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port,
                         MACH_MSG_TYPE_MAKE_SEND);

  kern_return_t kr = task_set_exception_ports(
      mach_task_self(), EXC_MASK_BREAKPOINT, g_exc_port,
      EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, x86_THREAD_STATE64);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[HOOK] exc-bp: task_set_exception_ports kr=%d\n", kr);
    return;
  }

  pthread_t s, r;
  pthread_create(&s, NULL, exc_server_thread, NULL);
  pthread_detach(s);
  pthread_create(&r, NULL, rearm_thread, NULL);
  pthread_detach(r);

  fprintf(stderr, "[HOOK] *** EXC BREAKPOINT ARMED at 0x%llx "
          "(slide=0x%lx) ***\n", (unsigned long long)t, (long)slide);
  if (logf)
    fprintf(logf, "[HOOK] exc breakpoint armed at 0x%llx\n",
            (unsigned long long)t);
}

// =====================================================================
// Verification: check if mbedtls symbols resolve at load time
// =====================================================================
__attribute__((constructor))
static void hook_init(void) {
  logf = fopen("/tmp/stick-tls-plaintext.log", "w");
  if (logf) {
    setvbuf(logf, NULL, _IONBF, 0);
    time_t now = time(NULL);
    fprintf(logf, "=== Hook loaded PID %d at %s", getpid(), ctime(&now));
  }
  fprintf(stderr, "\n\n========================================\n");
  fprintf(stderr, "[HOOK] LOADED PID %d\n", getpid());
  fprintf(stderr, "========================================\n");

  // Verify we can find mbedtls symbols (proves dynamic linking works)
  const char *syms[] = {
    "mbedtls_aes_setkey_enc", "mbedtls_aes_setkey_dec",
    "mbedtls_aes_crypt_ecb", "mbedtls_aes_crypt_cbc",
    "mbedtls_aes_crypt_ctr", "mbedtls_aes_crypt_cfb128",
    "mbedtls_aes_crypt_ofb", "mbedtls_aes_crypt_xts",
    "mbedtls_gcm_crypt_and_tag", "mbedtls_gcm_update",
    "mbedtls_ccm_encrypt_and_tag", "mbedtls_ccm_update",
    "mbedtls_chacha20_crypt", "mbedtls_chacha20_update",
    "mbedtls_cipher_crypt", "mbedtls_cipher_setkey",
    "mbedtls_cipher_auth_encrypt_ext",
    NULL
  };
  for (int i = 0; syms[i]; i++) {
    void *p = dlsym(RTLD_DEFAULT, syms[i]);
    fprintf(stderr, "[HOOK]   %s -> %s\n", syms[i], p ? "FOUND" : "NOT FOUND");
    if (logf) fprintf(logf, "[HOOK]   %s -> %s\n", syms[i], p ? "FOUND" : "NOT FOUND");
  }
  fprintf(stderr, "========================================\n\n");

  install_exc_breakpoint();
}

// =====================================================================
// Socket hooks (send, sendto, sendmsg, recv, connect, write, read, writev)
// =====================================================================

static int stick_fds[8] = {0};
static int stick_fd_count = 0;
static int is_stick_fd(int fd) {
  for (int i = 0; i < stick_fd_count; i++)
    if (stick_fds[i] == fd) return 1;
  return 0;
}

ssize_t hooked_send(int sockfd, const void *buf, size_t len, int flags) {
  if (logf && len > 0) {
    msg_count++;
    fprintf(logf, "\n[%d] SEND fd=%d len=%zu flags=%d\n", msg_count, sockfd, len, flags);
    hex_dump(logf, (const unsigned char *)buf, len > 512 ? 512 : len);
  }
  return send(sockfd, buf, len, flags);
}

// =====================================================================
// AES key scanner — searches heap for AES-256 key schedule
// =====================================================================
static int key_dumped = 0;

static const unsigned char aes_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint32_t sub_word(uint32_t w) {
  return ((uint32_t)aes_sbox[w & 0xff]) |
         ((uint32_t)aes_sbox[(w >> 8) & 0xff] << 8) |
         ((uint32_t)aes_sbox[(w >> 16) & 0xff] << 16) |
         ((uint32_t)aes_sbox[(w >> 24) & 0xff] << 24);
}

static int is_aes256_key_schedule(const unsigned char *data) {
  uint32_t W[60];
  memcpy(W, data, 240);

  // Reject trivial (all-zero key)
  int nonzero = 0;
  for (int i = 0; i < 8; i++) if (W[i]) nonzero = 1;
  if (!nonzero) return 0;

  static const uint32_t rcon[8] = {
    0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
  };

  for (int i = 8; i < 60; i++) {
    uint32_t temp = W[i - 1];
    if (i % 8 == 0) {
      temp = (temp >> 8) | (temp << 24); // RotWord
      temp = sub_word(temp);
      temp ^= rcon[i / 8];
    } else if (i % 8 == 4) {
      temp = sub_word(temp);
    }
    if (W[i] != (W[i - 8] ^ temp)) return 0;
  }
  return 1;
}

// AES-128: 44 words / 176 bytes. Nk=4, Nr=10.
// W[i]=W[i-4]^temp; if i%4==0 temp=SubWord(RotWord(W[i-1]))^Rcon[i/4]
static int is_aes128_key_schedule(const unsigned char *data) {
  uint32_t W[44];
  memcpy(W, data, 176);

  int nonzero = 0;
  for (int i = 0; i < 4; i++) if (W[i]) nonzero = 1;
  if (!nonzero) return 0;

  static const uint32_t rcon[11] = {
    0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
  };

  for (int i = 4; i < 44; i++) {
    uint32_t temp = W[i - 1];
    if (i % 4 == 0) {
      temp = (temp >> 8) | (temp << 24); // RotWord
      temp = sub_word(temp);
      temp ^= rcon[i / 4];
    }
    if (W[i] != (W[i - 4] ^ temp)) return 0;
  }
  return 1;
}

// Same as is_aes128_key_schedule but treats each stored 4-byte word as
// byte-swapped (the custom expander at 0x10040b2c0 may store words in the
// opposite endianness, which would make a valid schedule fail the normal
// check).
static int is_aes128_key_schedule_bswap(const unsigned char *data) {
  unsigned char tmp[176];
  for (int i = 0; i < 176; i += 4) {
    tmp[i+0] = data[i+3];
    tmp[i+1] = data[i+2];
    tmp[i+2] = data[i+1];
    tmp[i+3] = data[i+0];
  }
  return is_aes128_key_schedule(tmp);
}

static void scan_for_key_schedule(void) {
  mach_port_t task = mach_task_self();
  size_t chunk = 0x10000; // 64K
  unsigned char *buf = (unsigned char *)malloc(chunk + 240);
  if (!buf) return;

  fprintf(stderr, "[HOOK] Scanning ALL memory for AES-256 key schedule...\n");

  int regions_scanned = 0;
  int found_count = 0;
  mach_vm_address_t addr = 0;

  while (1) {
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj_name;

    kern_return_t kr = mach_vm_region(task, &addr, &region_size,
                                       VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&info, &info_count,
                                       &obj_name);
    if (kr != KERN_SUCCESS) break;

    if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
      regions_scanned++;
      for (uint64_t offset = 0; offset < region_size; offset += chunk) {
        mach_vm_size_t read_size = chunk + 240;
        if (offset + read_size > region_size)
          read_size = region_size - offset;
        if (read_size < 240) { continue; }

        mach_vm_size_t actual = read_size;
        kr = mach_vm_read_overwrite(task, addr + offset, read_size,
                                     (mach_vm_address_t)buf, &actual);
        if (kr != KERN_SUCCESS) continue;

        for (size_t i = 0; i + 240 <= (size_t)actual; i += 4) {
          if (is_aes256_key_schedule(buf + i)) {
            uint64_t key_addr = addr + offset + i;
            found_count++;
            fprintf(stderr, "\n[HOOK] *** FOUND AES-256 KEY SCHEDULE at 0x%llx ***\n",
                    (unsigned long long)key_addr);
            fprintf(stderr, "[HOOK] Original key (first 32 bytes):\n");
            hex_dump(stderr, buf + i, 32);
            if (logf) {
              fprintf(logf, "\n[KEY] AES-256 KEY SCHEDULE at 0x%llx\n",
                      (unsigned long long)key_addr);
              hex_dump(logf, buf + i, 240);
            }
          }
          if (is_aes128_key_schedule_bswap(buf + i)) {
            uint64_t key_addr = addr + offset + i;
            found_count++;
            fprintf(stderr, "\n[HOOK] *** FOUND AES-128 (BSWAP) SCHEDULE at 0x%llx ***\n",
                    (unsigned long long)key_addr);
            fprintf(stderr, "[HOOK] raw 16 bytes:\n");
            hex_dump(stderr, buf + i, 16);
            if (logf) {
              fprintf(logf, "\n[KEY] *** AES-128 BSWAP SCHEDULE at 0x%llx ***\n",
                      (unsigned long long)key_addr);
              fprintf(logf, "[KEY] raw KEY(16):\n");
              hex_dump(logf, buf + i, 16);
              fprintf(logf, "[KEY] full raw schedule(176):\n");
              hex_dump(logf, buf + i, 176);
            }
          }
          if (is_aes128_key_schedule(buf + i)) {
            uint64_t key_addr = addr + offset + i;
            found_count++;
            fprintf(stderr, "\n[HOOK] *** FOUND AES-128 KEY SCHEDULE at 0x%llx ***\n",
                    (unsigned long long)key_addr);
            fprintf(stderr, "[HOOK] Original key (first 16 bytes):\n");
            hex_dump(stderr, buf + i, 16);
            fprintf(stderr, "[HOOK] Full schedule (176 bytes):\n");
            hex_dump(stderr, buf + i, 176);
            // IV typically follows at +0xb0 (176) within the crypto context
            fprintf(stderr, "[HOOK] Bytes at +0xb0 (possible IV, 16 bytes):\n");
            hex_dump(stderr, buf + i + 176, 16);
            if (logf) {
              fprintf(logf, "\n[KEY] *** AES-128 KEY SCHEDULE at 0x%llx ***\n",
                      (unsigned long long)key_addr);
              fprintf(logf, "[KEY] KEY (16 bytes):\n");
              hex_dump(logf, buf + i, 16);
              fprintf(logf, "[KEY] Full schedule (176 bytes):\n");
              hex_dump(logf, buf + i, 176);
              fprintf(logf, "[KEY] IV candidate at +0xb0 (16 bytes):\n");
              hex_dump(logf, buf + i + 176, 16);
            }
          }
        }
      }
    }

    addr += region_size;
  }

  free(buf);
  fprintf(stderr, "[HOOK] Key schedule scan: %d regions, %d schedules found.\n",
          regions_scanned, found_count);
}

static void dump_ptr_at(mach_port_t task, uint64_t addr, int depth, const char *path) {
  if (depth > 2) return;
  kern_return_t kr;
  unsigned char obj[1024];
  mach_vm_size_t osz = 1024;
  kr = mach_vm_read_overwrite(task, addr, 1024, (mach_vm_address_t)obj, &osz);
  if (kr != KERN_SUCCESS) return;

  fprintf(stderr, "\n[HOOK] === %s at 0x%llx (depth=%d) ===\n",
          path, (unsigned long long)addr, depth);

  // Check for key schedule at various offsets
  for (size_t off = 0; off + 192 <= (size_t)osz; off += 4) {
    if (off + 240 <= (size_t)osz && is_aes256_key_schedule(obj + off)) {
      fprintf(stderr, "[HOOK] *** AES-256 SCHEDULE at %s+0x%zx ***\n", path, off);
      hex_dump(stderr, obj + off, 32);
      if (logf) {
        fprintf(logf, "\n[KEY] AES256 at %s+0x%zx addr=0x%llx\n",
                path, off, (unsigned long long)(addr + off));
        hex_dump(logf, obj + off, 32);
      }
    }
    if (is_aes128_key_schedule_bswap(obj + off)) {
      unsigned char k[16];
      for (int b = 0; b < 16; b += 4) {
        k[b+0]=obj[off+b+3]; k[b+1]=obj[off+b+2];
        k[b+2]=obj[off+b+1]; k[b+3]=obj[off+b+0];
      }
      fprintf(stderr, "[HOOK] *** AES-128 BSWAP SCHEDULE at %s+0x%zx ***\n", path, off);
      fprintf(stderr, "[HOOK] KEY (bswapped 16):\n");
      hex_dump(stderr, k, 16);
      fprintf(stderr, "[HOOK] raw 16 / IV cand +0xb0:\n");
      hex_dump(stderr, obj + off, 16);
      hex_dump(stderr, obj + off + 176, 16);
      if (logf) {
        fprintf(logf, "\n[KEY] *** AES128-BSWAP at %s+0x%zx addr=0x%llx ***\n",
                path, off, (unsigned long long)(addr + off));
        fprintf(logf, "[KEY] KEY bswapped(16):\n");
        hex_dump(logf, k, 16);
        fprintf(logf, "[KEY] raw(16):\n");
        hex_dump(logf, obj + off, 16);
        fprintf(logf, "[KEY] IV cand(+0xb0):\n");
        hex_dump(logf, obj + off + 176, 16);
      }
    }
    if (is_aes128_key_schedule(obj + off)) {
      fprintf(stderr, "[HOOK] *** AES-128 SCHEDULE at %s+0x%zx ***\n", path, off);
      hex_dump(stderr, obj + off, 16);
      fprintf(stderr, "[HOOK] IV cand +0xb0:\n");
      hex_dump(stderr, obj + off + 176, 16);
      if (logf) {
        fprintf(logf, "\n[KEY] *** AES128 at %s+0x%zx addr=0x%llx ***\n",
                path, off, (unsigned long long)(addr + off));
        fprintf(logf, "[KEY] KEY(16):\n");
        hex_dump(logf, obj + off, 16);
        fprintf(logf, "[KEY] IV cand(+0xb0):\n");
        hex_dump(logf, obj + off + 176, 16);
      }
    }
  }

  // Dump first 512 bytes
  hex_dump(stderr, obj, osz < 512 ? (size_t)osz : 512);
  if (logf) {
    fprintf(logf, "\n[OBJ] %s at 0x%llx:\n", path, (unsigned long long)addr);
    hex_dump(logf, obj, osz < 512 ? (size_t)osz : 512);
  }

  // Follow pointers (only in first 256 bytes, heap range 0x1-0x7fff)
  if (depth < 2) {
    for (size_t off = 0; off + 8 <= 256 && off + 8 <= (size_t)osz; off += 8) {
      uint64_t val;
      memcpy(&val, obj + off, 8);
      // Skip null, small values, and the vtable pointer we already know
      if (val < 0x10000 || val > 0x7fffffffffffULL) continue;
      // Skip code pointers (in __TEXT segment ~0x100000000-0x110000000)
      if (val >= 0x100000000ULL && val < 0x110000000ULL) continue;
      char subpath[256];
      snprintf(subpath, sizeof(subpath), "%s+0x%zx->", path, off);
      dump_ptr_at(task, val, depth + 1, subpath);
    }
  }
}

static void scan_for_key(uint64_t vtable_target) {
  mach_port_t task = mach_task_self();
  size_t chunk = 0x10000; // 64K
  unsigned char *buf = (unsigned char *)malloc(chunk);
  if (!buf) return;

  unsigned char vtable_bytes[8];
  memcpy(vtable_bytes, &vtable_target, 8);

  fprintf(stderr, "[HOOK] Scanning ALL memory regions for vtable 0x%llx...\n",
          (unsigned long long)vtable_target);

  int regions_scanned = 0;
  int found_count = 0;
  mach_vm_address_t addr = 0;

  while (1) {
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj_name;

    kern_return_t kr = mach_vm_region(task, &addr, &region_size,
                                       VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&info, &info_count,
                                       &obj_name);
    if (kr != KERN_SUCCESS) break;

    // Only scan readable, writable regions (heap)
    if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
      regions_scanned++;
      for (uint64_t offset = 0; offset < region_size; offset += chunk) {
        mach_vm_size_t read_size = chunk;
        if (offset + read_size > region_size)
          read_size = region_size - offset;

        mach_vm_size_t actual = read_size;
        kr = mach_vm_read_overwrite(task, addr + offset, read_size,
                                     (mach_vm_address_t)buf, &actual);
        if (kr != KERN_SUCCESS) continue;

        for (size_t i = 0; i + 8 <= (size_t)actual; i += 8) {
          if (memcmp(buf + i, vtable_bytes, 8) == 0) {
            uint64_t obj_addr = addr + offset + i;
            found_count++;
            fprintf(stderr, "\n[HOOK] *** FOUND vtable match at 0x%llx ***\n",
                    (unsigned long long)obj_addr);

            char rootpath[64];
            snprintf(rootpath, sizeof(rootpath), "vtable_0x%llx",
                     (unsigned long long)vtable_target);
            dump_ptr_at(task, obj_addr, 0, rootpath);
          }
        }
      }
    }

    addr += region_size;
  }

  free(buf);
  fprintf(stderr, "[HOOK] Scan complete: %d regions scanned, %d matches found.\n",
          regions_scanned, found_count);
}

static void try_dump_key(void) {
  if (key_dumped) return;
  key_dumped = 1;

  intptr_t slide = _dyld_get_image_vmaddr_slide(0);
  // Stick3CryptDmxUniverse vtable[0] file vmaddr
  uint64_t vtable_stick3 = (uint64_t)(0x100964F20 + slide);
  // DasNetCryptDmxUniverse vtable[0] file vmaddr
  uint64_t vtable_base = (uint64_t)(0x100985F18 + slide);

  fprintf(stderr, "\n[HOOK] === KEY SCAN ===\n");
  fprintf(stderr, "[HOOK] slide=0x%lx\n", (long)slide);
  fprintf(stderr, "[HOOK] Stick3 vtable=0x%llx\n", (unsigned long long)vtable_stick3);
  fprintf(stderr, "[HOOK] DasNet vtable=0x%llx\n", (unsigned long long)vtable_base);

  scan_for_key(vtable_stick3);
  scan_for_key(vtable_base);

  // Global scan disabled: the triple validation across all memory is
  // pathologically slow and freezes the app. The fast pointer-following
  // path above (dump_ptr_at) now checks AES-128 + AES-128-bswap on the
  // ~686 crypto sub-objects, which is where the key context actually is.
  // scan_for_key_schedule();
  fprintf(stderr, "[HOOK] (global key-schedule scan skipped; "
          "see AES-128 BSWAP hits in pointer-following output above)\n");
}

ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest, socklen_t addrlen) {
  // Trigger key dump on first 576-byte DMX frame
  if (len == 576 && !key_dumped) {
    try_dump_key();
  }

  if (logf && len > 0) {
    msg_count++;
    if (dest && dest->sa_family == AF_INET) {
      struct sockaddr_in *sin = (struct sockaddr_in *)dest;
      char ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
      fprintf(logf, "\n[%d] SENDTO fd=%d len=%zu -> %s:%d\n", msg_count, sockfd, len, ip, ntohs(sin->sin_port));
    } else {
      fprintf(logf, "\n[%d] SENDTO fd=%d len=%zu\n", msg_count, sockfd, len);
    }
    hex_dump(logf, (const unsigned char *)buf, len > 576 ? 576 : len);
  }
  return sendto(sockfd, buf, len, flags, dest, addrlen);
}

ssize_t hooked_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  ssize_t ret = sendmsg(sockfd, msg, flags);
  if (logf && ret > 0) {
    msg_count++;
    fprintf(logf, "\n[%d] SENDMSG fd=%d ret=%zd iovlen=%d\n", msg_count, sockfd, ret, (int)msg->msg_iovlen);
    for (int i = 0; i < (int)msg->msg_iovlen && i < 4; i++) {
      size_t dump_len = msg->msg_iov[i].iov_len;
      if (dump_len > 256) dump_len = 256;
      fprintf(logf, "  iov[%d] len=%zu:\n", i, msg->msg_iov[i].iov_len);
      hex_dump(logf, (const unsigned char *)msg->msg_iov[i].iov_base, dump_len);
    }
  }
  return ret;
}

ssize_t hooked_writev(int fd, const struct iovec *iov, int iovcnt) {
  ssize_t ret = writev(fd, iov, iovcnt);
  if (logf && ret > 0) {
    msg_count++;
    fprintf(logf, "\n[%d] WRITEV fd=%d ret=%zd iovcnt=%d\n", msg_count, fd, ret, iovcnt);
    for (int i = 0; i < iovcnt && i < 4; i++) {
      size_t dump_len = iov[i].iov_len;
      if (dump_len > 256) dump_len = 256;
      fprintf(logf, "  iov[%d] len=%zu:\n", i, iov[i].iov_len);
      hex_dump(logf, (const unsigned char *)iov[i].iov_base, dump_len);
    }
  }
  return ret;
}

ssize_t hooked_recv(int sockfd, void *buf, size_t len, int flags) {
  ssize_t ret = recv(sockfd, buf, len, flags);
  if (logf && ret > 0) {
    msg_count++;
    fprintf(logf, "\n[%d] RECV fd=%d len=%zd\n", msg_count, sockfd, ret);
    hex_dump(logf, (const unsigned char *)buf, (size_t)ret > 512 ? 512 : (size_t)ret);
  }
  return ret;
}

int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int ret = connect(sockfd, addr, addrlen);
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    int port = ntohs(sin->sin_port);
    if (logf) fprintf(logf, "\n[CONNECT] fd=%d -> %s:%d ret=%d\n", sockfd, ip, port, ret);
    fprintf(stderr, "[HOOK] CONNECT fd=%d -> %s:%d ret=%d\n", sockfd, ip, port, ret);
    if (port == 2431 && stick_fd_count < 8) {
      stick_fds[stick_fd_count++] = sockfd;
      if (logf) fprintf(logf, "[CONNECT] Tracking Stick fd=%d\n", sockfd);
    }
  }
  return ret;
}

ssize_t hooked_write(int fd, const void *buf, size_t len) {
  ssize_t ret = write(fd, buf, len);
  if (logf && ret > 0 && is_stick_fd(fd)) {
    msg_count++;
    fprintf(logf, "\n[%d] WRITE fd=%d len=%zu\n", msg_count, fd, len);
    hex_dump(logf, (const unsigned char *)buf, len > 512 ? 512 : len);
  }
  return ret;
}

ssize_t hooked_read(int fd, void *buf, size_t len) {
  ssize_t ret = read(fd, buf, len);
  if (logf && ret > 0 && is_stick_fd(fd)) {
    msg_count++;
    fprintf(logf, "\n[%d] READ fd=%d len=%zd\n", msg_count, fd, ret);
    hex_dump(logf, (const unsigned char *)buf, (size_t)ret > 512 ? 512 : (size_t)ret);
  }
  return ret;
}

// =====================================================================
// mbedtls AES — ALL MODES
// =====================================================================
typedef struct mbedtls_aes_context mbedtls_aes_context;
typedef struct mbedtls_aes_xts_context mbedtls_aes_xts_context;

extern int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits);
extern int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits);
extern int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16]);
extern int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output);
extern int mbedtls_aes_crypt_cfb128(mbedtls_aes_context *ctx, int mode, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input, unsigned char *output);
extern int mbedtls_aes_crypt_ofb(mbedtls_aes_context *ctx, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input, unsigned char *output);
extern int mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx, size_t length, size_t *nc_off, unsigned char nonce_counter[16], unsigned char stream_block[16], const unsigned char *input, unsigned char *output);
extern int mbedtls_aes_crypt_xts(mbedtls_aes_xts_context *ctx, int mode, size_t length, const unsigned char data_unit[16], const unsigned char *input, unsigned char *output);

int hooked_mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
  fprintf(stderr, "[HOOK] >>> AES_SETKEY_ENC keybits=%u <<<\n", keybits);
  if (logf) {
    fprintf(logf, "\n=== AES_SETKEY_ENC keybits=%u ===\n", keybits);
    hex_dump(logf, key, keybits / 8);
  }
  return mbedtls_aes_setkey_enc(ctx, key, keybits);
}

int hooked_mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
  fprintf(stderr, "[HOOK] >>> AES_SETKEY_DEC keybits=%u <<<\n", keybits);
  if (logf) {
    fprintf(logf, "\n=== AES_SETKEY_DEC keybits=%u ===\n", keybits);
    hex_dump(logf, key, keybits / 8);
  }
  return mbedtls_aes_setkey_dec(ctx, key, keybits);
}

int hooked_mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16]) {
  fprintf(stderr, "[HOOK] >>> AES_ECB mode=%d <<<\n", mode);
  if (logf) {
    fprintf(logf, "\n=== AES_ECB mode=%s ===\n", mode ? "DECRYPT" : "ENCRYPT");
    fprintf(logf, "  input:\n"); hex_dump(logf, input, 16);
  }
  int ret = mbedtls_aes_crypt_ecb(ctx, mode, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, 16); }
  return ret;
}

int hooked_mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output) {
  fprintf(stderr, "[HOOK] >>> AES_CBC mode=%d len=%zu <<<\n", mode, length);
  if (logf) {
    fprintf(logf, "\n=== AES_CBC mode=%s len=%zu ===\n", mode ? "DECRYPT" : "ENCRYPT", length);
    fprintf(logf, "  iv:\n"); hex_dump(logf, iv, 16);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, length > 256 ? 256 : length);
  }
  int ret = mbedtls_aes_crypt_cbc(ctx, mode, length, iv, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, length > 256 ? 256 : length); }
  return ret;
}

int hooked_mbedtls_aes_crypt_cfb128(mbedtls_aes_context *ctx, int mode, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input, unsigned char *output) {
  fprintf(stderr, "[HOOK] >>> AES_CFB128 mode=%d len=%zu <<<\n", mode, length);
  if (logf) {
    fprintf(logf, "\n=== AES_CFB128 mode=%s len=%zu iv_off=%zu ===\n", mode ? "DECRYPT" : "ENCRYPT", length, *iv_off);
    fprintf(logf, "  iv:\n"); hex_dump(logf, iv, 16);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, length > 256 ? 256 : length);
  }
  int ret = mbedtls_aes_crypt_cfb128(ctx, mode, length, iv_off, iv, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, length > 256 ? 256 : length); }
  return ret;
}

int hooked_mbedtls_aes_crypt_ofb(mbedtls_aes_context *ctx, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input, unsigned char *output) {
  fprintf(stderr, "[HOOK] >>> AES_OFB len=%zu <<<\n", length);
  if (logf) {
    fprintf(logf, "\n=== AES_OFB len=%zu iv_off=%zu ===\n", length, *iv_off);
    fprintf(logf, "  iv:\n"); hex_dump(logf, iv, 16);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, length > 256 ? 256 : length);
  }
  int ret = mbedtls_aes_crypt_ofb(ctx, length, iv_off, iv, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, length > 256 ? 256 : length); }
  return ret;
}

int hooked_mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx, size_t length, size_t *nc_off, unsigned char nonce_counter[16], unsigned char stream_block[16], const unsigned char *input, unsigned char *output) {
  fprintf(stderr, "[HOOK] >>> AES_CTR len=%zu <<<\n", length);
  if (logf) {
    fprintf(logf, "\n=== AES_CTR len=%zu nc_off=%zu ===\n", length, *nc_off);
    fprintf(logf, "  nonce_counter:\n"); hex_dump(logf, nonce_counter, 16);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, length > 256 ? 256 : length);
  }
  int ret = mbedtls_aes_crypt_ctr(ctx, length, nc_off, nonce_counter, stream_block, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, length > 256 ? 256 : length); }
  return ret;
}

int hooked_mbedtls_aes_crypt_xts(mbedtls_aes_xts_context *ctx, int mode, size_t length, const unsigned char data_unit[16], const unsigned char *input, unsigned char *output) {
  fprintf(stderr, "[HOOK] >>> AES_XTS mode=%d len=%zu <<<\n", mode, length);
  if (logf) {
    fprintf(logf, "\n=== AES_XTS mode=%s len=%zu ===\n", mode ? "DECRYPT" : "ENCRYPT", length);
    fprintf(logf, "  data_unit:\n"); hex_dump(logf, data_unit, 16);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, length > 256 ? 256 : length);
  }
  int ret = mbedtls_aes_crypt_xts(ctx, mode, length, data_unit, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, length > 256 ? 256 : length); }
  return ret;
}

// =====================================================================
// mbedtls GCM
// =====================================================================
typedef struct mbedtls_gcm_context mbedtls_gcm_context;

extern int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx, int cipher, const unsigned char *key, unsigned int keybits);
extern int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx, int mode, size_t length,
    const unsigned char *iv, size_t iv_len, const unsigned char *add, size_t add_len,
    const unsigned char *input, unsigned char *output, size_t tag_len, unsigned char *tag);
extern int mbedtls_gcm_starts(mbedtls_gcm_context *ctx, int mode, const unsigned char *iv, size_t iv_len);
extern int mbedtls_gcm_update(mbedtls_gcm_context *ctx, const unsigned char *input, size_t input_length, unsigned char *output, size_t output_size, size_t *output_length);

int hooked_mbedtls_gcm_setkey(mbedtls_gcm_context *ctx, int cipher, const unsigned char *key, unsigned int keybits) {
  fprintf(stderr, "[HOOK] >>> GCM_SETKEY cipher=%d keybits=%u <<<\n", cipher, keybits);
  if (logf) {
    fprintf(logf, "\n=== GCM_SETKEY cipher=%d keybits=%u ===\n", cipher, keybits);
    hex_dump(logf, key, keybits / 8);
  }
  return mbedtls_gcm_setkey(ctx, cipher, key, keybits);
}

int hooked_mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx, int mode, size_t length,
    const unsigned char *iv, size_t iv_len, const unsigned char *add, size_t add_len,
    const unsigned char *input, unsigned char *output, size_t tag_len, unsigned char *tag) {
  fprintf(stderr, "[HOOK] >>> GCM_CRYPT_AND_TAG mode=%d len=%zu <<<\n", mode, length);
  if (logf) {
    fprintf(logf, "\n=== GCM_CRYPT_AND_TAG mode=%s len=%zu iv_len=%zu add_len=%zu tag_len=%zu ===\n",
      mode ? "DECRYPT" : "ENCRYPT", length, iv_len, add_len, tag_len);
    fprintf(logf, "  iv:\n"); hex_dump(logf, iv, iv_len);
    if (add_len > 0) { fprintf(logf, "  aad:\n"); hex_dump(logf, add, add_len > 64 ? 64 : add_len); }
    fprintf(logf, "  input:\n"); hex_dump(logf, input, length > 256 ? 256 : length);
  }
  int ret = mbedtls_gcm_crypt_and_tag(ctx, mode, length, iv, iv_len, add, add_len, input, output, tag_len, tag);
  if (logf) {
    fprintf(logf, "  output:\n"); hex_dump(logf, output, length > 256 ? 256 : length);
    fprintf(logf, "  tag:\n"); hex_dump(logf, tag, tag_len);
  }
  return ret;
}

int hooked_mbedtls_gcm_starts(mbedtls_gcm_context *ctx, int mode, const unsigned char *iv, size_t iv_len) {
  fprintf(stderr, "[HOOK] >>> GCM_STARTS mode=%d iv_len=%zu <<<\n", mode, iv_len);
  if (logf) {
    fprintf(logf, "\n=== GCM_STARTS mode=%s iv_len=%zu ===\n", mode ? "DECRYPT" : "ENCRYPT", iv_len);
    fprintf(logf, "  iv:\n"); hex_dump(logf, iv, iv_len);
  }
  return mbedtls_gcm_starts(ctx, mode, iv, iv_len);
}

int hooked_mbedtls_gcm_update(mbedtls_gcm_context *ctx, const unsigned char *input, size_t input_length, unsigned char *output, size_t output_size, size_t *output_length) {
  fprintf(stderr, "[HOOK] >>> GCM_UPDATE input_len=%zu <<<\n", input_length);
  if (logf) {
    fprintf(logf, "\n=== GCM_UPDATE input_len=%zu output_size=%zu ===\n", input_length, output_size);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, input_length > 256 ? 256 : input_length);
  }
  int ret = mbedtls_gcm_update(ctx, input, input_length, output, output_size, output_length);
  if (logf && output_length) {
    fprintf(logf, "  output (len=%zu):\n", *output_length);
    hex_dump(logf, output, *output_length > 256 ? 256 : *output_length);
  }
  return ret;
}

// =====================================================================
// mbedtls CCM
// =====================================================================
typedef struct mbedtls_ccm_context mbedtls_ccm_context;

extern int mbedtls_ccm_setkey(mbedtls_ccm_context *ctx, int cipher, const unsigned char *key, unsigned int keybits);
extern int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
    const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len,
    const unsigned char *input, unsigned char *output, unsigned char *tag, size_t tag_len);
extern int mbedtls_ccm_update(mbedtls_ccm_context *ctx, const unsigned char *input, size_t input_length, unsigned char *output, size_t output_size, size_t *output_length);

int hooked_mbedtls_ccm_setkey(mbedtls_ccm_context *ctx, int cipher, const unsigned char *key, unsigned int keybits) {
  fprintf(stderr, "[HOOK] >>> CCM_SETKEY cipher=%d keybits=%u <<<\n", cipher, keybits);
  if (logf) {
    fprintf(logf, "\n=== CCM_SETKEY cipher=%d keybits=%u ===\n", cipher, keybits);
    hex_dump(logf, key, keybits / 8);
  }
  return mbedtls_ccm_setkey(ctx, cipher, key, keybits);
}

int hooked_mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
    const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len,
    const unsigned char *input, unsigned char *output, unsigned char *tag, size_t tag_len) {
  fprintf(stderr, "[HOOK] >>> CCM_ENCRYPT_AND_TAG len=%zu <<<\n", length);
  if (logf) {
    fprintf(logf, "\n=== CCM_ENCRYPT_AND_TAG len=%zu iv_len=%zu ad_len=%zu tag_len=%zu ===\n",
      length, iv_len, ad_len, tag_len);
    fprintf(logf, "  iv:\n"); hex_dump(logf, iv, iv_len);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, length > 256 ? 256 : length);
  }
  int ret = mbedtls_ccm_encrypt_and_tag(ctx, length, iv, iv_len, ad, ad_len, input, output, tag, tag_len);
  if (logf) {
    fprintf(logf, "  output:\n"); hex_dump(logf, output, length > 256 ? 256 : length);
    fprintf(logf, "  tag:\n"); hex_dump(logf, tag, tag_len);
  }
  return ret;
}

int hooked_mbedtls_ccm_update(mbedtls_ccm_context *ctx, const unsigned char *input, size_t input_length, unsigned char *output, size_t output_size, size_t *output_length) {
  fprintf(stderr, "[HOOK] >>> CCM_UPDATE input_len=%zu <<<\n", input_length);
  if (logf) {
    fprintf(logf, "\n=== CCM_UPDATE input_len=%zu ===\n", input_length);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, input_length > 256 ? 256 : input_length);
  }
  int ret = mbedtls_ccm_update(ctx, input, input_length, output, output_size, output_length);
  if (logf && output_length) {
    fprintf(logf, "  output (len=%zu):\n", *output_length);
    hex_dump(logf, output, *output_length > 256 ? 256 : *output_length);
  }
  return ret;
}

// =====================================================================
// mbedtls ChaCha20 / ChaChaPoly
// =====================================================================
typedef struct mbedtls_chacha20_context mbedtls_chacha20_context;
typedef struct mbedtls_chachapoly_context mbedtls_chachapoly_context;

extern int mbedtls_chacha20_crypt(const unsigned char key[32], const unsigned char nonce[12], uint32_t counter, size_t size, const unsigned char *input, unsigned char *output);
extern int mbedtls_chacha20_update(mbedtls_chacha20_context *ctx, size_t size, const unsigned char *input, unsigned char *output);
extern int mbedtls_chachapoly_encrypt_and_tag(mbedtls_chachapoly_context *ctx, size_t length, const unsigned char nonce[12], const unsigned char *aad, size_t aad_len, const unsigned char *input, unsigned char *output, unsigned char tag[16]);
extern int mbedtls_chachapoly_update(mbedtls_chachapoly_context *ctx, size_t len, const unsigned char *input, unsigned char *output);

int hooked_mbedtls_chacha20_crypt(const unsigned char key[32], const unsigned char nonce[12], uint32_t counter, size_t size, const unsigned char *input, unsigned char *output) {
  fprintf(stderr, "[HOOK] >>> CHACHA20_CRYPT size=%zu <<<\n", size);
  if (logf) {
    fprintf(logf, "\n=== CHACHA20_CRYPT size=%zu counter=%u ===\n", size, counter);
    fprintf(logf, "  key:\n"); hex_dump(logf, key, 32);
    fprintf(logf, "  nonce:\n"); hex_dump(logf, nonce, 12);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, size > 256 ? 256 : size);
  }
  int ret = mbedtls_chacha20_crypt(key, nonce, counter, size, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, size > 256 ? 256 : size); }
  return ret;
}

int hooked_mbedtls_chacha20_update(mbedtls_chacha20_context *ctx, size_t size, const unsigned char *input, unsigned char *output) {
  fprintf(stderr, "[HOOK] >>> CHACHA20_UPDATE size=%zu <<<\n", size);
  if (logf) {
    fprintf(logf, "\n=== CHACHA20_UPDATE size=%zu ===\n", size);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, size > 256 ? 256 : size);
  }
  int ret = mbedtls_chacha20_update(ctx, size, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, size > 256 ? 256 : size); }
  return ret;
}

int hooked_mbedtls_chachapoly_encrypt_and_tag(mbedtls_chachapoly_context *ctx, size_t length, const unsigned char nonce[12], const unsigned char *aad, size_t aad_len, const unsigned char *input, unsigned char *output, unsigned char tag[16]) {
  fprintf(stderr, "[HOOK] >>> CHACHAPOLY_ENCRYPT len=%zu <<<\n", length);
  if (logf) {
    fprintf(logf, "\n=== CHACHAPOLY_ENCRYPT_AND_TAG len=%zu aad_len=%zu ===\n", length, aad_len);
    fprintf(logf, "  nonce:\n"); hex_dump(logf, nonce, 12);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, length > 256 ? 256 : length);
  }
  int ret = mbedtls_chachapoly_encrypt_and_tag(ctx, length, nonce, aad, aad_len, input, output, tag);
  if (logf) {
    fprintf(logf, "  output:\n"); hex_dump(logf, output, length > 256 ? 256 : length);
    fprintf(logf, "  tag:\n"); hex_dump(logf, tag, 16);
  }
  return ret;
}

int hooked_mbedtls_chachapoly_update(mbedtls_chachapoly_context *ctx, size_t len, const unsigned char *input, unsigned char *output) {
  fprintf(stderr, "[HOOK] >>> CHACHAPOLY_UPDATE len=%zu <<<\n", len);
  if (logf) {
    fprintf(logf, "\n=== CHACHAPOLY_UPDATE len=%zu ===\n", len);
    fprintf(logf, "  input:\n"); hex_dump(logf, input, len > 256 ? 256 : len);
  }
  int ret = mbedtls_chachapoly_update(ctx, len, input, output);
  if (logf) { fprintf(logf, "  output:\n"); hex_dump(logf, output, len > 256 ? 256 : len); }
  return ret;
}

// =====================================================================
// mbedtls generic cipher API
// =====================================================================
typedef struct mbedtls_cipher_context_t mbedtls_cipher_context_t;
typedef void mbedtls_cipher_info_t;

extern int mbedtls_cipher_setkey(mbedtls_cipher_context_t *ctx, const unsigned char *key, int key_bitlen, int operation);
extern int mbedtls_cipher_crypt(mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen);
extern int mbedtls_cipher_auth_encrypt_ext(mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t output_len, size_t *olen, size_t tag_len);

int hooked_mbedtls_cipher_setkey(mbedtls_cipher_context_t *ctx, const unsigned char *key, int key_bitlen, int operation) {
  fprintf(stderr, "[HOOK] >>> CIPHER_SETKEY keybits=%d op=%s <<<\n", key_bitlen, operation ? "DECRYPT" : "ENCRYPT");
  if (logf) {
    fprintf(logf, "\n=== CIPHER_SETKEY keybits=%d op=%s ===\n", key_bitlen, operation ? "DECRYPT" : "ENCRYPT");
    hex_dump(logf, key, key_bitlen / 8);
  }
  return mbedtls_cipher_setkey(ctx, key, key_bitlen, operation);
}

int hooked_mbedtls_cipher_crypt(mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen) {
  fprintf(stderr, "[HOOK] >>> CIPHER_CRYPT ilen=%zu iv_len=%zu <<<\n", ilen, iv_len);
  if (logf) {
    fprintf(logf, "\n=== CIPHER_CRYPT ilen=%zu iv_len=%zu ===\n", ilen, iv_len);
    if (iv_len > 0) { fprintf(logf, "  iv:\n"); hex_dump(logf, iv, iv_len); }
    fprintf(logf, "  input:\n"); hex_dump(logf, input, ilen > 256 ? 256 : ilen);
  }
  int ret = mbedtls_cipher_crypt(ctx, iv, iv_len, input, ilen, output, olen);
  if (logf && olen) {
    fprintf(logf, "  output (len=%zu):\n", *olen);
    hex_dump(logf, output, *olen > 256 ? 256 : *olen);
  }
  return ret;
}

int hooked_mbedtls_cipher_auth_encrypt_ext(mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t output_len, size_t *olen, size_t tag_len) {
  fprintf(stderr, "[HOOK] >>> CIPHER_AUTH_ENCRYPT_EXT ilen=%zu tag_len=%zu <<<\n", ilen, tag_len);
  if (logf) {
    fprintf(logf, "\n=== CIPHER_AUTH_ENCRYPT_EXT ilen=%zu iv_len=%zu ad_len=%zu tag_len=%zu ===\n",
      ilen, iv_len, ad_len, tag_len);
    if (iv_len > 0) { fprintf(logf, "  iv:\n"); hex_dump(logf, iv, iv_len); }
    fprintf(logf, "  input:\n"); hex_dump(logf, input, ilen > 256 ? 256 : ilen);
  }
  int ret = mbedtls_cipher_auth_encrypt_ext(ctx, iv, iv_len, ad, ad_len, input, ilen, output, output_len, olen, tag_len);
  if (logf && olen) {
    fprintf(logf, "  output (len=%zu):\n", *olen);
    hex_dump(logf, output, *olen > 256 ? 256 : *olen);
  }
  return ret;
}

// =====================================================================
// QCryptographicHash::hash hook — capture key derivation
// =====================================================================

// Qt's QByteArray internal: pointer to QArrayData
// QArrayData: ref(4), size(4), alloc(4), [pad 4], offset(8)
// Data at: (char*)d + d->offset

extern void* _ZN18QCryptographicHash4hashERK10QByteArrayNS_9AlgorithmE(
    void *retval, const void *data, int method);

void* hooked_QCryptographicHash_hash(void *retval, const void *data, int method) {
  static const char *algo_names[] = {
    "MD4", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
    "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512", "KECCAK_224",
    "KECCAK_256", "KECCAK_384", "KECCAK_512", "BLAKE2b_512", "BLAKE2s_256"
  };
  const char *algo = (method >= 0 && method < 17) ? algo_names[method] : "UNKNOWN";

  msg_count++;
  fprintf(stderr, "\n[HOOK] >>> QCryptographicHash::hash algo=%d (%s) <<<\n", method, algo);

  // Extract input from QByteArray
  void *d = *(void **)data;
  int in_size = 0;
  const unsigned char *in_bytes = NULL;
  if (d) {
    in_size = *((int *)((char *)d + 4));
    long off = *(long *)((char *)d + 16);
    in_bytes = (const unsigned char *)((char *)d + off);
    fprintf(stderr, "[HOOK]   input (%d bytes):\n", in_size);
    hex_dump(stderr, in_bytes, in_size > 256 ? 256 : in_size);
  }

  if (logf) {
    fprintf(logf, "\n[%d] QCryptographicHash::hash algo=%d (%s)\n", msg_count, method, algo);
    if (in_bytes) {
      fprintf(logf, "  input (%d bytes):\n", in_size);
      hex_dump(logf, in_bytes, in_size > 256 ? 256 : in_size);
    }
  }

  void *result = _ZN18QCryptographicHash4hashERK10QByteArrayNS_9AlgorithmE(retval, data, method);

  // Extract output
  void *rd = *(void **)retval;
  if (rd) {
    int out_size = *((int *)((char *)rd + 4));
    long roff = *(long *)((char *)rd + 16);
    const unsigned char *out_bytes = (const unsigned char *)((char *)rd + roff);
    fprintf(stderr, "[HOOK]   output (%d bytes):\n", out_size);
    hex_dump(stderr, out_bytes, out_size > 64 ? 64 : out_size);
    if (logf) {
      fprintf(logf, "  output (%d bytes):\n", out_size);
      hex_dump(logf, out_bytes, out_size > 64 ? 64 : out_size);
    }
  }

  return result;
}

// =====================================================================
// DYLD_INTERPOSE declarations
// =====================================================================

// Socket hooks
DYLD_INTERPOSE(hooked_send, send)
DYLD_INTERPOSE(hooked_recv, recv)
DYLD_INTERPOSE(hooked_write, write)
DYLD_INTERPOSE(hooked_read, read)
DYLD_INTERPOSE(hooked_connect, connect)
DYLD_INTERPOSE(hooked_sendto, sendto)
DYLD_INTERPOSE(hooked_sendmsg, sendmsg)
DYLD_INTERPOSE(hooked_writev, writev)

// AES — all modes
DYLD_INTERPOSE(hooked_mbedtls_aes_setkey_enc, mbedtls_aes_setkey_enc)
DYLD_INTERPOSE(hooked_mbedtls_aes_setkey_dec, mbedtls_aes_setkey_dec)
DYLD_INTERPOSE(hooked_mbedtls_aes_crypt_ecb, mbedtls_aes_crypt_ecb)
DYLD_INTERPOSE(hooked_mbedtls_aes_crypt_cbc, mbedtls_aes_crypt_cbc)
DYLD_INTERPOSE(hooked_mbedtls_aes_crypt_cfb128, mbedtls_aes_crypt_cfb128)
DYLD_INTERPOSE(hooked_mbedtls_aes_crypt_ofb, mbedtls_aes_crypt_ofb)
DYLD_INTERPOSE(hooked_mbedtls_aes_crypt_ctr, mbedtls_aes_crypt_ctr)
DYLD_INTERPOSE(hooked_mbedtls_aes_crypt_xts, mbedtls_aes_crypt_xts)

// GCM
DYLD_INTERPOSE(hooked_mbedtls_gcm_setkey, mbedtls_gcm_setkey)
DYLD_INTERPOSE(hooked_mbedtls_gcm_crypt_and_tag, mbedtls_gcm_crypt_and_tag)
DYLD_INTERPOSE(hooked_mbedtls_gcm_starts, mbedtls_gcm_starts)
DYLD_INTERPOSE(hooked_mbedtls_gcm_update, mbedtls_gcm_update)

// CCM
DYLD_INTERPOSE(hooked_mbedtls_ccm_setkey, mbedtls_ccm_setkey)
DYLD_INTERPOSE(hooked_mbedtls_ccm_encrypt_and_tag, mbedtls_ccm_encrypt_and_tag)
DYLD_INTERPOSE(hooked_mbedtls_ccm_update, mbedtls_ccm_update)

// ChaCha20 / ChaChaPoly
DYLD_INTERPOSE(hooked_mbedtls_chacha20_crypt, mbedtls_chacha20_crypt)
DYLD_INTERPOSE(hooked_mbedtls_chacha20_update, mbedtls_chacha20_update)
DYLD_INTERPOSE(hooked_mbedtls_chachapoly_encrypt_and_tag, mbedtls_chachapoly_encrypt_and_tag)
DYLD_INTERPOSE(hooked_mbedtls_chachapoly_update, mbedtls_chachapoly_update)

// Generic cipher API
DYLD_INTERPOSE(hooked_mbedtls_cipher_setkey, mbedtls_cipher_setkey)
DYLD_INTERPOSE(hooked_mbedtls_cipher_crypt, mbedtls_cipher_crypt)
DYLD_INTERPOSE(hooked_mbedtls_cipher_auth_encrypt_ext, mbedtls_cipher_auth_encrypt_ext)

// Qt crypto
DYLD_INTERPOSE(hooked_QCryptographicHash_hash, _ZN18QCryptographicHash4hashERK10QByteArrayNS_9AlgorithmE)
