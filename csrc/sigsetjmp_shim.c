#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Protected execution via sigsetjmp/siglongjmp.
 *
 * sigsetjmp MUST be called from a function that remains on the stack
 * when siglongjmp fires. Wrapping sigsetjmp in a helper and returning
 * its result to Rust does NOT work — siglongjmp would return into a
 * dead stack frame.
 *
 * Solution: the C function calls sigsetjmp, then calls the Rust
 * function pointer. siglongjmp returns into THIS function, which
 * is still alive on the stack.
 */

/* Rust callback type: takes a void* context, returns a void* result. */
typedef void* (*rust_callback_fn)(void *ctx);

/*
 * Execute `callback(ctx)` with sigsetjmp/siglongjmp protection.
 *
 * - env:      per-thread sigjmp_buf (must persist for siglongjmp)
 * - callback: function pointer to the Rust closure trampoline
 * - ctx:      opaque pointer passed through to callback
 * - out:      receives the callback return value on success
 *
 * Returns 0 on normal completion (callback ran, *out is set).
 * Returns non-zero if siglongjmp jumped back (SIGBUS caught).
 */
int mmap_guard_protected_call(
    sigjmp_buf env,
    rust_callback_fn callback,
    void *ctx,
    void **out
) {
    int r = sigsetjmp(env, 1);
    if (r != 0) {
        return r;
    }
    *out = callback(ctx);
    return 0;
}

_Noreturn void mmap_guard_siglongjmp(sigjmp_buf env, int val) {
    siglongjmp(env, val);
}

size_t mmap_guard_sigjmp_buf_size(void) {
    return sizeof(sigjmp_buf);
}
