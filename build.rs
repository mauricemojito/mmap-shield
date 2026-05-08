fn main() {
    cc::Build::new()
        .file("csrc/sigsetjmp_shim.c")
        .compile("sigsetjmp_shim");
}
