    .text
    .globl _start
    .type _start, @function
_start:
    movq %rsp, %rdi
    andq $-16, %rsp
    call kzt_guest_perf_main
    movl %eax, %edi
    movl $60, %eax
    syscall
    hlt
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
