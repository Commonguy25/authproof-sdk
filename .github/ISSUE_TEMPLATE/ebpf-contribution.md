# eBPF Kernel Module — Help Wanted

## What's needed
A production-safe eBPF LSM module that enforces AuthProof 
delegation receipts at the kernel level.

## Specific hooks required
- security_file_open
- security_socket_connect  
- security_task_execve
- cgroup attach points

## How it works
1. TEE injects signed capability token into process context via prctl
2. eBPF LSM validates token on every relevant syscall
3. No valid token or scope violation = immediate kernel deny
4. Pairs with existing TEEAttestation and PreExecutionVerifier

## Reference implementations
- Tetragon (Cilium) — syscall-level enforcement
- Falco + KubeArmor — eBPF security at scale
- eBPF Foundation LSM samples

## Requirements
- CO-RE eBPF + BTF — no custom kernel modules
- Kernel 5.8+ BPF LSM support
- Must pass eBPF verifier cleanly
- Security review required before merge

## Contact
Open this issue to discuss. Looking for engineers with 
eBPF LSM experience preferably from Isovalent, Red Canary,
or similar.
