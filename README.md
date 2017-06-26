# Introduction

This is the code accompanying the paper "Telling Your Secrets Without Page Faults:
Stealthy Page Table-Based Attacks on Enclaved Execution" which appears in the
26th USENIX security symposium. A copy of the paper can be found at
<https://people.cs.kuleuven.be/~jo.vanbulck/usenix17.pdf>.

# Paper abstract

Protected module architectures, such as Intel SGX, enable strong trusted
computing guarantees for hardware-enforced enclaves on top a potentially
malicious operating system. However, such enclaved execution environments are
known to be vulnerable to a powerful class of controlled-channel attacks.
Recent research convincingly demonstrated that adversarial system software can
extract sensitive data from enclaved applications by carefully revoking access
rights on enclave pages, and recording the associated page faults. As a
response, a number of state-of-the-art defense techniques has been proposed
that suppress page faults during enclave execution.

This paper shows, however, that page table-based threats go beyond page faults.
We demonstrate that an untrusted operating system can observe enclave page
accesses without resorting to page faults, by exploiting other side-effects of
the address translation process. We contribute two novel attack vectors that
infer enclaved memory accesses from page table attributes, as well as from the
caching behavior of unprotected page table memory. We demonstrate the
effectiveness of our attacks by recovering EdDSA session keys with little to no
noise from the popular Libgcrypt cryptographic software suite.

# Build and Run

TODO: more detailed instructions will appear here soon...

# License

The code base is based on the Graphene-SGX project
<https://github.com/oscarlab/graphene>, which is itself licensed under GPLv3
(<https://github.com/oscarlab/graphene/issues/1>).
Libgcrypt (<https://gnupg.org/related_software/libgcrypt/>) is available under
the LGPL license.

All our attacker code extensions are equally licensed as free software, under
the GPLv3 license.
