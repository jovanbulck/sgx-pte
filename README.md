# Introduction

This is the source code accompanying the paper "Telling Your Secrets Without
Page Faults: Stealthy Page Table-Based Attacks on Enclaved Execution" which
appears in the 26th USENIX security symposium. A copy of the paper is available
at <https://people.cs.kuleuven.be/~jo.vanbulck/usenix17.pdf>.

Van Bulck, J., Weichbrodt, N., Kapitza, R., Piessens, F., and Strackx, R.
Telling your secrets without page faults: Stealthy page table-based attacks on
enclaved execution. In 26th USENIX Security Symposium (2017), USENIX
Association.

# Paper Abstract

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

# Source Code Overview

We based our attack framework on on commit [#df4af24](https://github.com/jovanbulck/sgx-pte/commit/df4af2451dad05914b60ef87445dee219ccc74d1) from the upstream
[Graphene-SGX](https://github.com/oscarlab/graphene) project. Note that we use the environment variables `$GRAPHENE` and `$GRAPHENE_SGX` to refer to respectively the root directory containing the Graphene git directory and `$GRAPHENE/Pal/src/host/Linux-SGX/`.

 The following lists the major modifications:

* `$GRAPHENE_SGX/sgx_attacker.c`: untrusted user space runtime
   modifications to create and synchronize spy/victim threads.

* `$GRAPHENE_SGX/sgx-driver/gsgx_attacker_*`: untrusted gsgx kernel
   driver modifications implementing attacker thread to spy on victim Page
   Table Entries (PTEs).

* `$GRAPHENE/LibOS/shim/test/apps/hello`: simple microbenchmark application to quantify
   Inter Processor Interrupt (IPI) latency in terms of the number of instructions
   executed by the enclave after accessing a page, and before being interrupted
   by the kernel.

* `$GRAPHENE/LibOS/shim/test/apps/libgcrypt/`: minimal client application and Graphene
   manifest to run unmodified Libgcrypt v1.6.3/v1.7.5 libraries in an SGX enclave.

# Build and Run

## Building Graphene

Build PAL (partly trusted/untrusted), Graphene SGX driver (untrusted), and
libOS (trusted) (<https://github.com/oscarlab/graphene/wiki/SGX-Quick-Start>).


0. Prepare a signing key:

```bash
    $ cd $GRAPHENE_SGX/signer
    $ openssl genrsa -3 -out enclave-key.pem 3072
```

1. Build PAL/libOS (with debug output enabled):

```bash
    $ cd $GRAPHENE/Pal/src/
    $ make SGX=1 DEBUG=1
    $ cd $GRAPHENE/LibOS/
    $ make SGX=1 DEBUG=1
```

2. Make sure you have a working [linux-sgx-driver](<https://github.com/01org/linux-sgx-driver/>).
   The microbenchmark code requires the patches in the
   `$GRAPHENE_SGX/sgx-driver/isgx-patches/` directory,
   so as to be able to read the memory of a debug enclave from the gsgx driver.
   We applied the patches to isgx v1.7 (commit [#51b2884](https://github.com/01org/linux-sgx-driver/commit/51b2884d4c3ac0f7bfa5b46ff529496e360e5ef1)).
   Note that EDBGRD is only used to quantify the latency of Inter Processor Interrupts
   by retrieving the stored instruction pointer of an interrupted
   microbenchmark debug enclave.

3. Build and load gsgx driver (including our attacker spy code):

```bash
    $ cd $GRAPHENE_SGX/sgx-driver/
    $ make load
```

Graphene somehow wants to map enclaves in low virtual memory (from 0x0).
This has to be explicitly allowed (<https://wiki.debian.org/mmap_min_addr>);
`make load` should automatically take care of this.

## Spying on Enclaved Application Binaries

0. Before building Graphene untrusted runtime (step 1/3 above):

   * `$GRAPHENE_SGX/sgx_attacker.c`: configure spy/victim pinned CPU numbers
   * `$GRAPHENE_SGX/sgx-driver/gsgx_attacker_config.h`: configure spy thread options
   * `$GRAPHENE_SGX/sgx-driver/gsgx_attacker_pte_set.c`: configure addresses to monitor

1. Build the trusted PAL, application binary and untrusted loader, based on the
   configuration in the manifest. Also signs the enclaved binary and
   supporting libOS to make them ready for shipment.

```bash
    $ cd $GRAPHENE/LibOS/shim/test/apps/hello
    $ make SGX=1 # DEBUG=1 for dmesg-style debug output
```

2. Get the enclave launch token from Intel aesmd service. (Keep on restarting
   the aesmd service in case it crashes.)

```bash
    $ make SGX_RUN=1
    $ sudo service aesmd status # restart/stop/start as needed
```

3. Launch enclaved application binary.

```bash
    $ ../pal_loader helloworld
```

4. Retrieve the spy results from the gsgx driver:

```bash
    $ dmesg | tail
```

## Attacking Libgcrypt EdDSA (`CONFIG_SPY_GCRY`)

Proceed as follows:

0. `$GRAPHENE_SGX/sgx-driver/sgx_attacker_config.h`: configure spy thread
before building untrusted Graphene runtime:

   * Enable `CONFIG_SPY_GCRY` and disable `CONFIG_SPY_MICRO`.
   * Choose to monitor trigger pages with either the A/D or Flush+Flush technique.
     Likewise, PTE sets on IPIs can be constructed with either A/D or
     Flush+Reload. Adjust cache timing threshold values as needed.
   * Select victim Libgcrypt version (v1.6.3 or v1.7.5).

1. Build unmodified Libgcrypt binaries:

```bash
    $ cd $GRAPHENE/LibOS/shim/test/apps/libgcrypt/libgcrypt-ecc/
    $ make src
```

2. Build simple client application by setting `$GCRY_VERSION` and `$MAIN`
   accordingly in the Makefile.

```bash
    $ make SGX=1
    $ make SGX_RUN=1
```

3. Run the application, extract side-channel measurements, and run the
   post-processing script to extract the 512-bit EdDSA key:

```bash
    $ ./run.sh
```

## IPI Latency Microbenchmarks (`CONFIG_SPY_MICRO`)

The helloworld binary (`$GRAPHENE/LibOS/shim/test/apps/hello/`)
includes asm code that can be used to quantify Inter
Processor Interrupt (IPI) latency in terms of the number of instructions
executed by the enclave after accessing a page, and before being interrupted
by the kernel.

Proceed as follows:

0. Before building untrusted Graphene runtime:

   * `$GRAPHENE_SGX/sgx_attacker.c`: enable`SYSDUMP_CONTROL_SPY`.
   * `$GRAPHENE_SGX/sgx-driver/sgx_attacker_config.h`:
      includes precompiler options to investigate the effect of
      a.o, disabling the cache on the enclave CPU (CR0.CD) and sending the IPI
      directly from custom kernel asm code. Also enable `CONFIG_SPY_MICRO` and
      disable `CONFIG_SPY_GCRY` here.
   * `$GRAPHENE_SGX/sgx-driver/gsgx_attacker_pte_set.c`:
      Configure the address to monitor `&a` and the expected instruction pointer
      address `&asm_microbenchmark_slide`.

1. x86 instruction type and the landing slide length for the microbenchmark
   experiment can be configured in the `build_asm` Python script.

2. Finally, run the enclaved binary in Graphene, retrieve the measurements
   from the gsgx driver, and parse them as follows:

```bash
    $ ./parse_microbenchmarks.sh
```

   This creates a file measurements.txt and dumps basic statistics (median,
   mean, stddev) on stdout using R. Also, a histogram of the distribution is
   created in plot.pdf (using gnuplot).

**Note:** the raw microbenchmark data used to generate Table 1 in the paper can
be found in the `$GRAPHENE/LibOS/shim/test/apps/hello/paper-data` directory.

# License

The code base is based on the Graphene-SGX project, which is itself licensed
under GPLv3 (<https://github.com/oscarlab/graphene/issues/1>). Libgcrypt is
available under the LGPL license
(<https://gnupg.org/related_software/libgcrypt/>).

All our attacker code extensions are equally licensed as free software, under
the GPLv3 license.
