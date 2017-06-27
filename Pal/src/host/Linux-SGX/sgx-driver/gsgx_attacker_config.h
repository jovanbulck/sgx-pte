#ifndef GSGX_ATTACKER_CONFIG_H
#define GSGX_ATTACKER_CONFIG_H

#define CONFIG_SPY_MICRO            1
#define CONFIG_SPY_GCRY             0
#define CONFIG_SPY_GCRY_VERSION     175
//#define CONFIG_SPY_GCRY_VERSION     163

#define CONFIG_FLUSH_FLUSH          1
#define CONFIG_CLFLUSH_THRESHOLD    168
#define CONFIG_CLFLUSH_MAX          1000
#define CONFIG_FLUSH_RELOAD         1
#define CONFIG_RELOAD_THRESHOLD     200

#if CONFIG_SPY_MICRO
    #define CONFIG_EDBGRD_RIP       1
#else
    #define CONFIG_EDBGRD_RIP       0
#endif

#define CONFIG_DISABLE_CACHE        0
#define CONFIG_UNDERCLOCK_VICTIM    0
#define CONFIG_USE_KVM_IPI_HOOK     1

#endif
