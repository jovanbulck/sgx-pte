#ifndef SGX_ATTACK_H
#define SGX_ATTACK_H

void sgx_enter_victim(void);
void sgx_exit_victim(void);
void sgx_sysdump_victim(int val);

#endif /*SGX_ATTACK_H*/
