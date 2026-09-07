#include<sys/ptrace.h>
#include<sys/types.h>
#include<unistd.h>
#include<sys/wait.h>
#include<string.h>
#include<stdlib.h>
#include<elf.h>
#include<stdio.h>

#ifdef __x86_64__
	#include<sys/user.h>
#elif __aarch64__
	#include<asm/ptrace.h>
	#include<sys/uio.h>
#endif

void step(pid_t pid);
void print_mem(pid_t pid);
void print_regs(pid_t pid);
int read_buf(char * buf,int x);
void breakpoint(pid_t pid);
char * arch;
unsigned long saved_instr;
unsigned long saved_addr;
int bp_set = 0;

__attribute__((constructor)) void arch_detect()
{
	arch = getenv("ARCH_DEBUG");
        if(arch == NULL)
        {
                printf("[+] Warning: ARCH_DEBUG not set.default: x86_64.\n");
                arch = "x86_64";
        }
}

void step(pid_t pid)
{
	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
}

void print_mem(pid_t pid)
{
	unsigned long addr;
        printf("Address: ");
        fflush(stdout);
        int ret = scanf("%lx",&addr);
        if(ret != 1)
        {
                printf("[+] Warning: unknown address.\n");
                return;
        }
	for(int i = 0;i < 8;i++)
	{
		unsigned long word = ptrace(PTRACE_PEEKDATA,pid,(void *)(addr + i*8),NULL);
		printf("%016lx: %016lx\n",addr + i*8,word);
	}
}

void print_regs(pid_t pid)
{
	if(!strcmp(arch,"x86_64"))
	{
#ifdef __x86_64__
		struct user_regs_struct regs;
		if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) < 0)
		{
			printf("[+] Ptrace GETREGS.\n");
			return;
		}
		printf("RIP: %016llx\n",regs.rip);
		printf("RSP: %016llx\n",regs.rsp);
		printf("RBP: %016llx\n",regs.rbp);
		printf("RAX: %016llx\n",regs.rax);
		printf("RDI: %016llx\n",regs.rdi);
		printf("RSI: %016llx\n",regs.rsi);
		printf("RDX: %016llx\n",regs.rdx);
		printf("RCX: %016llx\n",regs.rcx);
		printf("R8: %016llx\n",regs.r8);
		printf("R9: %016llx\n",regs.r9);
		printf("R10: %016llx\n",regs.r10);
		printf("R11: %016llx\n",regs.r11);
		printf("R12: %016llx\n",regs.r12);
		printf("R13: %016llx\n",regs.r13);
		printf("R14: %016llx\n",regs.r14);
		printf("R15: %016llx\n",regs.r15);
		printf("EFLAGS: %08llx\n",regs.eflags);
		printf("CS: %04llx\n",regs.cs);
		printf("SS: %04llx\n",regs.ss);
		return;
#endif
	}
	else 
	{
#ifdef __aarch64__
    		struct user_pt_regs regs;
    		struct iovec iov;
    		iov.iov_base = &regs;
    		iov.iov_len = sizeof(regs);
    		if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
		{
        		printf("[+] Ptrace GETREGSET.\n");
        		return;
    		}
    		printf("PC : %016llx\n", regs.pc);
    		printf("SP : %016llx\n", regs.sp);
    		printf("PSTATE: %016llx\n", regs.pstate);
    		printf("X0 : %016llx\n", regs.regs[0]);
    		printf("X1 : %016llx\n", regs.regs[1]);
    		printf("X2 : %016llx\n", regs.regs[2]);
    		printf("X3 : %016llx\n", regs.regs[3]);
    		printf("X4 : %016llx\n", regs.regs[4]);
    		printf("X5 : %016llx\n", regs.regs[5]);
    		printf("X6 : %016llx\n", regs.regs[6]);
    		printf("X7 : %016llx\n", regs.regs[7]);
    		printf("X8 : %016llx\n", regs.regs[8]);
    		printf("X9 : %016llx\n", regs.regs[9]);
    		printf("X10: %016llx\n", regs.regs[10]);
    		printf("X11: %016llx\n", regs.regs[11]);
    		printf("X12: %016llx\n", regs.regs[12]);
    		printf("X13: %016llx\n", regs.regs[13]);
    		printf("X14: %016llx\n", regs.regs[14]);
    		printf("X15: %016llx\n", regs.regs[15]);
    		printf("X16: %016llx\n", regs.regs[16]);
    		printf("X17: %016llx\n", regs.regs[17]);
    		printf("X18: %016llx\n", regs.regs[18]);
    		printf("X19: %016llx\n", regs.regs[19]);
    		printf("X20: %016llx\n", regs.regs[20]);
    		printf("X21: %016llx\n", regs.regs[21]);
    		printf("X22: %016llx\n", regs.regs[22]);
    		printf("X23: %016llx\n", regs.regs[23]);
    		printf("X24: %016llx\n", regs.regs[24]);
    		printf("X25: %016llx\n", regs.regs[25]);
    		printf("X26: %016llx\n", regs.regs[26]);
    		printf("X27: %016llx\n", regs.regs[27]);
    		printf("X28: %016llx\n", regs.regs[28]);
    		printf("X29: %016llx\n", regs.regs[29]); 
    		printf("X30: %016llx\n", regs.regs[30]);
		return;
#endif
	}
}

int read_buf(char * buf,int x)
{
	int n = read(0,buf,x-1);
	buf[n] = '\0';
	for(int i = 0;i < n;i++)
        {
		if(buf[i] == '\n')
		{
			buf[i] = '\0';
			break;
		}
   	}
	return n;
}

void breakpoint(pid_t pid)
{
	unsigned long bp;
	printf("Address: ");
	fflush(stdout);
	int ret = scanf("%lx",&bp);
	if(ret != 1)
	{
		printf("[+] Warning: unknown address.\n");
		return;
	}
	if(!strcmp(arch,"x86_64"))
	{
#ifdef __x86_64__
		unsigned long orign = ptrace(PTRACE_PEEKDATA,pid,(void *)bp,NULL);
		if(orign == -1)
		{
			printf("[+] Ptrace PEEKDATA.\n");
			return;
		}
		unsigned long tmp = orign & 0xFFFFFFFFFFFFFF00;
		unsigned long new = tmp | 0xCC;
		if(ptrace(PTRACE_POKEDATA,pid,(void *)bp,new) == 0)
		{
			bp_set = 1;
			saved_instr = orign;
			saved_addr = bp;
		}
		return;
#endif
	}
	else
	{
#ifdef __aarch64__
		unsigned long orign = ptrace(PTRACE_PEEKDATA,pid,(void *)bp,NULL);
		if(orign == -1)
		{
			printf("[+] Ptrace PEEKDATA.\n");
                        return;
		}
		unsigned long tmp = orign & 0xFFFFFFFF00000000;
		unsigned long new = tmp | 0xD4200000;
		if(ptrace(PTRACE_POKEDATA,pid,(void *)bp,new) == 0)
                {
                        bp_set = 1;
                        saved_instr = orign;
                        saved_addr = bp;
                }
                return;
#endif
	}
}

int main(int argc,char * argv[],char * envp[])
{
	if(argc != 2)
	{
		printf("Usage: %s <pid>\n",argv[0]);
		exit(1);
	}
	int ret;
	int status;
	char buf[4];
	pid_t pid = atoi(argv[1]);
	if(pid > 0)
	{
		if(ptrace(PTRACE_ATTACH,pid,NULL,NULL) < 0)
		{
			printf("[+] Error: Can't attach.\n");
			exit(1);
		}
		while(1)
		{
			pid_t wpid = waitpid(pid,&status,WUNTRACED);
			printf("Waiting for process %d...\n", pid);
			if(WIFEXITED(status))
			{
				printf("[+] EXIT.\n");
				exit(1);
			}
			else if(WIFSIGNALED(status))
			{
				printf("[+] Signal interrupt.\n");
				exit(1);
			}
			else if(WIFSTOPPED(status))
			{
				int sig = WSTOPSIG(status);
				print_regs(pid);
				while(1)
				{
					printf("(debugger) ");
					fflush(stdout);
 	                               	int n = read_buf(buf,4);
                                       	if(n <= 0)
                                	{
                                       		printf("[+] Warning: Length failed.\n");
						continue;
                               		}
					if(!strcmp(buf,"ni"))
					{
						step(pid);
						break;
					}
					else if(!strcmp(buf,"b"))
					{
						breakpoint(pid);
					}
					else if(!strcmp(buf,"r"))
					{
						if(bp_set == 0)
						{
							ptrace(PTRACE_CONT,pid,NULL,NULL);
							break;
						}
						if(!strcmp(arch,"x86_64"))
                                        	{
#ifdef __x86_64__
                                               		struct user_regs_struct regs;
                                               		ptrace(PTRACE_GETREGS,pid,NULL,&regs);
                                               		unsigned long current_rip = regs.rip;
                                               		if(current_rip - 1 == saved_addr)
                                               		{
                                                       		ptrace(PTRACE_POKEDATA,pid,(void *)saved_addr,(void *)saved_instr);
                                                       		regs.rip = saved_addr;
                                                      		ptrace(PTRACE_SETREGS,pid,NULL,&regs);
                                                       		ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL);
								pid_t wpid_2 = waitpid(pid,NULL,0);
								unsigned long new_instr = saved_instr & 0xFFFFFFFFFFFFFF00 | 0xCC;
                                                       		ptrace(PTRACE_POKEDATA,pid,saved_addr,(void *)new_instr);
                                               		}
#endif
                                       		}
                                       		else
                                       		{
#ifdef __aarch64__
							struct user_pt_regs regs;
							struct iovec iov;
							iov.iov_base = &regs;
							iov.iov_len = sizeof(regs);
                                                        if(ptrace(PTRACE_GETREGSET,pid,NT_PRSTATUS,&iov) < 0)
							{
								printf("[+] Ptrace GETREGSET.\n");
							}
                                                        unsigned long current_pc = regs.pc;
                                                        if(current_pc - 4 == saved_addr)
                                                        {
                                                        	ptrace(PTRACE_POKEDATA,pid,(void *)saved_addr,(void *)saved_instr);
                                                                regs.pc = saved_addr;
                                                                ptrace(PTRACE_SETREGSET,pid,NT_PRSTATUS,&iov);
                                                                ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL);
                                                                pid_t wpid_2 = waitpid(pid,NULL,0);
                                                                unsigned long new_instr = (saved_instr & 0xFFFFFFFF00000000) | 0xD4200000;
                                                                ptrace(PTRACE_POKEDATA,pid,saved_addr,(void *)new_instr);
                                                        }
#endif
							ptrace(PTRACE_CONT,pid,NULL,NULL);
							break;
						}
					}
					else if(!strcmp(buf,"p"))
					{
						print_mem(pid);
					}
					else if(!strcmp(buf,"re"))
					{
						print_regs(pid);
					}
					else if(!strcmp(buf,"q"))
					{
						printf("[+] Detach.\n");
						ptrace(PTRACE_DETACH,pid,NULL,NULL);
						exit(0);
					}
					else
					{
						printf("[+] Warning: unknown cmd.\n");
                                              	continue;
					}
				}	
			}
		}
	}
	else
	{
		printf("[+] Error: Invaild PID.\n");
		exit(1);
	}
	return 0;
}
