#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/fs.h>  
#include <asm/uaccess.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

SYSCALL_DEFINE3(2017510055, char *, arg1, char *, arg2, char *, retValueP){
    int retValueI = -1;
    char * karg1 = (char *)kmalloc(sizeof(arg1) + 1, GFP_KERNEL);
    char * karg2 = (char *)kmalloc(sizeof(arg2) + 1, GFP_KERNEL);

    if (copy_from_user(karg1, arg1, strlen(arg1)+1) == 0)
    {
        if (strcmp(karg1, "-all") == 0){
            char * str = (char *)kmalloc(sizeof(char) * 50, GFP_KERNEL);
            char * retStr = (char *)kmalloc(sizeof(char) * 10000, GFP_KERNEL);
	        struct task_struct *task;
            int uid;
            for_each_process(task){   
                uid = __kuid_val(task->cred->uid);
                sprintf(str ,"Name: %s PID: [%d] UID: [%d] PPID: [%d] State: [%ld]\n", task->comm, task->pid, uid, task_ppid_nr(task), task->state);
                strncat(retStr, str, strlen(str));
            };
            retValueI = copy_to_user(retValueP, retStr, strlen(retStr)+1);
        }   
        if (copy_from_user(karg2, arg2, strlen(arg2)+1) == 0){
            if (strcmp(karg1, "-p") == 0){
                struct file *f;
                mm_segment_t fs;
                char buffer[128];
                int i;
                for(i = 0 ; i < 128 ; i++)
                    buffer[i] = 0;
                char path[25];
                strcpy(path,"/proc/");
                strcat(path,karg2);
                strcat(path,"/cmdline");
                f = filp_open(path, O_RDONLY, 0);
                if (f == NULL)
                    printk(KERN_ALERT "File could not found!\n");
                else {
                    fs = get_fs();
                    set_fs(get_ds());
                    f->f_op->read(f, buffer, 128, &f->f_pos);
                    set_fs(fs);
                    char comm[50];
                    char str[100];
                    sscanf(buffer, "%s", comm);
                    if (comm[0] == '\0'){
                        sprintf(str, "PID : %s\tcmdline : NULL\n", karg2);
                    }
                    else {
                        sprintf(str, "PID : %s\tcmdline : %s\n", karg2, buffer);  
                    }
                    retValueI = copy_to_user(retValueP,str,strlen(str)+1);
                }
                filp_close(f,NULL);
            }
            else if (strcmp(arg1, "-k") == 0) {
                long pid;
                char str[50];
                if (kstrtol(arg2, 10, &pid) == 0) {
                    if(kill_pid(find_vpid(pid),SIGKILL,1) == 0) {
                        sprintf(str, "Process %ld was killed...\n", pid);
                        retValueI = copy_to_user(retValueP,str,strlen(str)+1);
                    }
                }
            }
        }
    }
    return retValueI;
}
