/* QEMU/read-only capability probe using the exact shared progress helper. */
typedef unsigned size_t;
typedef void FILE;
extern FILE *fopen(const char *,const char *);
extern int fprintf(FILE *,const char *,...);
extern int fflush(FILE *);
extern int fclose(FILE *);
extern int snprintf(char *,size_t,const char *,...);
extern int taskDelay(int);
extern int sysClkRateGet(void);
static int theme_progress_begin(void);
static int theme_progress_step(const char *);
static int theme_progress_percent(unsigned);
static int theme_progress_finish(int,const char *);
int smeg_theme_progress_probe(void)
{
    if(theme_progress_begin()){
        FILE *f=fopen("/bd0/THEME_STATUS.TXT","wb");
        if(f){fprintf(f,"FAILED\nUI preflight failed\n");fclose(f);}
        return -1;
    }
#ifdef THEME_PROGRESS_PERCENT_DEMO
    {
        unsigned i;static const unsigned values[]={0,25,50,75,100};
        for(i=0;i<sizeof(values)/sizeof(values[0]);++i){
            char message[48];
            snprintf(message,sizeof(message),"UI demo %u%% - no source reads",values[i]);
            if(theme_progress_step(message) || theme_progress_percent(values[i]))
                return theme_progress_finish(-1,"FAILED - native progress API");
            taskDelay(sysClkRateGet()*8);
        }
    }
#else
    theme_progress_step("Checking USB 1/2");taskDelay(sysClkRateGet()*8);
#endif
#ifdef THEME_PROGRESS_FAIL_TEST
    return theme_progress_finish(-63,"FAILED - test only");
#else
    return theme_progress_finish(0,"DONE - TEST ONLY");
#endif
}
#include "theme_install_progress.h"
