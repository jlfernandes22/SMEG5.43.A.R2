/* Native, temporary UI state only. No database, code or NAND patches.
 * The exact getter fingerprint guards the existing generic wstring layout.
 * Restore both original values after acknowledgement or a bounded timeout.
 */
#include "theme_progress_contract.h"
#ifndef THEME_PROGRESS_ACK_SECONDS
#define THEME_PROGRESS_ACK_SECONDS 300
#endif
static void *theme_ui_app,*theme_ui_popup,*theme_ui_busy,*theme_ui_complete,*theme_ui_progress_client;
static unsigned theme_ui_saved_busy[32],theme_ui_string[32],theme_ui_saved_complete_id;
static unsigned theme_ui_saved_progress,theme_ui_percent;
static int theme_ui_ready;
static unsigned theme_ui_state(void *popup)
{return *(volatile unsigned *)((unsigned char *)popup+0x28);}
static void theme_ui_trace(const char *event)
{
    FILE *f=fopen("/bd0/UI_TRACE.TXT","ab");
    if(f){fprintf(f,"%s busy=%u complete=%u complete_timer=%u\n",event,
        theme_ui_state(theme_ui_busy),theme_ui_state(theme_ui_complete),
        *(volatile unsigned *)((unsigned char *)theme_ui_complete+0x30));fclose(f);}
}
static unsigned theme_ui_hash(const void *v,unsigned n)
{const unsigned char *p=v;unsigned h=2166136261u;while(n--)h=(h^*p++)*16777619u;return h;}
static unsigned theme_ui_wstring_hash(void *text)
{
    unsigned n=((unsigned (*)(void *))0x0205fa84)(text);
    const void *data=((const void *(*)(void *))0x020606c8)(text);
    if(n>1024)return 0;
    return theme_ui_hash(data,n*4);
}
static int theme_ui_receipt(const char *state,const char *message)
{
    FILE *f=fopen("/bd0/THEME_STATUS.TXT","wb");int bad;
    if(!f)return -1;
    bad=fprintf(f,"%s\n%s\n",state,message)<0;
    if(fflush(f))bad=1;
    if(fclose(f))bad=1;
    return bad?-1:0;
}
static void theme_ui_text(unsigned id,const char *message)
{
    ((void (*)(void *,const char *))0x011334e8)(theme_ui_string,message);
    ((void (*)(void *,unsigned,const void *))0x028a91d0)(theme_ui_popup,id,theme_ui_string);
    ((void (*)(void *))0x01958d74)(theme_ui_string);
}
static void theme_ui_update_text(void *popup,unsigned control)
{
    ((void (*)(void *,unsigned,unsigned,void *))0x027348c8)
        (popup,control,0,(unsigned char *)popup+0x70);
}
/* Native UI messages only: safe to call while one source FILE is open.
 * Do not add USB receipts/logging or BCM progress setters to this callback. */
static int theme_progress_percent(unsigned percent)
{
    if(!theme_ui_ready || percent>100 || theme_ui_state(theme_ui_busy)!=2)return -1;
    ((void (*)(void *,unsigned,unsigned,unsigned))0x02734a80)
        (theme_ui_busy,1000,2,percent);
    theme_ui_percent=percent;
    return 0;
}
static int theme_progress_detail(const char *message)
{
    if(!theme_ui_ready || theme_ui_state(theme_ui_busy)!=2)return -1;
    theme_ui_text(9010,message);
    theme_ui_update_text(theme_ui_busy,2000);
    return 0;
}
static int theme_progress_step(const char *message)
{
    unsigned seconds=0;
    if(!theme_ui_ready)return -1;
    theme_ui_text(9010,message);
    /* Re-activation invokes the stock initializer, which resets the bar to
     * the updater client's value. Keep an existing popup and change its data. */
    if(!theme_ui_state(theme_ui_busy))((void (*)(unsigned))0x0288bee4)(9010);
    while(theme_ui_state(theme_ui_busy)!=2 && seconds<15){
        taskDelay(sysClkRateGet());++seconds;
    }
    if(theme_ui_state(theme_ui_busy)!=2)return -1;
    if(theme_progress_detail(message))return -1;
    if(theme_progress_percent(theme_ui_percent))return -1;
    return theme_ui_receipt("RUNNING",message);
}
static int theme_progress_begin(void)
{
    unsigned i,a;
    for(i=0;i<sizeof(progress_checks)/sizeof(progress_checks[0]);++i){
        unsigned actual=theme_ui_hash((const void *)progress_checks[i].address,64);
        if(actual!=progress_checks[i].hash){
            FILE *f=fopen("/bd0/UI_GUARD.TXT","wb");
            if(f){fprintf(f,"API_GUARD address=%08x expected=%08x actual=%08x\n",progress_checks[i].address,progress_checks[i].hash,actual);fclose(f);}
            return -1;
        }
    }
    a=*(volatile unsigned *)0x02fbf520;
    if(a<0x01000000u || a>0x0ff00000u-0x51294u)return -1;
    if(!*(volatile unsigned *)0x02fbfa6c)return -1;
    theme_ui_app=((void *(*)(void))0x0288b97c)();
    theme_ui_popup=((void *(*)(void *))0x028acd98)(theme_ui_app);
    theme_ui_busy=((void *(*)(void *,unsigned))0x028a8e8c)(theme_ui_popup,9010);
    theme_ui_complete=((void *(*)(void *,unsigned))0x028a8e8c)(theme_ui_popup,9014);
    if(!theme_ui_busy || !theme_ui_complete)return -1;
    theme_ui_progress_client=((void *(*)(void))0x02884c40)();
    if(!theme_ui_progress_client)return -1;
    theme_ui_saved_progress=((unsigned (*)(void *))0x026883e8)(theme_ui_progress_client);
    if(theme_ui_saved_progress>100)return -1;
    theme_ui_percent=0;
    ((void (*)(void *))0x020615a0)(theme_ui_saved_busy);
    ((void (*)(void *,void *))0x028ad890)(theme_ui_busy,theme_ui_saved_busy);
    ((void (*)(void *,unsigned *))0x028ad7d4)(theme_ui_complete,&theme_ui_saved_complete_id);
    theme_ui_ready=1;
    return theme_progress_step("Checking USB");
}
static int theme_progress_finish(int status,const char *message)
{
    unsigned seconds=0,complete_after=0,progress_after;int receipt,ui_ok;
    if(!theme_ui_ready)return -1;
    ((void (*)(void *,unsigned char))0x027360dc)(theme_ui_busy,0);
    theme_ui_trace("BUSY_CLOSE_REQUESTED");
    while(theme_ui_state(theme_ui_busy) && seconds<15){
        taskDelay(sysClkRateGet());++seconds;
    }
    /* Restore the hidden widget through the same native UI message route.
     * The BCM updater client's progress is never assigned by this helper. */
    ((void (*)(void *,unsigned,unsigned,unsigned))0x02734a80)
        (theme_ui_busy,1000,2,theme_ui_saved_progress);
    /* The stock resource's control500 expects a logical text ID. These IDs
     * are used by the original updater and map to localized success/failure
     * strings in both installed SQUARE and WARMLIGHT resources. */
    ((void (*)(void *,unsigned,unsigned))0x028a924c)(theme_ui_popup,9014,
        status?0x0033e336u:0x0033e334u);
    ((void (*)(unsigned))0x0288bee4)(9014);
    theme_ui_trace("COMPLETE_REQUESTED");
    /* ActivateUPGPopupTest queues a command. A zero state immediately after
     * submission means it has not been processed, not acknowledgement. */
    seconds=0;
    while(theme_ui_state(theme_ui_complete)!=2 && seconds<15){
        taskDelay(sysClkRateGet());++seconds;
    }
    theme_ui_trace("COMPLETE_ACTIVATION_WAITED");
    ui_ok=theme_ui_state(theme_ui_complete)==2;
    receipt=theme_ui_receipt(ui_ok?(status?"FAILED":"DONE"):"FAILED_UI",message);
    seconds=0;
    while(theme_ui_state(theme_ui_complete) && seconds<THEME_PROGRESS_ACK_SECONDS){
        /* The native timer only exists after the popup has reached state2. */
        ((void (*)(void *))0x02733578)(theme_ui_complete);
        taskDelay(sysClkRateGet());++seconds;
    }
    theme_ui_trace("COMPLETE_ACK_OR_TIMEOUT");
    ((void (*)(void *,unsigned char))0x027360dc)(theme_ui_complete,0);
    ((void *(*)(void *,const void *))0x02063394)((unsigned char *)theme_ui_busy+0x70,theme_ui_saved_busy);
    ((void (*)(void *,unsigned,unsigned))0x028a924c)(theme_ui_popup,9014,theme_ui_saved_complete_id);
    ((void (*)(void *,unsigned *))0x028ad7d4)(theme_ui_complete,&complete_after);
    progress_after=((unsigned (*)(void *))0x026883e8)(theme_ui_progress_client);
    {
        unsigned busy_before=theme_ui_wstring_hash(theme_ui_saved_busy),
            busy_after=theme_ui_wstring_hash((unsigned char *)theme_ui_busy+0x70);
        FILE *f=fopen("/bd0/UI_TRACE.TXT","ab");
        if(f){fprintf(f,"TEXT_RESTORED busy=%u complete=%u busy_before=%08x busy_after=%08x complete_before=%08x complete_after=%08x\n",
            busy_before==busy_after,theme_ui_saved_complete_id==complete_after,busy_before,busy_after,theme_ui_saved_complete_id,complete_after);fclose(f);}
    }
    {
        FILE *f=fopen("/bd0/UI_TRACE.TXT","ab");
        if(f){fprintf(f,"PROGRESS_RESTORED client_unchanged=%u before=%u after=%u last_shown=%u\n",
            theme_ui_saved_progress==progress_after,theme_ui_saved_progress,progress_after,theme_ui_percent);fclose(f);}
    }
    ((void (*)(void *))0x0206162c)(theme_ui_saved_busy);
    theme_ui_ready=0;
    return ui_ok?receipt:-1;
}
