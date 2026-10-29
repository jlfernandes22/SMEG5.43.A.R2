/* One entry, one original-database export, ordered resource/preview/flag steps.
 * Experimental: validate this exact module on the stock two-theme QEMU seed.
 * No browser, network, binary replacement or automatic reboot is included.
 */
#define SMEG_EMULATOR_ONLY_SET_WEB 1
#define smeg_emulator_set_web smeg_complete_theme_install
#include "usb_backup_readonly.c"
#undef smeg_emulator_set_web
#undef SMEG_EMULATOR_ONLY_SET_WEB
#ifdef SMEG_NATIVE_THEME_PROGRESS
static int theme_progress_begin(void);
static int theme_progress_step(const char *);
static int theme_progress_percent(unsigned);
static int theme_progress_detail(const char *);
static int theme_progress_finish(int,const char *);
static int complete_progress_stage(const char *,unsigned);
static int complete_progress_begin(const char *,unsigned,unsigned,unsigned);
static int complete_progress_advance(unsigned);
static int complete_progress_flush(void);
static int complete_progress_failed(void);
static void complete_progress_destructive(void);
static int complete_source_attempt(const char *,unsigned);
static int complete_source_bytes(const char *,unsigned,unsigned,unsigned);
static int complete_source_result(const char *,unsigned,unsigned,unsigned,int,unsigned);
#define RESOURCE_PROGRESS_STAGE(message,percent) complete_progress_stage(message,percent)
#define RESOURCE_PROGRESS_BEGIN(message,low,high,total) complete_progress_begin(message,low,high,total)
#define RESOURCE_PROGRESS_ADD(bytes) complete_progress_advance(bytes)
#define RESOURCE_PROGRESS_FLUSH() complete_progress_flush()
#define RESOURCE_PROGRESS_FAILED() complete_progress_failed()
#define RESOURCE_PROGRESS_DESTRUCTIVE() complete_progress_destructive()
#define RESOURCE_CHECK_PROGRESS(path,attempt) complete_source_attempt(path,attempt)
#define RESOURCE_CHECK_BYTES(path,attempt,count,expected) complete_source_bytes(path,attempt,count,expected)
#define RESOURCE_CHECK_RESULT(path,attempt,count,expected,matched,consecutive) complete_source_result(path,attempt,count,expected,matched,consecutive)
#endif
#define SMEG_BACKUP_INCLUDED_EXTERNALLY 1
#include "usb_install_theme_resources_sandbox.c"
#include "usb_theme_previews_sandbox.c"
#ifdef SMEG_COMPLETE_REGISTER_CATALOGUE
#include "usb_set_theme_catalogue_sandbox.c"
#endif
#ifdef SMEG_COMPLETE_REFRESH_CATALOGUE
#define SMEG_CATALOGUE_MARKER_ONLY 1
#include "usb_refresh_theme_catalogue_sandbox.c"
#endif

static int complete_close_log(FILE **f)
{
    int bad=ferror(*f)!=0;
    if(fflush(*f))bad=1;
    if(fclose(*f))bad=1;
    *f=0;return bad?-1:0;
}
static int smeg_complete_theme_steps(void);
#ifdef SMEG_NATIVE_THEME_PROGRESS
#include "theme_install_progress.h"
/* Overall percentages are phase weights, not an invented NAND byte counter.
 * Only measured loops advance within a byte phase. Native erase/write calls
 * hold their milestone until return. Samples are logged only with all bulk
 * USB source/backup streams closed. Presentation errors are deferred once a
 * destructive native call has started; rebuilding always takes precedence. */
struct CompleteProgressSample {const char *stage;unsigned percent,done,total;};
static struct CompleteProgressSample complete_samples[192];
static unsigned complete_sample_count,complete_flushed,complete_percent;
static unsigned complete_low,complete_high,complete_total,complete_done,complete_source_count;
static const char *complete_stage="Prerequisites",*complete_source_path;
static int complete_ui_bad,complete_destructive_started,complete_retry_added;
static int complete_progress_error(void)
{complete_ui_bad=1;return complete_destructive_started?0:-1;}
static unsigned complete_threshold(unsigned total,unsigned part,unsigned span)
{return (total/span)*part+((total%span)*part+span-1)/span;}
static int complete_progress_publish(int force)
{
    unsigned next=complete_percent;char message[88];
    if(complete_ui_bad)return complete_destructive_started?0:-1;
    while(complete_total && next<complete_high &&
          complete_done>=complete_threshold(complete_total,next+1-complete_low,complete_high-complete_low))++next;
    if(!force && next==complete_percent)return 0;
    if(complete_total)snprintf(message,sizeof(message),"%s %u%% %u/%u KiB",complete_stage,next,complete_done/1024,complete_total/1024);
    else snprintf(message,sizeof(message),"%s (%u%%)",complete_stage,next);
    if(theme_progress_detail(message)||theme_progress_percent(next))return complete_progress_error();
    complete_percent=next;
    if(complete_sample_count>=192)return complete_progress_error();
    complete_samples[complete_sample_count++]=(struct CompleteProgressSample){complete_stage,next,complete_done,complete_total};
    return 0;
}
static int complete_progress_flush(void)
{
    unsigned n;int bad=0;FILE *f;
    if(complete_ui_bad)return complete_destructive_started?0:-1;
    if(complete_flushed==complete_sample_count)return 0;
    f=fopen("/bd0/SMEG_BACKUP/theme-progress.txt","ab");if(!f)return complete_progress_error();
    for(n=complete_flushed;n<complete_sample_count;++n){const struct CompleteProgressSample *p=&complete_samples[n];
        if(fprintf(f,"INSTALL_PROGRESS percent=%u done=%u total=%u measured=%u stage=%s\n",p->percent,p->done,p->total,p->total!=0,p->stage)<0)bad=1;
    }
    if(ferror(f))bad=1;
    if(fflush(f))bad=1;
    if(fclose(f))bad=1;
    if(bad)return complete_progress_error();
    complete_flushed=complete_sample_count;return 0;
}
static int complete_progress_stage(const char *message,unsigned percent)
{
    if(complete_progress_flush())return -1;
    if(complete_ui_bad)return complete_destructive_started?0:-1;
    if(percent<complete_percent || percent>99)return complete_progress_error();
    complete_stage=message;complete_low=complete_high=percent;complete_total=complete_done=0;complete_percent=percent;
    if(theme_progress_step(message))return complete_progress_error();
    return complete_progress_publish(1);
}
static int complete_progress_begin(const char *message,unsigned low,unsigned high,unsigned total)
{
    if(complete_progress_stage(message,low))return -1;
    if(complete_ui_bad)return complete_destructive_started?0:-1;
    if(!total || low>=high || high>99)return complete_progress_error();
    complete_low=low;complete_high=high;complete_total=total;complete_done=complete_source_count=0;
    complete_source_path=0;complete_retry_added=0;return complete_progress_publish(1);
}
static int complete_progress_advance(unsigned count)
{
    if(complete_ui_bad)return complete_destructive_started?0:-1;
    if(count>complete_total-complete_done)return complete_progress_error();
    complete_done+=count;return complete_progress_publish(0);
}
static int complete_source_attempt(const char *path,unsigned attempt)
{
    char message[64];
    if(path!=complete_source_path){complete_source_path=path;complete_retry_added=0;}
    complete_source_count=0;
    if(complete_progress_flush())return -1;
    if(complete_ui_bad)return complete_destructive_started?0:-1;
    snprintf(message,sizeof(message),"%s read %u/3",complete_stage,attempt);
    if(theme_progress_step(message))return complete_progress_error();
    return 0;
}
static int complete_source_bytes(const char *path,unsigned attempt,unsigned count,unsigned expected)
{
    unsigned delta;(void)attempt;
    if(path!=complete_source_path || count<complete_source_count)return complete_progress_error();
    if(count>expected)count=expected;
    delta=count-complete_source_count;complete_source_count=count;return complete_progress_advance(delta);
}
static int complete_source_result(const char *path,unsigned attempt,unsigned count,unsigned expected,int matched,unsigned consecutive)
{
    (void)path;(void)count;(void)consecutive;
    if(!matched && attempt<3 && !complete_retry_added){
        if(expected>~0u-complete_total)return complete_progress_error();
        complete_total+=expected;complete_retry_added=1;
    }
    return complete_progress_flush();
}
static int complete_progress_failed(void){return complete_ui_bad;}
static void complete_progress_destructive(void){complete_destructive_started=1;}
#endif
int smeg_complete_theme_install(void)
{
    int status;
#ifdef SMEG_NATIVE_THEME_PROGRESS
    if(theme_progress_begin())return -158;
#endif
    status=smeg_complete_theme_steps();
#ifdef SMEG_NATIVE_THEME_PROGRESS
    if(!status && (complete_progress_flush() || complete_progress_failed() ||
        theme_progress_detail("Themes verified - restart after USB removal") || theme_progress_percent(100)))status=-159;
    if(theme_progress_finish(status,status?"FAILED - check USB log":"DONE - remove USB") && !status)status=-159;
#endif
    return status;
}

static int smeg_complete_theme_steps(void)
{
    unsigned i;
    FILE *log = fopen("/bd0/SMEG_BACKUP/complete-themes.txt", "wb");
    int status = -100;
    if (!log) return status;
    if(RESOURCE_PROGRESS_STAGE("Check prerequisites",0)){status=-160;goto done;}
#ifdef SMEG_COMPLETE_REGISTER_CATALOGUE
    for (i = 0; i < 13; ++i)
        if (common_catalogue_hash((const void *)common_api[i].address,64) != common_api[i].hash) { status=-137; goto done; }
    for (i = 0; i < 2; ++i)
        if (common_catalogue_hash((const void *)common_bsp[i].address,64) != common_bsp[i].hash) { status=-137; goto done; }
#endif
    /* Check ALL remaining APIs and source JPEGs before resource-bank erasure. */
    for (i = 0; i < 10; ++i)
        if (fingerprint((const void *)warm_api_checks[i].address, warm_api_checks[i].bytes)
                != warm_api_checks[i].hash) { status = -101; goto done; }
    for (i = 0; i < 2; ++i)
        if (fingerprint((const void *)preview_fs_api[i].address, 64)
                != preview_fs_api[i].hash) { status = -102; goto done; }
    {
    unsigned preview_bytes=0;
    for(i=0;i<6;++i)preview_bytes+=theme_previews[i].bytes;
    if(RESOURCE_PROGRESS_BEGIN("Check previews",0,5,preview_bytes)){status=-160;goto done;}
    for (i = 0; i < 6; ++i) {
        const struct ThemePreview *p = &theme_previews[i];
        FILE *f = fopen(p->source, "rb");
        unsigned count = 0, h = 2166136261u; size_t n, j;
        if (!f) { status = -103; goto done; }
        while ((n = fread(buffer, 1, sizeof(buffer), f)) != 0) {
            for (j = 0; j < n; ++j) h = (h ^ buffer[j]) * 16777619u;
            count += n;
            if(RESOURCE_PROGRESS_ADD(n)){status=-160;break;}
        }
        if(status!=-160)status = ferror(f) || count != p->bytes || h != p->hash ? -104 : 0;
        if (fclose(f)) status = -104;
        if (status) goto done;
    }
    if(RESOURCE_PROGRESS_FLUSH()){status=-160;goto done;}
    }
#ifdef SMEG_COMPLETE_REFRESH_CATALOGUE
    status = smeg_check_theme_cache_marker();
    if (status) goto done;
#endif
    fprintf(log, "PREFLIGHT additional APIs and all preview sources verified\n");
    if (complete_close_log(&log)) return -105;
    log = 0;
    /* Do not keep an additional USB log open across native DOSFS bulk I/O. */
    status = smeg_install_theme_resources();
    log = fopen("/bd0/SMEG_BACKUP/complete-themes.txt", "ab");
    if (!log) return -106;
    fprintf(log, "RESOURCES status=%d\n", status); fflush(log);
    if (status) goto done;
    if (complete_close_log(&log)) return -105;
    log = 0;
    /* Publish availability only after all six previews are present. */
    RESOURCE_PROGRESS_STAGE("Copy previews",92);
    if(RESOURCE_PROGRESS_FAILED()){status=-160;goto done;}
    status = smeg_copy_new_theme_previews();
    log = fopen("/bd0/SMEG_BACKUP/complete-themes.txt", "ab");
    if (!log) return -106;
    fprintf(log, "PREVIEWS status=%d\n", status); fflush(log);
    if (status) goto done;
    if (complete_close_log(&log)) return -105;
    log = 0;
    RESOURCE_PROGRESS_STAGE("Enable themes",94);
    if(RESOURCE_PROGRESS_FAILED()){status=-160;goto done;}
    status = smeg_emulator_extra_theme_flags();
    log = fopen("/bd0/SMEG_BACKUP/complete-themes.txt", "ab");
    if (!log) return -106;
    fprintf(log, "FLAGS status=%d\n", status);
#ifdef SMEG_COMPLETE_REGISTER_CATALOGUE
    if (status) goto done;
    if (complete_close_log(&log)) return -105;
    log = 0;
    RESOURCE_PROGRESS_STAGE("Register themes",96);
    if(RESOURCE_PROGRESS_FAILED()){status=-160;goto done;}
    status = smeg_set_theme_catalogue();
    log = fopen("/bd0/SMEG_BACKUP/complete-themes.txt", "ab");
    if (!log) return -106;
    fprintf(log, "NATIVE_THEME_CATALOGUE status=%d\n", status);
#endif
#ifdef SMEG_COMPLETE_REFRESH_CATALOGUE
    if (status) goto done;
    if (complete_close_log(&log)) return -105;
    log = 0;
    RESOURCE_PROGRESS_STAGE("Finish catalogue",98);
    if(RESOURCE_PROGRESS_FAILED()){status=-160;goto done;}
    status = smeg_refresh_theme_catalogue();
    log = fopen("/bd0/SMEG_BACKUP/complete-themes.txt", "ab");
    if (!log) return -106;
    fprintf(log, "CATALOGUE_CACHE_INVALIDATION status=%d\n", status);
#endif
    if(!status && RESOURCE_PROGRESS_STAGE("Finalize receipts",99))status=-160;
    if(!status && RESOURCE_PROGRESS_FAILED())status=-160;
done:
    if(!log)log=fopen("/bd0/SMEG_BACKUP/complete-themes.txt","ab");
    if(log){
        fprintf(log, "COMPLETE_THEMES_RESULT status=%d\n", status);
        if (fflush(log) && !status) status = -105;
        if (fclose(log) && !status) status = -105;
    }else if(!status)status=-105;
    printf("SMEG_COMPLETE_THEMES_RESULT status=%d\n", status);
    return status;
}
