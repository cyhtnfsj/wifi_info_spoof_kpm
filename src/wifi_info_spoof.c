// wifi_info_spoof.c — 完全自包含，无需 KernelPatch SDK 头文件
// 所有宏/类型/外部符号全部内联定义

// ── 基础类型 ────────────────────────────────────────────────
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

// ── KPM section 宏 ─────────────────────────────────────────
// 对应 ELF section：.kpm.info / .kpm.init / .kpm.exit / .kpm.ctl0
#define __used     __attribute__((used))
#define __sect(s)  __attribute__((section(s)))
#define __kpm_info __used __sect(".kpm.info")
#define __kpm_init __used __sect(".kpm.init")
#define __kpm_exit __used __sect(".kpm.exit")
#define __kpm_ctl0 __used __sect(".kpm.ctl0")

// 元数据（key=value，C 字符串 \0 做分隔）
#define KPM_NAME(n)    static char _n[] __kpm_info = "name=" n
#define KPM_VERSION(v) static char _v[] __kpm_info = "version=" v
#define KPM_AUTHOR(a)  static char _a[] __kpm_info = "author=" a
#define KPM_DESC(d)    static char _d[] __kpm_info = "description=" d
#define KPM_LIC(l)     static char _l[] __kpm_info = "license=" l

// 入口点指针类型
typedef int  (*init_fn_t)(const char *, const char *, void *);
typedef void (*exit_fn_t)(void *);
typedef long (*ctl_fn_t) (const char *, char *, long);

#define KPM_INIT(fn) static init_fn_t __init_ptr __kpm_init = (init_fn_t)(fn)
#define KPM_EXIT(fn) static exit_fn_t __exit_ptr __kpm_exit = (exit_fn_t)(fn)
#define KPM_CTL(fn)  static ctl_fn_t  __ctl_ptr  __kpm_ctl0 = (ctl_fn_t)(fn)

// ── hook_fargs_t（KernelPatch hook 回调参数）────────────────
typedef struct {
    u64 args[8];       // x0-x7 寄存器（函数入参）
    u64 local[8];      // 内部暂存
    u64 ret;           // 返回值（post-hook 里可改）
    int skip_origin;   // pre-hook 里设 1 可跳过原函数
} hook_fargs_t;

// ── 外部内核 / KSU API 声明 ─────────────────────────────────
extern unsigned long kallsyms_lookup_name(const char *name);
extern int  hook_wrap(unsigned long addr,
                      void (*pre) (hook_fargs_t *, void *),
                      void (*post)(hook_fargs_t *, void *),
                      void *udata);
extern int  unhook(unsigned long addr);
extern int  printk(const char *fmt, ...);

// ── 元数据 ──────────────────────────────────────────────────
KPM_NAME("wifi_info_spoof");
KPM_VERSION("1.0.0");
KPM_AUTHOR("cyhtnfsj");
KPM_DESC("Randomize SSID/BSSID for native WiFi reads");
KPM_LIC("GPL v2");

// ── 状态 ────────────────────────────────────────────────────
static char g_ssid[33];
static u8   g_bssid[6];
static u32  g_rng;

static unsigned long g_fn_essid = 0;
static unsigned long g_fn_ap    = 0;

// ── 工具 ────────────────────────────────────────────────────
static u32 krand(void)
{
    g_rng = g_rng * 1664525u + 1013904223u;
    return g_rng;
}

static char hc(u8 v)
{
    v &= 0xF;
    return (char)(v < 10 ? '0' + v : 'A' + v - 10);
}

static void km_cpy(void *d, const void *s, u64 n)
{
    u8 *dd = d; const u8 *ss = s;
    while (n--) *dd++ = *ss++;
}

static u64 km_len(const char *s)
{
    u64 n = 0; while (*s++) n++; return n;
}

// ── 随机化 ──────────────────────────────────────────────────
static const char * const PFX[] = {
    "CMCC-", "TP-LINK_", "Xiaomi_", "HUAWEI-", "ChinaNet-", "360WiFi-"
};

static void new_vals(void)
{
    const char *p = PFX[krand() % 6];
    u64 pl = km_len(p);
    km_cpy(g_ssid, p, pl);
    u32 r = krand();
    g_ssid[pl+0] = hc((u8)(r>>12));
    g_ssid[pl+1] = hc((u8)(r>>8));
    g_ssid[pl+2] = hc((u8)(r>>4));
    g_ssid[pl+3] = hc((u8)(r>>0));
    g_ssid[pl+4] = '\0';

    static const u8 fb[] = {0x02, 0x06, 0x0A, 0x0E};
    g_bssid[0] = fb[krand() % 4];
    u32 r2 = krand(), r3 = krand();
    g_bssid[1] = (u8)(r2>>0);  g_bssid[2] = (u8)(r2>>8);
    g_bssid[3] = (u8)(r2>>16); g_bssid[4] = (u8)(r3>>0);
    g_bssid[5] = (u8)(r3>>8);
}

// ── 被钩住的结构体（仅用到的字段）──────────────────────────
struct iw_pt { void *ptr; u16 len; u16 flags; };  // iw_point
struct saddr  { u16 fam; char data[14]; };          // sockaddr

// ── Post-hook: cfg80211_wext_giwessid ───────────────────────
// int fn(net_dev*, iw_info*, iw_point* x2, char* ssid_kbuf x3)
// wireless ext 框架自己把 ssid_kbuf copy_to_user，我们改 kbuf 即可
static void post_essid(hook_fargs_t *a, void *u)
{
    if ((int)a->ret) return;
    struct iw_pt *dp = (struct iw_pt *)a->args[2];
    char         *kb = (char *)a->args[3];
    u64 fl = km_len(g_ssid);
    km_cpy(kb, g_ssid, fl);
    dp->len = (u16)fl;
}

// ── Post-hook: cfg80211_wext_giwap ──────────────────────────
// int fn(net_dev*, iw_info*, sockaddr* x2, char* extra)
// sockaddr.data[0..5] = BSSID
static void post_ap(hook_fargs_t *a, void *u)
{
    if ((int)a->ret) return;
    struct saddr *ap = (struct saddr *)a->args[2];
    km_cpy(ap->data, g_bssid, 6);
}

// ── init ─────────────────────────────────────────────────────
static int init(const char *args, const char *ev, void *rsv)
{
    g_rng = (u32)(unsigned long)&g_rng ^ 0xC0FFEE42u;
    new_vals();
    printk("[wifi_spoof] init SSID=%s BSSID=%02X:%02X:%02X:%02X:%02X:%02X\n",
           g_ssid, g_bssid[0],g_bssid[1],g_bssid[2],
                   g_bssid[3],g_bssid[4],g_bssid[5]);

    g_fn_essid = kallsyms_lookup_name("cfg80211_wext_giwessid");
    if (g_fn_essid) {
        int r = hook_wrap(g_fn_essid, 0, post_essid, 0);
        printk("[wifi_spoof] giwessid hook %s\n", r ? "FAIL" : "OK");
    } else {
        printk("[wifi_spoof] giwessid not found (wext disabled?)\n");
    }

    g_fn_ap = kallsyms_lookup_name("cfg80211_wext_giwap");
    if (g_fn_ap) {
        int r = hook_wrap(g_fn_ap, 0, post_ap, 0);
        printk("[wifi_spoof] giwap hook %s\n", r ? "FAIL" : "OK");
    } else {
        printk("[wifi_spoof] giwap not found\n");
    }

    return 0;
}

// ── exit ─────────────────────────────────────────────────────
static void exit_(void *rsv)
{
    if (g_fn_essid) unhook(g_fn_essid);
    if (g_fn_ap)    unhook(g_fn_ap);
    printk("[wifi_spoof] unloaded\n");
}

// ── control：service.sh 游戏启动时发 "new" 触发随机化 ────────
// /data/adb/ksud kpm ctl wifi_info_spoof "new"
static long ctl(const char *args, char *reply, long rlen)
{
    if (args && args[0]=='n' && args[1]=='e' && args[2]=='w') {
        g_rng ^= (u32)(unsigned long)g_ssid;
        new_vals();
        printk("[wifi_spoof] refresh SSID=%s\n", g_ssid);
    }
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit_);
KPM_CTL(ctl);
