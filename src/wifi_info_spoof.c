// wifi_info_spoof.c
// KPM: SSID / BSSID 随机化欺骗
//
// 钩子目标（ioctl 路径，native getifaddrs 都走这里）：
//   cfg80211_wext_giwessid → SIOCGIWESSID → 返回 SSID
//   cfg80211_wext_giwap    → SIOCGIWAP    → 返回 BSSID
//
// 集成：service.sh 在游戏启动时发 control "new" 触发重新随机化
//
// 如果内核关闭了 CONFIG_WIRELESS_EXT（wext 路径不存在），
// 模块加载不报错，仅在 dmesg 记录提示，后续换 nl80211 实现。

#include <kpm/kpm.h>
#include <kpm/ksym.h>
#include <kpm/hook.h>

// ── 元数据 ───────────────────────────────────────────────────
KPM_NAME("wifi_info_spoof");
KPM_VERSION("1.0.0");
KPM_AUTHOR("cyhtnfsj");
KPM_DESCRIPTION("Randomize SSID/BSSID for native WiFi reads");
KPM_LICENSE("GPL v2");

// ── 基础类型（-nostdinc 下不引 libc/stdlib 头）───────────────
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

// iw_point（仅用到的字段）
struct my_iw_point {
    void *pointer;   // 用户空间缓冲区（wireless ext 层自己 copy_to_user）
    u16   length;    // SSID 字节数
    u16   flags;
};

// sockaddr（sa_data[0..5] = BSSID）
struct my_sockaddr {
    u16  sa_family;
    char sa_data[14];
};

// ── 全局状态 ─────────────────────────────────────────────────
static char g_fake_ssid[33];    // 当前假 SSID（含 \0）
static u8   g_fake_bssid[6];    // 当前假 BSSID
static u32  g_rng;              // 简单 LCG 状态

static unsigned long g_fn_giwessid = 0;
static unsigned long g_fn_giwap    = 0;

// ── 工具函数（不依赖 libc）───────────────────────────────────
static u32 krand(void)
{
    g_rng = g_rng * 1664525u + 1013904223u;
    return g_rng;
}

static char hex4(u8 v)
{
    v &= 0xF;
    return (char)(v < 10 ? '0' + v : 'A' + v - 10);
}

static void km_memcpy(void *dst, const void *src, u64 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    while (n--) *d++ = *s++;
}

static u64 km_strlen(const char *s)
{
    u64 n = 0; while (*s++) n++; return n;
}

// ── 随机化 SSID + BSSID ───────────────────────────────────────
// SSID 格式：常见前缀 + 4位随机 hex → 看起来像真实家用路由器
static const char * const PREFIXES[] = {
    "CMCC-", "TP-LINK_", "Xiaomi_", "HUAWEI-", "ChinaNet-", "360WiFi-"
};
#define PREFIX_CNT 6

static void gen_new_values(void)
{
    const char *pfx = PREFIXES[krand() % PREFIX_CNT];
    u64 plen = km_strlen(pfx);
    km_memcpy(g_fake_ssid, pfx, plen);

    // 4位 hex 后缀
    u32 r = krand();
    g_fake_ssid[plen + 0] = hex4((u8)(r >> 12));
    g_fake_ssid[plen + 1] = hex4((u8)(r >> 8));
    g_fake_ssid[plen + 2] = hex4((u8)(r >> 4));
    g_fake_ssid[plen + 3] = hex4((u8)(r >> 0));
    g_fake_ssid[plen + 4] = '\0';

    // BSSID：本地管理单播 MAC（bit1=1, bit0=0 → 首字节 0x02/0x06/0x0A/0x0E）
    static const u8 first_bytes[] = {0x02, 0x06, 0x0A, 0x0E};
    g_fake_bssid[0] = first_bytes[krand() % 4];
    u32 r2 = krand(), r3 = krand();
    g_fake_bssid[1] = (u8)(r2 >>  0);
    g_fake_bssid[2] = (u8)(r2 >>  8);
    g_fake_bssid[3] = (u8)(r2 >> 16);
    g_fake_bssid[4] = (u8)(r3 >>  0);
    g_fake_bssid[5] = (u8)(r3 >>  8);
}

// ── Hook: cfg80211_wext_giwessid ─────────────────────────────
// 原型: int fn(struct net_device*, struct iw_request_info*,
//              struct iw_point* data, char* ssid_kbuf)
//
// wireless ext 框架在函数返回后自己 copy_to_user(data->pointer, ssid_kbuf, data->length)
// 所以我们只需要在 post-hook 里改 ssid_kbuf 和 data->length，不用手动 copy_to_user
static void post_giwessid(hook_fargs_t *args, void *udata)
{
    if ((int)args->ret != 0) return;            // 函数失败时不改

    struct my_iw_point *data = (struct my_iw_point *)args->args[2];
    char               *kbuf = (char *)args->args[3];   // 内核侧 SSID 缓冲

    u64 flen = km_strlen(g_fake_ssid);
    km_memcpy(kbuf, g_fake_ssid, flen);
    data->length = (u16)flen;
}

// ── Hook: cfg80211_wext_giwap ────────────────────────────────
// 原型: int fn(struct net_device*, struct iw_request_info*,
//              struct sockaddr* ap_addr, char* extra)
// ap_addr->sa_data[0..5] = BSSID（框架同样负责 copy_to_user）
static void post_giwap(hook_fargs_t *args, void *udata)
{
    if ((int)args->ret != 0) return;

    struct my_sockaddr *ap = (struct my_sockaddr *)args->args[2];
    km_memcpy(ap->sa_data, g_fake_bssid, 6);
}

// ── init ──────────────────────────────────────────────────────
static int init(const char *args, const char *event, void *reserved)
{
    // 用模块自身地址做种，每次加载都不一样
    g_rng = (u32)(unsigned long)&g_rng ^ 0xC0FFEE42u;
    gen_new_values();

    printk("[wifi_spoof] init SSID=%s BSSID=%02X:%02X:%02X:%02X:%02X:%02X\n",
           g_fake_ssid,
           g_fake_bssid[0], g_fake_bssid[1], g_fake_bssid[2],
           g_fake_bssid[3], g_fake_bssid[4], g_fake_bssid[5]);

    // SSID hook
    g_fn_giwessid = kallsyms_lookup_name("cfg80211_wext_giwessid");
    if (g_fn_giwessid) {
        int rc = hook_wrap(g_fn_giwessid, 0, (void *)post_giwessid, 0);
        printk("[wifi_spoof] giwessid hook %s (rc=%d)\n",
               rc ? "FAILED" : "OK", rc);
    } else {
        // 内核关闭了 CONFIG_WIRELESS_EXT → 需要 nl80211 版本
        printk("[wifi_spoof] giwessid not found, check CONFIG_WIRELESS_EXT\n");
    }

    // BSSID hook
    g_fn_giwap = kallsyms_lookup_name("cfg80211_wext_giwap");
    if (g_fn_giwap) {
        int rc = hook_wrap(g_fn_giwap, 0, (void *)post_giwap, 0);
        printk("[wifi_spoof] giwap hook %s (rc=%d)\n",
               rc ? "FAILED" : "OK", rc);
    } else {
        printk("[wifi_spoof] giwap not found, check CONFIG_WIRELESS_EXT\n");
    }

    return 0;   // 即使符号找不到也不报错，让模块正常加载
}

// ── exit ──────────────────────────────────────────────────────
static void exit_(void *reserved)
{
    if (g_fn_giwessid) unhook(g_fn_giwessid);
    if (g_fn_giwap)    unhook(g_fn_giwap);
    printk("[wifi_spoof] unloaded\n");
}

// ── control ───────────────────────────────────────────────────
// service.sh 在游戏启动前调用：
//   /data/adb/ksud kpm ctl wifi_info_spoof "new"
// 触发重新随机化，让每次进游戏读到的都不一样
static long control(const char *args, char *__user reply, long reply_len)
{
    if (!args) return 0;

    // "new" → 重新随机化
    if (args[0] == 'n' && args[1] == 'e' && args[2] == 'w') {
        // 混入当前 bss 地址增加熵
        g_rng ^= (u32)(unsigned long)g_fake_ssid;
        gen_new_values();
        printk("[wifi_spoof] refreshed SSID=%s BSSID=%02X:%02X:%02X:%02X:%02X:%02X\n",
               g_fake_ssid,
               g_fake_bssid[0], g_fake_bssid[1], g_fake_bssid[2],
               g_fake_bssid[3], g_fake_bssid[4], g_fake_bssid[5]);
    }
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit_);
KPM_CTL(control);
