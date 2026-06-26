CC      = aarch64-linux-gnu-gcc
KPM_SDK = KernelPatch/kernel/patch/include

CFLAGS  = -nostdinc \
           -I$(KPM_SDK) \
           -fno-pic \
           -fno-stack-protector \
           -fno-builtin \
           -mstrict-align \
           -O2 \
           -std=gnu11

TARGET  = wifi_info_spoof.kpm

$(TARGET): src/wifi_info_spoof.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET)
