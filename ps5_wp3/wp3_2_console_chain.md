# WP3-STEP 2: Console path — printf → Titania UART (MMIO 0xC1010100)

## 1. Full call chain (byte-exact, all thunks resolved)

```
printf            0xffffffff9e64d410  (thunk) → 0xffffffff9e89dd60  (real printf)
  → kvprintf core 0xffffffff9e89da20(rdi=-1, rsi=5(prio), rdx=fmt, rcx=&retbuf, r8=va)
      flags = 5 | 0x10 = 0x15, then gate(0x5e)=1, gate(0x4b)=1 → flags = 0x15 & 0x11 = 0x11
      (bits: 0=TOCONS, 4=TOLOG-disabled, log sink gated by [0xa1926628])
  → putchar       thunk 0x9e65c4b8 → 0xffffffff9e89d890
      msgbuf write if flags&2; console write if (char!=0 && flags&0x25) || (flags&0x14 && !(flags&0x25))
  → console line-writer 0xffffffff9e8a0ee0  (buffered, flush on '\n' or 2-left)
      sinks: bit4→0x9f025230 log (DISABLED: flags=0x11), bit0x20→0x9ef0d260(1)/char,
             bit1→0x9f025230 crashlog (gated [0xa210fc18]=0 → off)
  → sink_line      0xffffffff9ef0d8f0 → per char:
  → cnputc         0xffffffff9ef0d260  (console list walk + validation)
      mute: r14d = ([0xa05e9598] != 0) ? [0xa05e9598] : char   ← CONSOLE MUTE!!
      list: [0xa0cc2a40] → node 0xa210fb70 → consdev 0x9fe8c7b0
      validate: (0x9e65af68 - putc_thunk) ror 3 ≤ 0x10b  (anti-tamper, thunk window)
  → device putc   thunk 0x9e65a7a8 → 0xffffffff9e739bc0
      tty mutex + validate ([0x9e65edb0 - ll_putc) ror 3 ≤ 0xc)
  → ll putc       thunk 0x9e65ed80 → 0xffffffff9e8c5180  ← THE DEVICE REGISTER WRITE
```

## 2. THE DEVICE: "Titania UART" (security-processor UART)

methods/ident table @0xffffffff9feba8b8: name 'Titania UART' @+0x30.
consdev 0x9fe8c7b0 {methods=0x9f25b920, prio=4, softc=0xa184f310, ...}
softc: regs VA @+0x18 = 0xffff8e77c1010100 = DMAP(0xC1010100) → **PHYS MMIO BASE 0xC1010100**

Register protocol (0x9e8c5180):
```c
volatile u32 *r = softc->regs;
while (r[0xc/4] & 0x800) ;   // wait status bit 11 (TX ready)
r[0x4/4] = c;                 // 32-bit data write
```
NOT 16550-compatible (32-bit regs, custom status bit). PS5 console = MMIO UART in the
shared memory map at phys 0xC1010100.

## 3. Console mute — THE retail-serial silencer

cnputc: `call 0x9eaca040` → returns byte [0xa05e9598]; if nonzero, EVERY character is
REPLACED by that byte. Live/ELF value = 0x20 (' ') → output would be all spaces!
Writer: 0x9eaca400 (boot-param reader): `[0xa05e9598] = byte[0x9fe4c15a]` (config blob,
live 0x20 = retail mute; devkits 0x00).
**BOOT PATCH #1: byte @0x9fe4c15a: 0x20 → 0x00 (devkit-mode console un-mute).**

## 4. Console list is PRE-LINKED in the reconstructed ELF (verified 10/10 intact)
[0xa0cc2a40]=0xa210fb70 → {next=0, consdev=0x9fe8c7b0} → methods {putc=thunk 0x9e65a7a8}
→ softc {regs VA 0xffff8e77c1010100} — all present in ps5_kernel_1360_reconstructed.elf.
So console output works from the very first printf — no driver attach needed.
Gates: [0xa1092908]=0 ✓, [0xa210fc18]=0 ✓, [0xa192662c]=0 ✓, [0xa210fb60]=0 ✓,
[0xa197818c] dword=0 ✓, bitmap [0xa20b1390]=all-ones ✓, [0xa1926628]=1 (log sink —
but disabled via flags 0x11, so the stale log-buf pointer 0xffff8e7b7f2fffb8 is never
dereferenced).

## 5. BOOT PATCH #2: Titania putc → QEMU debugcon (port 0x402)
The real UART MMIO (phys 0xC1010100) doesn't exist in QEMU and the regs-VA is baked
with the live DMAP base. Since we force DMAP=live constants the VA would be mapped —
but to phys 0xC1010100 which is RAM in our VM (wrong device!). Cleanest: replace the
whole body of 0x9e739bc0 (0x24 B) with:
```
40 88 F0        mov al, sil
66 BA 02 40     mov dx, 0x402
EE              out dx, al        ; QEMU isa-debugcon
C3              ret
```
(-debugcon file:serial.log, default iobase 0x402). Bypasses tty/mutex/softc entirely.

## 6. Boot-param block (phys 0x9b000-0x9c000) — reverse-extracted live values
0x9eaca400 reads (via DMAP!) and caches to .data 0xa1d0ae40..0xa1d0aef8:
```
phys      size   dest          live value (reverse-extracted)
0x9b310   6B     0xa1d0aedc    c0 15 1b 18 52 61   (machine ID?)
0x9b318   6B     0xa1d0aee2    ff ff ff ff ff ff   (empty)
0x9b350   0x40B  0xa1d0ae40    01000000 00000000 01000000 00000000 22010101 00000000
                              0c000000 00003600 20044400 00000000 01000000 00000000
                              00000100 0c0c0c0c 008d0001 00000000
0x9b6be   1B     0xa1d0aec0    00
0x9b6c0   4B     0xa1d0aec4    00000000
0x9b6d4   4B     0xa1d0aee8    00010000
0x9b6d8   4B     0xa1d0aeec    00000000
0x9b6dc   1B     0xa1d0aec8    00        (==0xb would set flag [0xa1d0ae88]=1)
0x9b6dd   1B     0xa1d0ae8c    00
0x9b6e0   4B     0xa1d0ae94    00120101  (flags: 0x100000|0x20000|0x101?)
0x9b6e4   8B     0xa1d0aeb0    0
0x9b6ec   8B     0xa1d0aeb8    0
0x9b6f4   8B     0xa1fa55d8    0         (kernel phys delta — WP2 contract)
0x9bf44   3B     0xa1d0aef0    66 00 00
0x9bf48   4B     0xa1d0ae90    00000001
0x9bf4c   8B     0xa1fa55c8    0         (KERNBASE GB selector — WP2 contract)
0x9bf54   8B     0xa1fa55d0    1e1e0000  (low-mem/DMAP window base — WP2 contract)
0x9bf5c   1B     0xa1d0aea8    00
0x9bf6c   4B     0xa1d0aecc    00070000
0x9bf70   4B     0xa1d0aed0    00030000
0x9bf74   4B     0xa1d0aed4    7f9d0000
0x9bf78   4B     0xa1d0aed8    00610000
```
config blob (.text, loader-patchable): [0x9fe4c064]=0x17, [0x9fe4c088]=0x10300,
[0x9fe4c15a]=0x20(mute→patch 0), [0x9fe4c15c]=f8f65e1e (seed), [0x9fe4c194]/[0x9fe4c198]/
[0x9fe4c208]/[0x9fe4c23b] → cached to 0xa1d0ae98/9c/a0/aef3.

## 7. panic (0xffffffff9f08aa10)
Uses the same printf path (thunk → 0x9e89dd60) with flags|=2 (msgbuf) + backtrace
printer reads LBR MSRs 0x1DD/0x1DE ('last branch from/to' strings @0x9f7748e2) —
values garbage under our rdmsr shim but unread-critical.
