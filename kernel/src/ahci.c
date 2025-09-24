#include "ahci.h"
#include "block.h"
#include "console.h"
#include "heap.h"
#include "libc.h"
#include "limine_requests.h"
#include "pci.h"
#include "pmm.h"
#include "sync.h"
#include "vmm.h"
#include <stdbool.h>
#include <stdint.h>

#define AHCI_PRDT_ENTRIES 8
#define AHCI_MAX_SECTORS_PER_CMD 128

#define HBA_GHC_AE (1U << 31)
#define HBA_GHC_IE (1U << 1)

#define HBA_PxCMD_ST (1U << 0)
#define HBA_PxCMD_FRE (1U << 4)
#define HBA_PxCMD_FR (1U << 14)
#define HBA_PxCMD_CR (1U << 15)

#define HBA_PxIS_TFES (1U << 30)

#define SATA_SIG_ATA 0x00000101

#define ATA_DEV_BUSY 0x80
#define ATA_DEV_DRQ 0x08

#define HBA_PORT_DET_PRESENT 3
#define HBA_PORT_IPM_ACTIVE 1

#define FIS_TYPE_REG_H2D 0x27

#define ATA_CMD_READ_DMA_EX 0x25
#define ATA_CMD_WRITE_DMA_EX 0x35
#define ATA_CMD_IDENTIFY 0xEC

#pragma pack(push, 1)
typedef volatile struct {
  uint32_t clb;
  uint32_t clbu;
  uint32_t fb;
  uint32_t fbu;
  uint32_t is;
  uint32_t ie;
  uint32_t cmd;
  uint32_t reserved0;
  uint32_t tfd;
  uint32_t sig;
  uint32_t ssts;
  uint32_t sctl;
  uint32_t serr;
  uint32_t sact;
  uint32_t ci;
  uint32_t sntf;
  uint32_t fbs;
  uint32_t reserved1[11];
  uint32_t vendor[4];
} hba_port_t;

typedef volatile struct {
  uint32_t cap;
  uint32_t ghc;
  uint32_t is;
  uint32_t pi;
  uint32_t vs;
  uint32_t ccc_ctl;
  uint32_t ccc_pts;
  uint32_t em_loc;
  uint32_t em_ctl;
  uint32_t cap2;
  uint32_t bohc;
  uint8_t reserved[0xA0 - 0x2C];
  uint8_t vendor[0x100 - 0xA0];
  hba_port_t ports[32];
} hba_mem_t;

typedef struct {
  uint8_t fis_type;
  uint8_t pmport : 4;
  uint8_t reserved0 : 3;
  uint8_t c : 1;
  uint8_t command;
  uint8_t featurel;
  uint8_t lba0;
  uint8_t lba1;
  uint8_t lba2;
  uint8_t device;
  uint8_t lba3;
  uint8_t lba4;
  uint8_t lba5;
  uint8_t featureh;
  uint8_t countl;
  uint8_t counth;
  uint8_t icc;
  uint8_t control;
  uint8_t reserved1[4];
} fis_reg_h2d_t;

typedef struct {
  uint32_t dba;
  uint32_t dbau;
  uint32_t reserved0;
  uint32_t dbc : 22;
  uint32_t reserved1 : 9;
  uint32_t i : 1;
} hba_prdt_entry_t;

typedef struct {
  uint8_t cfis[64];
  uint8_t acmd[16];
  uint8_t reserved[48];
  hba_prdt_entry_t prdt_entry[AHCI_PRDT_ENTRIES];
} hba_cmd_tbl_t;

typedef struct {
  uint8_t cfl : 5;
  uint8_t a : 1;
  uint8_t w : 1;
  uint8_t p : 1;
  uint8_t r : 1;
  uint8_t b : 1;
  uint8_t c : 1;
  uint8_t reserved0 : 1;
  uint8_t pmp : 4;
  uint16_t prdtl;
  volatile uint32_t prdbc;
  uint32_t ctba;
  uint32_t ctbau;
  uint32_t reserved1[4];
} hba_cmd_header_t;
#pragma pack(pop)

typedef struct {
  volatile hba_port_t *port;
  hba_mem_t *abar;
  uint32_t port_number;
  block_device_t *device;
  void *cmd_list_virt;
  uint64_t cmd_list_phys;
  void *fis_virt;
  uint64_t fis_phys;
  void *cmd_table_virt;
  uint64_t cmd_table_phys;
  void *dma_virt;
  uint64_t dma_phys;
  uint32_t dma_sectors;
  uint32_t sector_size;
  uint64_t sector_count;
  size_t cmd_table_pages;
  size_t dma_pages;
  spinlock_t lock;
} ahci_port_ctx_t;

static uint64_t hhdm_offset = 0;

static inline void *phys_to_virt(uint64_t phys) {
  return (void *)(phys + hhdm_offset);
}

static inline uint64_t virt_to_phys(void *virt) {
  return (uint64_t)virt - hhdm_offset;
}

static void *ahci_map_region(uint64_t phys, size_t size) {
  if (!size) {
    return NULL;
  }

  uint64_t aligned_phys = phys & ~(PAGE_SIZE - 1);
  size_t offset = (size_t)(phys - aligned_phys);
  size_t total = size + offset;
  size_t pages = (total + PAGE_SIZE - 1) / PAGE_SIZE;
  page_table_t *kernel_map = vmm_get_kernel_pagemap();

  for (size_t i = 0; i < pages; i++) {
    uint64_t page_phys = aligned_phys + (uint64_t)i * PAGE_SIZE;
    uint64_t page_virt = page_phys + hhdm_offset;
    uint64_t flags = VMM_WRITABLE | VMM_CACHE_DISABLE | VMM_NO_EXECUTE;
    if (!vmm_map_page(kernel_map, page_virt, page_phys, flags)) {
      return NULL;
    }
  }

  return (void *)(phys + hhdm_offset);
}

static void ahci_stop_cmd(volatile hba_port_t *port) {
  port->cmd &= ~HBA_PxCMD_ST;
  port->cmd &= ~HBA_PxCMD_FRE;

  while (port->cmd & (HBA_PxCMD_FR | HBA_PxCMD_CR)) {
    asm volatile("pause");
  }
}

static void ahci_start_cmd(volatile hba_port_t *port) {
  while (port->cmd & HBA_PxCMD_CR) {
    asm volatile("pause");
  }

  port->cmd |= HBA_PxCMD_FRE;
  port->cmd |= HBA_PxCMD_ST;
}

static bool ahci_wait_ready(volatile hba_port_t *port) {
  for (int i = 0; i < 1000000; i++) {
    uint32_t tfd = port->tfd;
    if (!(tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ))) {
      return true;
    }
    asm volatile("pause");
  }
  return false;
}

static int ahci_find_free_slot(volatile hba_port_t *port) {
  uint32_t slots = port->sact | port->ci;
  for (int i = 0; i < 32; i++) {
    if ((slots & (1U << i)) == 0) {
      return i;
    }
  }
  return -1;
}

static int ahci_issue_command(ahci_port_ctx_t *ctx, uint8_t command,
                              uint64_t lba, uint32_t count, bool write) {
  volatile hba_port_t *port = ctx->port;

  if (!ahci_wait_ready(port)) {
    return -1;
  }

  int slot = ahci_find_free_slot(port);
  if (slot < 0) {
    return -1;
  }

  hba_cmd_header_t *cmd_header = (hba_cmd_header_t *)ctx->cmd_list_virt;
  hba_cmd_header_t *cmd = &cmd_header[slot];
  memset(cmd, 0, sizeof(hba_cmd_header_t));
  cmd->cfl = sizeof(fis_reg_h2d_t) / sizeof(uint32_t);
  cmd->w = write ? 1 : 0;
  cmd->prdtl = 1;

  uintptr_t table_phys =
      ctx->cmd_table_phys + (uintptr_t)slot * sizeof(hba_cmd_tbl_t);
  hba_cmd_tbl_t *table =
      (hba_cmd_tbl_t *)((uint8_t *)ctx->cmd_table_virt +
                        (size_t)slot * sizeof(hba_cmd_tbl_t));
  memset(table, 0, sizeof(hba_cmd_tbl_t));

  table->prdt_entry[0].dba = (uint32_t)(ctx->dma_phys & 0xFFFFFFFFULL);
  table->prdt_entry[0].dbau = (uint32_t)(ctx->dma_phys >> 32);
  table->prdt_entry[0].dbc = count * ctx->sector_size - 1;
  table->prdt_entry[0].i = 1;

  fis_reg_h2d_t *fis = (fis_reg_h2d_t *)table->cfis;
  memset(fis, 0, sizeof(fis_reg_h2d_t));
  fis->fis_type = FIS_TYPE_REG_H2D;
  fis->c = 1;
  fis->command = command;
  fis->device = 1 << 6; // LBA mode
  fis->lba0 = (uint8_t)(lba & 0xFF);
  fis->lba1 = (uint8_t)((lba >> 8) & 0xFF);
  fis->lba2 = (uint8_t)((lba >> 16) & 0xFF);
  fis->lba3 = (uint8_t)((lba >> 24) & 0xFF);
  fis->lba4 = (uint8_t)((lba >> 32) & 0xFF);
  fis->lba5 = (uint8_t)((lba >> 40) & 0xFF);
  fis->countl = count & 0xFF;
  fis->counth = (count >> 8) & 0xFF;

  cmd->ctba = (uint32_t)(table_phys & 0xFFFFFFFFULL);
  cmd->ctbau = (uint32_t)(table_phys >> 32);

  port->is = (uint32_t)-1;
  port->serr = (uint32_t)-1;

  port->ci |= (1U << slot);

  while (port->ci & (1U << slot)) {
    if (port->is & HBA_PxIS_TFES) {
      port->is = HBA_PxIS_TFES;
      return -1;
    }
    asm volatile("pause");
  }

  if (port->is & HBA_PxIS_TFES) {
    port->is = HBA_PxIS_TFES;
    return -1;
  }

  return 0;
}

static int ahci_port_rw(ahci_port_ctx_t *ctx, uint64_t lba, uint32_t count,
                        void *buffer, bool write) {
  uint32_t bytes = count * ctx->sector_size;
  uint8_t *dma = (uint8_t *)ctx->dma_virt;

  if (write) {
    memcpy(dma, buffer, bytes);
  }

  int res = ahci_issue_command(
      ctx, write ? ATA_CMD_WRITE_DMA_EX : ATA_CMD_READ_DMA_EX, lba, count,
      write);
  if (res != 0) {
    return res;
  }

  if (!write) {
    memcpy(buffer, dma, bytes);
  }

  return 0;
}

static int ahci_port_identify(ahci_port_ctx_t *ctx) {
  uint8_t *dma = (uint8_t *)ctx->dma_virt;
  memset(dma, 0, ctx->dma_sectors * ctx->sector_size);

  int res = ahci_issue_command(ctx, ATA_CMD_IDENTIFY, 0, 1, false);
  if (res != 0) {
    return res;
  }

  uint16_t *identify = (uint16_t *)dma;
  uint64_t sectors =
      ((uint64_t)identify[100]) | ((uint64_t)identify[101] << 16) |
      ((uint64_t)identify[102] << 32) | ((uint64_t)identify[103] << 48);
  if (sectors == 0) {
    sectors = ((uint64_t)identify[60]) | ((uint64_t)identify[61] << 16);
  }

  ctx->sector_count = sectors;
  ctx->sector_size = 512;

  return 0;
}

static const char *ahci_make_disk_name(int index, char *buffer,
                                       size_t buffer_len) {
  if (buffer_len < 6) {
    return NULL;
  }
  strcpy(buffer, "sata");
  char num[12];
  int i = 0;
  if (index == 0) {
    num[i++] = '0';
  } else {
    int value = index;
    char tmp[12];
    int j = 0;
    while (value > 0 && j < (int)sizeof(tmp)) {
      tmp[j++] = '0' + (value % 10);
      value /= 10;
    }
    while (j > 0) {
      num[i++] = tmp[--j];
    }
  }
  num[i] = '\0';
  strcat(buffer, num);
  return buffer;
}

static int ahci_block_read(block_device_t *device, uint64_t lba, uint32_t count,
                           void *buffer) {
  ahci_port_ctx_t *ctx = (ahci_port_ctx_t *)device->driver_data;
  if (!ctx || !buffer || count == 0) {
    return -1;
  }
  if (lba + count > ctx->sector_count) {
    return -1;
  }

  spin_lock(&ctx->lock);

  uint8_t *dst = (uint8_t *)buffer;
  while (count > 0) {
    uint32_t chunk = count;
    if (chunk > ctx->dma_sectors) {
      chunk = ctx->dma_sectors;
    }
    if (ahci_port_rw(ctx, lba, chunk, dst, false) != 0) {
      spin_unlock(&ctx->lock);
      return -1;
    }
    lba += chunk;
    count -= chunk;
    dst += (uint64_t)chunk * ctx->sector_size;
  }

  spin_unlock(&ctx->lock);
  return 0;
}

static int ahci_block_write(block_device_t *device, uint64_t lba,
                            uint32_t count, const void *buffer) {
  ahci_port_ctx_t *ctx = (ahci_port_ctx_t *)device->driver_data;
  if (!ctx || !buffer || count == 0) {
    return -1;
  }
  if (lba + count > ctx->sector_count) {
    return -1;
  }

  spin_lock(&ctx->lock);

  const uint8_t *src = (const uint8_t *)buffer;
  while (count > 0) {
    uint32_t chunk = count;
    if (chunk > ctx->dma_sectors) {
      chunk = ctx->dma_sectors;
    }
    if (ahci_port_rw(ctx, lba, chunk, (void *)src, true) != 0) {
      spin_unlock(&ctx->lock);
      return -1;
    }
    lba += chunk;
    count -= chunk;
    src += (uint64_t)chunk * ctx->sector_size;
  }

  spin_unlock(&ctx->lock);
  return 0;
}

static int ahci_block_flush(block_device_t *device) {
  (void)device;
  return 0;
}

static void ahci_destroy_ctx(ahci_port_ctx_t *ctx) {
  if (!ctx) {
    return;
  }

  if (ctx->port) {
    ahci_stop_cmd(ctx->port);
  }

  if (ctx->cmd_table_phys) {
    pmm_free((void *)ctx->cmd_table_phys, ctx->cmd_table_pages);
  }
  if (ctx->cmd_list_phys) {
    pmm_free((void *)ctx->cmd_list_phys, 1);
  }
  if (ctx->fis_phys) {
    pmm_free((void *)ctx->fis_phys, 1);
  }
  if (ctx->dma_phys) {
    pmm_free((void *)ctx->dma_phys, ctx->dma_pages);
  }

  kfree(ctx);
}

static bool ahci_port_has_device(volatile hba_port_t *port) {
  uint32_t ssts = port->ssts;
  uint8_t det = ssts & 0x0F;
  uint8_t ipm = (ssts >> 8) & 0x0F;
  if (det != HBA_PORT_DET_PRESENT || ipm != HBA_PORT_IPM_ACTIVE) {
    return false;
  }
  if (port->sig != SATA_SIG_ATA) {
    return false;
  }
  return true;
}

static ahci_port_ctx_t *ahci_init_port(hba_mem_t *abar, uint32_t port_index,
                                       int disk_index) {
  volatile hba_port_t *port = &abar->ports[port_index];
  if (!ahci_port_has_device(port)) {
    return NULL;
  }

  ahci_stop_cmd(port);

  ahci_port_ctx_t *ctx = kmalloc(sizeof(ahci_port_ctx_t));
  if (!ctx) {
    return NULL;
  }
  memset(ctx, 0, sizeof(ahci_port_ctx_t));
  ctx->port = port;
  ctx->abar = abar;
  ctx->port_number = port_index;
  ctx->sector_size = 512;
  ctx->dma_sectors = AHCI_MAX_SECTORS_PER_CMD;
  spinlock_init(&ctx->lock, "ahci_port");

  void *cmd_list_phys = pmm_alloc_zero(1);
  void *fis_phys = pmm_alloc_zero(1);

  if (!cmd_list_phys || !fis_phys) {
    if (cmd_list_phys)
      pmm_free(cmd_list_phys, 1);
    if (fis_phys)
      pmm_free(fis_phys, 1);
    kfree(ctx);
    return NULL;
  }

  ctx->cmd_list_phys = (uint64_t)cmd_list_phys;
  ctx->cmd_list_virt = phys_to_virt(ctx->cmd_list_phys);
  ctx->fis_phys = (uint64_t)fis_phys;
  ctx->fis_virt = phys_to_virt(ctx->fis_phys);

  size_t cmd_table_pages =
      (sizeof(hba_cmd_tbl_t) * 32 + PAGE_SIZE - 1) / PAGE_SIZE;
  void *cmd_table_phys = pmm_alloc_zero(cmd_table_pages);
  if (!cmd_table_phys) {
    pmm_free(cmd_list_phys, 1);
    pmm_free(fis_phys, 1);
    kfree(ctx);
    return NULL;
  }

  ctx->cmd_table_phys = (uint64_t)cmd_table_phys;
  ctx->cmd_table_virt = phys_to_virt(ctx->cmd_table_phys);
  ctx->cmd_table_pages = cmd_table_pages;

  size_t dma_bytes = ctx->dma_sectors * ctx->sector_size;
  size_t dma_pages = (dma_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
  void *dma_phys = pmm_alloc_zero(dma_pages);
  if (!dma_phys) {
    pmm_free(cmd_table_phys, cmd_table_pages);
    pmm_free(cmd_list_phys, 1);
    pmm_free(fis_phys, 1);
    kfree(ctx);
    return NULL;
  }

  ctx->dma_phys = (uint64_t)dma_phys;
  ctx->dma_virt = phys_to_virt(ctx->dma_phys);
  ctx->dma_pages = dma_pages;

  memset(ctx->cmd_list_virt, 0, 1024);
  memset(ctx->fis_virt, 0, 256);

  hba_cmd_header_t *cmd_header = (hba_cmd_header_t *)ctx->cmd_list_virt;
  for (int i = 0; i < 32; i++) {
    cmd_header[i].prdtl = AHCI_PRDT_ENTRIES;
    uintptr_t tbl_phys =
        ctx->cmd_table_phys + (uintptr_t)i * sizeof(hba_cmd_tbl_t);
    cmd_header[i].ctba = (uint32_t)(tbl_phys & 0xFFFFFFFFULL);
    cmd_header[i].ctbau = (uint32_t)(tbl_phys >> 32);
  }

  port->clb = (uint32_t)(ctx->cmd_list_phys & 0xFFFFFFFFULL);
  port->clbu = (uint32_t)(ctx->cmd_list_phys >> 32);
  port->fb = (uint32_t)(ctx->fis_phys & 0xFFFFFFFFULL);
  port->fbu = (uint32_t)(ctx->fis_phys >> 32);

  ahci_start_cmd(port);

  if (ahci_port_identify(ctx) != 0) {
    kprint("AHCI: identify failed\n");
    ahci_destroy_ctx(ctx);
    return NULL;
  }

  char name[32];
  if (!ahci_make_disk_name(disk_index, name, sizeof(name))) {
    kfree(ctx);
    return NULL;
  }

  ctx->device = block_device_register(name, BLOCK_DEVICE_DISK, ctx->sector_size,
                                      ctx->sector_count, ahci_block_read,
                                      ahci_block_write, ahci_block_flush, ctx);
  if (!ctx->device) {
    ahci_destroy_ctx(ctx);
    return NULL;
  }

  block_scan_partitions(ctx->device);

  return ctx;
}

void ahci_init(void) {
  if (!hhdm_request.response) {
    return;
  }

  hhdm_offset = hhdm_request.response->offset;

  int device_count = 0;
  pci_device_t *devices = pci_get_devices(&device_count);
  if (!devices || device_count == 0) {
    return;
  }

  int disk_index = 0;

  for (int i = 0; i < device_count; i++) {
    pci_device_t *dev = &devices[i];
    if (dev->class_code != PCI_CLASS_MASS_STORAGE ||
        dev->subclass_code != 0x06 || dev->prog_if != 0x01) {
      continue;
    }

    uint32_t bar5 = dev->bar[5];
    if (bar5 == 0) {
      continue;
    }

    uint64_t abar_phys = (uint64_t)(bar5 & ~0xFULL);
    hba_mem_t *abar = (hba_mem_t *)ahci_map_region(abar_phys, 0x1100);
    if (!abar) {
      continue;
    }

    uint16_t cmd =
        pci_config_read_word(dev->bus, dev->device, dev->function, 0x04);
    cmd |= (1 << 1) | (1 << 2);
    pci_config_write_word(dev->bus, dev->device, dev->function, 0x04, cmd);

    abar->ghc |= HBA_GHC_AE;
    abar->ghc |= HBA_GHC_IE;

    uint32_t pi = abar->pi;
    for (uint32_t port = 0; port < 32; port++) {
      if (!(pi & (1U << port))) {
        continue;
      }
      ahci_port_ctx_t *ctx = ahci_init_port(abar, port, disk_index);
      if (ctx && ctx->device) {
        disk_index++;
      }
    }
  }
}
