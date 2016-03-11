/*
 * Debugfs support for hosts and cards
 *
 * Copyright (C) 2008 Atmel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/moduleparam.h>
#include <linux/export.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/fault-inject.h>

#include <linux/mmc/card.h>
#include <linux/mmc/host.h>

#include "core.h"
#include "mmc_ops.h"

#ifdef CONFIG_FAIL_MMC_REQUEST

static DECLARE_FAULT_ATTR(fail_default_attr);
static char *fail_request;
module_param(fail_request, charp, 0);

#endif /* CONFIG_FAIL_MMC_REQUEST */

enum mmc_sdio_buf_c_type {
	MMC_CMD_BUF_TYPE_NULL = 0,
	MMC_CMD_BUF_TYPE_READ,
	MMC_CMD_BUF_TYPE_WRITE,
	MMC_CMD_BUF_TYPE_READ_WRITE
};

enum mmc_sdio_buf_c_size {
	MMC_CMD_BUF_SIZE_NULL = 0,
	MMC_CMD_BUF_SIZE_BYTE,
	MMC_CMD_BUF_SIZE_WORD,
	MMC_CMD_BUF_SIZE_LONG
};

struct mmc_sdio_buf_c {
	struct timespec tp;

	enum mmc_sdio_buf_c_type type;
	enum mmc_sdio_buf_c_size size;
	unsigned int addr;
	u8 w[4];
	u8 r[4];
	int ret;
};

struct mmc_sdio_buf {
	u8 record;

	u64 size;
	u64 total;
	u64 offset;

	struct mutex cb_mutex;

	u32 oflow_count;
	struct timespec rec_start;
	struct timespec oflow_last, oflow_short, oflow_long, oflow_avg;

	struct mmc_sdio_buf_c **cmds;
};

/* The debugfs functions are optimized away when CONFIG_DEBUG_FS isn't set. */
static int mmc_ios_show(struct seq_file *s, void *data)
{
	static const char *vdd_str[] = {
		[8]	= "2.0",
		[9]	= "2.1",
		[10]	= "2.2",
		[11]	= "2.3",
		[12]	= "2.4",
		[13]	= "2.5",
		[14]	= "2.6",
		[15]	= "2.7",
		[16]	= "2.8",
		[17]	= "2.9",
		[18]	= "3.0",
		[19]	= "3.1",
		[20]	= "3.2",
		[21]	= "3.3",
		[22]	= "3.4",
		[23]	= "3.5",
		[24]	= "3.6",
	};
	struct mmc_host	*host = s->private;
	struct mmc_ios	*ios = &host->ios;
	const char *str;

	seq_printf(s, "clock:\t\t%u Hz\n", ios->clock);
	if (host->actual_clock)
		seq_printf(s, "actual clock:\t%u Hz\n", host->actual_clock);
	seq_printf(s, "vdd:\t\t%u ", ios->vdd);
	if ((1 << ios->vdd) & MMC_VDD_165_195)
		seq_printf(s, "(1.65 - 1.95 V)\n");
	else if (ios->vdd < (ARRAY_SIZE(vdd_str) - 1)
			&& vdd_str[ios->vdd] && vdd_str[ios->vdd + 1])
		seq_printf(s, "(%s ~ %s V)\n", vdd_str[ios->vdd],
				vdd_str[ios->vdd + 1]);
	else
		seq_printf(s, "(invalid)\n");

	switch (ios->bus_mode) {
	case MMC_BUSMODE_OPENDRAIN:
		str = "open drain";
		break;
	case MMC_BUSMODE_PUSHPULL:
		str = "push-pull";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "bus mode:\t%u (%s)\n", ios->bus_mode, str);

	switch (ios->chip_select) {
	case MMC_CS_DONTCARE:
		str = "don't care";
		break;
	case MMC_CS_HIGH:
		str = "active high";
		break;
	case MMC_CS_LOW:
		str = "active low";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "chip select:\t%u (%s)\n", ios->chip_select, str);

	switch (ios->power_mode) {
	case MMC_POWER_OFF:
		str = "off";
		break;
	case MMC_POWER_UP:
		str = "up";
		break;
	case MMC_POWER_ON:
		str = "on";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "power mode:\t%u (%s)\n", ios->power_mode, str);
	seq_printf(s, "bus width:\t%u (%u bits)\n",
			ios->bus_width, 1 << ios->bus_width);

	switch (ios->timing) {
	case MMC_TIMING_LEGACY:
		str = "legacy";
		break;
	case MMC_TIMING_MMC_HS:
		str = "mmc high-speed";
		break;
	case MMC_TIMING_SD_HS:
		str = "sd high-speed";
		break;
	case MMC_TIMING_UHS_SDR50:
		str = "sd uhs SDR50";
		break;
	case MMC_TIMING_UHS_SDR104:
		str = "sd uhs SDR104";
		break;
	case MMC_TIMING_UHS_DDR50:
		str = "sd uhs DDR50";
		break;
	case MMC_TIMING_MMC_DDR52:
		str = "mmc DDR52";
		break;
	case MMC_TIMING_MMC_HS200:
		str = "mmc HS200";
		break;
	case MMC_TIMING_MMC_HS400:
		str = "mmc HS400";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "timing spec:\t%u (%s)\n", ios->timing, str);

	switch (ios->signal_voltage) {
	case MMC_SIGNAL_VOLTAGE_330:
		str = "3.30 V";
		break;
	case MMC_SIGNAL_VOLTAGE_180:
		str = "1.80 V";
		break;
	case MMC_SIGNAL_VOLTAGE_120:
		str = "1.20 V";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "signal voltage:\t%u (%s)\n", ios->chip_select, str);

	return 0;
}

static int mmc_ios_open(struct inode *inode, struct file *file)
{
	return single_open(file, mmc_ios_show, inode->i_private);
}

static const struct file_operations mmc_ios_fops = {
	.open		= mmc_ios_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int mmc_clock_opt_get(void *data, u64 *val)
{
	struct mmc_host *host = data;

	*val = host->ios.clock;

	return 0;
}

static int mmc_clock_opt_set(void *data, u64 val)
{
	struct mmc_host *host = data;

	/* We need this check due to input value is u64 */
	if (val > host->f_max)
		return -EINVAL;

	mmc_claim_host(host);
	mmc_set_clock(host, (unsigned int) val);
	mmc_release_host(host);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(mmc_clock_fops, mmc_clock_opt_get, mmc_clock_opt_set,
	"%llu\n");

static void _mmc_sdio_buf_reset(struct mmc_host *host)
{
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;

	sdio_buf->total = 0;
	sdio_buf->offset = 0;
	sdio_buf->record = 1;
	get_monotonic_boottime(&sdio_buf->rec_start);

	sdio_buf->oflow_count = 0;
	sdio_buf->oflow_last.tv_sec  = sdio_buf->rec_start.tv_sec;
	sdio_buf->oflow_last.tv_nsec = sdio_buf->rec_start.tv_nsec;
	sdio_buf->oflow_short.tv_sec = sdio_buf->oflow_short.tv_nsec = 0;
	sdio_buf->oflow_long.tv_sec  = sdio_buf->oflow_long.tv_nsec  = 0;
	sdio_buf->oflow_avg.tv_sec   = sdio_buf->oflow_avg.tv_nsec   = 0;
}

static int _mmc_alloc_sdio_buf_debugfs(struct mmc_host *host, u64 sz)
{
	struct mmc_sdio_buf *sdio_buf;
	u64 i;

	sdio_buf = kzalloc(sizeof(struct mmc_sdio_buf), GFP_KERNEL);
	host->sdio_buf = sdio_buf;

	mutex_init(&sdio_buf->cb_mutex);

	if (!sdio_buf) {
		dev_err(&host->class_dev, "failed to alloc sdio_buf\n");
		return(-1);
	}

	sdio_buf->size = sz;
	sdio_buf->cmds = kzalloc(sizeof(struct mmc_sdio_buf_c*) * sz, GFP_KERNEL);

	if (!sdio_buf->cmds) {
		dev_err(&host->class_dev, "failed to alloc sdio_bufs buffer\n");
		mmc_free_sdio_buf_debugfs(host);
		return(-1);
	}

	for (i = 0; i < sdio_buf->size; i++) {
		sdio_buf->cmds[i] =
			kzalloc(sizeof(struct mmc_sdio_buf_c), GFP_KERNEL);
		if (!sdio_buf->cmds[i]) {
			dev_err(&host->class_dev,
				"failed to alloc sdio_bufs(%llu) buffer\n", i);
			sdio_buf->size = i;
			mmc_free_sdio_buf_debugfs(host);
			return(-1);
		}
	}

	_mmc_sdio_buf_reset(host);

	return(0);
}

int mmc_alloc_sdio_buf_debugfs(struct mmc_host *host) {
	return _mmc_alloc_sdio_buf_debugfs(host, 128);
}

void mmc_free_sdio_buf_debugfs(struct mmc_host *host)
{
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;
	u64 i;

	if (sdio_buf) {
		mutex_destroy(&sdio_buf->cb_mutex);

		if (sdio_buf->cmds)
			for (i = 0; i < sdio_buf->size; i++)
				kfree(sdio_buf->cmds[i]);
			kfree(sdio_buf->cmds);
		kfree(sdio_buf);
	}
	host->sdio_buf = NULL;
}

#define NSEC_IN_SEC 1000000000

// void mmc_add_cmd2buf_debugfs(struct mmc_host *host, struct mmc_command *cmd)
void mmc_add_cmd2buf_debugfs(struct mmc_host *host, unsigned int addr, int sz, int write, u8 *w, u8 *r, int ret)
{
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;
	struct mmc_sdio_buf_c *c;
	int has_overflown = 0, i;

	if (!sdio_buf->record)
		return;

	mutex_lock(&sdio_buf->cb_mutex);

	sdio_buf->total++;
	if ((sdio_buf->size - 1) <= sdio_buf->offset) {
		sdio_buf->offset = 0;
		has_overflown = 1;
	} else {
		sdio_buf->offset++;
	}

	c = sdio_buf->cmds[sdio_buf->offset];

	get_monotonic_boottime(&c->tp);

	c->addr = addr;

	if (write) {
		c->type = (!r) ?  MMC_CMD_BUF_TYPE_WRITE :
			MMC_CMD_BUF_TYPE_READ_WRITE;
	} else {
		c->type = MMC_CMD_BUF_TYPE_READ;
	}

	switch (sz) {
		case 1:
			c->size = MMC_CMD_BUF_SIZE_BYTE;
			break;
		case 2:
			c->size = MMC_CMD_BUF_SIZE_WORD;
			break;
		case 4:
			c->size = MMC_CMD_BUF_SIZE_LONG;
			break;
		default:
			c->size = MMC_CMD_BUF_SIZE_NULL;
	}

	for (i = 0; i < 4; i++) {
		c->w[i] = 0;
		c->r[i] = 0;

		if (i < sz) {
			if (w)
				c->w[i] = w[i];
			if (r)
				c->r[i] = r[i];
		}
	}

	c->ret = ret;

	if (has_overflown) {
		struct timespec tp;
		u32 x;

		tp.tv_sec  = c->tp.tv_sec  - sdio_buf->oflow_last.tv_sec;
		tp.tv_nsec = c->tp.tv_nsec - sdio_buf->oflow_last.tv_nsec;

		if (tp.tv_nsec < 0) {
			tp.tv_sec -= 1;
			tp.tv_nsec += NSEC_IN_SEC;
		}

		/* last */
		sdio_buf->oflow_last.tv_sec  = c->tp.tv_sec;
		sdio_buf->oflow_last.tv_nsec = c->tp.tv_nsec;

		/* longest */
		if (sdio_buf->oflow_count == 0 ||
				sdio_buf->oflow_long.tv_sec < tp.tv_sec ||
				(sdio_buf->oflow_long.tv_sec == tp.tv_sec &&
				sdio_buf->oflow_long.tv_nsec < tp.tv_nsec)) {
			sdio_buf->oflow_long.tv_sec  = tp.tv_sec;
			sdio_buf->oflow_long.tv_nsec = tp.tv_nsec;
		}

		/* shortest */
		if (sdio_buf->oflow_count == 0 ||
				sdio_buf->oflow_short.tv_sec > tp.tv_sec ||
				(sdio_buf->oflow_short.tv_sec == tp.tv_sec &&
				sdio_buf->oflow_short.tv_nsec > tp.tv_nsec)) {
			sdio_buf->oflow_short.tv_sec  = tp.tv_sec;
			sdio_buf->oflow_short.tv_nsec = tp.tv_nsec;
		}

		sdio_buf->oflow_count++;

		/* avg */

		tp.tv_sec  = c->tp.tv_sec  - sdio_buf->rec_start.tv_sec;
		tp.tv_nsec = c->tp.tv_nsec - sdio_buf->rec_start.tv_nsec;

		if (tp.tv_nsec < 0) {
			tp.tv_sec -= 1;
			tp.tv_nsec += NSEC_IN_SEC;
		}

		x = tp.tv_sec % sdio_buf->oflow_count;

		sdio_buf->oflow_avg.tv_sec  = tp.tv_sec / sdio_buf->oflow_count;
		sdio_buf->oflow_avg.tv_nsec = tp.tv_nsec /sdio_buf->oflow_count;
		sdio_buf->oflow_avg.tv_nsec += x * (NSEC_IN_SEC /
				sdio_buf->oflow_count);
	}

	mutex_unlock(&sdio_buf->cb_mutex);
}

static int mmc_sdio_buf_show_h(struct seq_file *s, struct mmc_sdio_buf_c *c)
{
	char *t = NULL, *x = NULL;

	switch (c->type) {
		case MMC_CMD_BUF_TYPE_READ:
			t = "R ";
			break;
		case MMC_CMD_BUF_TYPE_WRITE:
			t = " W";
			break;
		case MMC_CMD_BUF_TYPE_READ_WRITE:
			t = "RW";
			break;
		case MMC_CMD_BUF_TYPE_NULL:
		default:
			t = "??";
			break;
	}

	switch (c->size) {
		case MMC_CMD_BUF_SIZE_BYTE:
			x = "b ";
			break;
		case MMC_CMD_BUF_SIZE_WORD:
			x = "w ";
			break;
		case MMC_CMD_BUF_SIZE_LONG:
			x = "l ";
			break;
		case MMC_CMD_BUF_SIZE_NULL:
		default:
			x = "??";
			break;
	}

	seq_printf(s, "[%li.%09li] %s ADDR:0x%08x SZ:%s ",
		c->tp.tv_sec, c->tp.tv_nsec, t, c->addr, x);

	if (c->type != MMC_CMD_BUF_TYPE_READ)
		seq_printf(s, "W:0x%02x%02x%02x%02x ",
			c->w[0], c->w[1], c->w[2], c->w[3]);
	else
		seq_printf(s, "            ");

	if (c->type != MMC_CMD_BUF_TYPE_WRITE)
		seq_printf(s, "R:0x%02x%02x%02x%02x ",
			c->r[0], c->r[1], c->r[2], c->r[3]);
	else
		seq_printf(s, "            ");

	seq_printf(s, "ret=%i\n", c->ret);

	return 0;
}

static int mmc_sdio_buf_show(struct seq_file *s, void *data)
{
	struct mmc_host	*host = s->private;
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;
	u64 i;

	mutex_lock(&sdio_buf->cb_mutex);

	if (sdio_buf->oflow_count) {
		for (i = sdio_buf->offset + 1; i < sdio_buf->size; i++) {
			mmc_sdio_buf_show_h(s, sdio_buf->cmds[i]);
		}
	}

	for (i = 0; i <= sdio_buf->offset; i++) {
		mmc_sdio_buf_show_h(s, sdio_buf->cmds[i]);
	}

	mutex_unlock(&sdio_buf->cb_mutex);

	return 0;
}

static int mmc_sdio_buf_open(struct inode *inode, struct file *file)
{
	return single_open(file, mmc_sdio_buf_show, inode->i_private);
}

static const struct file_operations mmc_sdio_buf_fops = {
	.open		= mmc_sdio_buf_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int mmc_sdio_buf_size_get(void *data, u64 *val)
{
	struct mmc_host *host = data;
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;

	*val = sdio_buf->size;

	return 0;
}

static int mmc_sdio_buf_size_set(void *data, u64 val)
{
	struct mmc_host *host = data;
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;
	int ret = 0;

	if (val != sdio_buf->size) {
		mmc_free_sdio_buf_debugfs(host);
		ret = _mmc_alloc_sdio_buf_debugfs(host, val);
	}

	return ret;
}

DEFINE_SIMPLE_ATTRIBUTE(mmc_sdio_buf_size_fops, mmc_sdio_buf_size_get,
	mmc_sdio_buf_size_set, "%llu\n");

static int mmc_sdio_buf_offset_get(void *data, u64 *val)
{
	struct mmc_host *host = data;
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;

	*val = sdio_buf->offset;

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(mmc_sdio_buf_offset_fops, mmc_sdio_buf_offset_get,
	NULL, "%llu\n");

static int mmc_sdio_buf_stats_show(struct seq_file *s, void *data)
{
	struct mmc_host	*host = s->private;
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;

	seq_printf(s, "last overflow at [%li.%09li]\n",
		sdio_buf->oflow_last.tv_sec, sdio_buf->oflow_last.tv_nsec);
	seq_printf(s, "Overflow count: %u\n", sdio_buf->oflow_count);
	seq_printf(s, "Total commands: %llu\n", sdio_buf->total);

	seq_printf(s, "shortest period till overflow: %li.%09li\n",
		sdio_buf->oflow_short.tv_sec, sdio_buf->oflow_short.tv_nsec);
	seq_printf(s, "longest period till overflow: %li.%09li\n",
		sdio_buf->oflow_long.tv_sec, sdio_buf->oflow_long.tv_nsec);
	seq_printf(s, "average period till overflow: %li.%09li\n",
		sdio_buf->oflow_avg.tv_sec, sdio_buf->oflow_avg.tv_nsec);

	return 0;
}

static int mmc_sdio_buf_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, mmc_sdio_buf_stats_show, inode->i_private);
}

static const struct file_operations mmc_sdio_buf_stats_fops = {
	.open		= mmc_sdio_buf_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void mmc_sdio_buf_start_recording(struct mmc_host *host)
{
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;
	if (!sdio_buf->record) {
		_mmc_sdio_buf_reset(host);
	}
}

void mmc_sdio_buf_stop_recording(struct mmc_host *host)
{
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;
	sdio_buf->record = 0;
}

static int mmc_sdio_buf_recording_get(void *data, u64 *val)
{
	struct mmc_host *host = data;
	struct mmc_sdio_buf *sdio_buf = host->sdio_buf;

	*val = sdio_buf->record;

	return 0;
}

static int mmc_sdio_buf_recording_set(void *data, u64 val)
{
	struct mmc_host *host = data;

	if (val)
		mmc_sdio_buf_start_recording(host);
	else
		mmc_sdio_buf_stop_recording(host);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(mmc_sdio_buf_recording_fops, mmc_sdio_buf_recording_get,
	mmc_sdio_buf_recording_set, "%llu\n");

void mmc_add_host_debugfs(struct mmc_host *host)
{
	struct dentry *root;

	root = debugfs_create_dir(mmc_hostname(host), NULL);
	if (IS_ERR(root))
		/* Don't complain -- debugfs just isn't enabled */
		return;
	if (!root)
		/* Complain -- debugfs is enabled, but it failed to
		 * create the directory. */
		goto err_root;

	host->debugfs_root = root;

	if (!debugfs_create_file("ios", S_IRUSR, root, host, &mmc_ios_fops))
		goto err_node;

	if (!debugfs_create_file("clock", S_IRUSR | S_IWUSR, root, host,
			&mmc_clock_fops))
		goto err_node;

#ifdef CONFIG_SDIO_DEBUG_BUFFER
	if (!debugfs_create_file("sdio_buf", S_IRUSR, root, host,
			&mmc_sdio_buf_fops))
		goto err_node;

	if (!debugfs_create_file("sdio_buf_size", S_IRUSR | S_IWUSR, root, host,
			&mmc_sdio_buf_size_fops))
		goto err_node;

	if (!debugfs_create_file("sdio_buf_offset", S_IRUSR, root, host,
			&mmc_sdio_buf_offset_fops))
		goto err_node;

	if (!debugfs_create_file("sdio_buf_stats", S_IRUSR, root, host,
			&mmc_sdio_buf_stats_fops))
		goto err_node;
	if (!debugfs_create_file("sdio_buf_recording", S_IRUSR | S_IWUSR,
			root, host, &mmc_sdio_buf_recording_fops))
		goto err_node;
#endif
#ifdef CONFIG_MMC_CLKGATE
	if (!debugfs_create_u32("clk_delay", (S_IRUSR | S_IWUSR),
				root, &host->clk_delay))
		goto err_node;
#endif
#ifdef CONFIG_FAIL_MMC_REQUEST
	if (fail_request)
		setup_fault_attr(&fail_default_attr, fail_request);
	host->fail_mmc_request = fail_default_attr;
	if (IS_ERR(fault_create_debugfs_attr("fail_mmc_request",
					     root,
					     &host->fail_mmc_request)))
		goto err_node;
#endif
	return;

err_node:
	debugfs_remove_recursive(root);
	host->debugfs_root = NULL;
err_root:
	dev_err(&host->class_dev, "failed to initialize debugfs\n");
}

void mmc_remove_host_debugfs(struct mmc_host *host)
{
	debugfs_remove_recursive(host->debugfs_root);
}

static int mmc_dbg_card_status_get(void *data, u64 *val)
{
	struct mmc_card	*card = data;
	u32		status;
	int		ret;

	mmc_get_card(card);

	ret = mmc_send_status(data, &status);
	if (!ret)
		*val = status;

	mmc_put_card(card);

	return ret;
}
DEFINE_SIMPLE_ATTRIBUTE(mmc_dbg_card_status_fops, mmc_dbg_card_status_get,
		NULL, "%08llx\n");

#define EXT_CSD_STR_LEN 1025

static int mmc_ext_csd_open(struct inode *inode, struct file *filp)
{
	struct mmc_card *card = inode->i_private;
	char *buf;
	ssize_t n = 0;
	u8 *ext_csd;
	int err, i;

	buf = kmalloc(EXT_CSD_STR_LEN + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mmc_get_card(card);
	err = mmc_get_ext_csd(card, &ext_csd);
	mmc_put_card(card);
	if (err)
		goto out_free;

	for (i = 0; i < 512; i++)
		n += sprintf(buf + n, "%02x", ext_csd[i]);
	n += sprintf(buf + n, "\n");
	BUG_ON(n != EXT_CSD_STR_LEN);

	filp->private_data = buf;
	kfree(ext_csd);
	return 0;

out_free:
	kfree(buf);
	return err;
}

static ssize_t mmc_ext_csd_read(struct file *filp, char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	char *buf = filp->private_data;

	return simple_read_from_buffer(ubuf, cnt, ppos,
				       buf, EXT_CSD_STR_LEN);
}

static int mmc_ext_csd_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static const struct file_operations mmc_dbg_ext_csd_fops = {
	.open		= mmc_ext_csd_open,
	.read		= mmc_ext_csd_read,
	.release	= mmc_ext_csd_release,
	.llseek		= default_llseek,
};

void mmc_add_card_debugfs(struct mmc_card *card)
{
	struct mmc_host	*host = card->host;
	struct dentry	*root;

	if (!host->debugfs_root)
		return;

	root = debugfs_create_dir(mmc_card_id(card), host->debugfs_root);
	if (IS_ERR(root))
		/* Don't complain -- debugfs just isn't enabled */
		return;
	if (!root)
		/* Complain -- debugfs is enabled, but it failed to
		 * create the directory. */
		goto err;

	card->debugfs_root = root;

	if (!debugfs_create_x32("state", S_IRUSR, root, &card->state))
		goto err;

	if (mmc_card_mmc(card) || mmc_card_sd(card))
		if (!debugfs_create_file("status", S_IRUSR, root, card,
					&mmc_dbg_card_status_fops))
			goto err;

	if (mmc_card_mmc(card))
		if (!debugfs_create_file("ext_csd", S_IRUSR, root, card,
					&mmc_dbg_ext_csd_fops))
			goto err;

	return;

err:
	debugfs_remove_recursive(root);
	card->debugfs_root = NULL;
	dev_err(&card->dev, "failed to initialize debugfs\n");
}

void mmc_remove_card_debugfs(struct mmc_card *card)
{
	debugfs_remove_recursive(card->debugfs_root);
}
