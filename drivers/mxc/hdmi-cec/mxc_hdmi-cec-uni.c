/*
 * Copyright (C) 2012-2013 Freescale Semiconductor, Inc. All Rights Reserved.
 */

/*
 * The code contained herein is licensed under the GNU General Public
 * License. You may obtain a copy of the GNU General Public License
 * Version 2 or later at the following locations:
 *
 * http://www.opensource.org/licenses/gpl-license.html
 * http://www.gnu.org/copyleft/gpl.html
 */

/*!
 * @file mxc_hdmi-cec.c
 *
 * @brief HDMI CEC system initialization and file operation implementation
 *
 * @ingroup HDMI
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/fsl_devices.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/sizes.h>

#include <linux/console.h>
#include <linux/types.h>
#include <linux/mfd/mxc-hdmi-core.h>
#include <linux/pinctrl/consumer.h>

#include <video/mxc_hdmi.h>

#include "mxc_hdmi-cec.h"

struct hdmi_cec_priv {
	int  receive_error;
	int  send_error;
	u8 Logical_address;
	bool cec_state;
	bool write_busy;
	u8 latest_cec_stat;
	spinlock_t irq_lock;
	struct delayed_work hdmi_cec_work;
	struct mutex lock;
	struct list_head head;
};

struct hdmi_cec_event {
	u8 event_type;
	u8 msg_len;
	u8 msg[MAX_MESSAGE_LEN];
};

struct hdmi_cec_event_list {
	struct hdmi_cec_event data;
	struct list_head ptr;
};

u8 physical_address[4];

static int hdmi_cec_ready = 0;
static int hdmi_cec_major;
static struct class *hdmi_cec_class;
static struct hdmi_cec_priv hdmi_cec_data;
static u8 open_count;

static wait_queue_head_t hdmi_cec_queue;
static wait_queue_head_t hdmi_cec_sent;
static irqreturn_t mxc_hdmi_cec_isr(int irq, void *data)
{
	struct hdmi_cec_priv *hdmi_cec = data;
	u8 cec_stat = 0;
	unsigned long flags;
	irqreturn_t ret = IRQ_HANDLED;

	spin_lock_irqsave(&hdmi_cec->irq_lock, flags);

	pr_debug("function : %s\n", __func__);

	hdmi_writeb(0x7f, HDMI_IH_MUTE_CEC_STAT0);

	cec_stat = hdmi_readb(HDMI_IH_CEC_STAT0);
	hdmi_writeb(cec_stat, HDMI_IH_CEC_STAT0);

	if (cec_stat & HDMI_IH_CEC_STAT0_ERROR_INIT) {
		hdmi_cec->send_error++;
		wake_up(&hdmi_cec_sent);
		pr_debug("function : %s error received %d\n", __func__, hdmi_cec->send_error);
	}
	if (cec_stat & (HDMI_IH_CEC_STAT0_NACK | HDMI_IH_CEC_STAT0_DONE)) {
		hdmi_cec->send_error = 0;
		wake_up(&hdmi_cec_sent);
	}

	if (cec_stat) {
		hdmi_cec->latest_cec_stat = cec_stat;
		pr_debug("function : %s HDMI CEC interrupt received\n", __func__);
	} else
		ret = IRQ_NONE;

	schedule_delayed_work(&(hdmi_cec->hdmi_cec_work), msecs_to_jiffies(20));
	spin_unlock_irqrestore(&hdmi_cec->irq_lock, flags);

	return ret;
}

void mxc_hdmi_cec_handle(u32 cec_stat)
{
	struct hdmi_cec_event_list *event = NULL;
	unsigned long flags;

	pr_debug("function : %s\n", __func__);
	memcpy(&physical_address, &cec_stat, 4*sizeof(u8));

	/* HDMI cable connected / HDMI cable disconnected */
	if (!open_count || !hdmi_cec_ready)
		return;

	event = kzalloc(sizeof(struct hdmi_cec_event_list), GFP_KERNEL);
	if (NULL == event) {
		pr_err("%s: Not enough memory!\n", __func__);
		return;
	}
	event->data.event_type = cec_stat ?
		MESSAGE_TYPE_CONNECTED : MESSAGE_TYPE_DISCONNECTED;

	spin_lock_irqsave(&hdmi_cec_data.irq_lock, flags);
	list_add_tail(&event->ptr, &hdmi_cec_data.head);
	spin_unlock_irqrestore(&hdmi_cec_data.irq_lock, flags);
	wake_up(&hdmi_cec_queue);
	pr_debug("function : %s exit\n", __func__);
}
EXPORT_SYMBOL(mxc_hdmi_cec_handle);

void mxc_hdmi_cec_msg(int event_type, struct hdmi_cec_priv *hdmi_cec)
{
	struct hdmi_cec_event_list *event = NULL;
	unsigned long flags;
	u8 i;

	event = kzalloc(sizeof(struct hdmi_cec_event_list), GFP_KERNEL);
	if (NULL == event) {
		pr_err("%s: Not enough memory!\n", __func__);
		goto error2;
	}
	event->data.event_type = event_type;

	event->data.msg_len = (event_type == MESSAGE_TYPE_RECEIVE_SUCCESS) ?
		hdmi_readb(HDMI_CEC_RX_CNT) : hdmi_readb(HDMI_CEC_TX_CNT);

	if (!event->data.msg_len || event->data.msg_len > MAX_MESSAGE_LEN) {
		pr_err("%s: Bad message size %d!\n", __func__, event->data.msg_len);
		goto error2;
	}

	for (i = 0; i < event->data.msg_len; i++)
		event->data.msg[i] = (event_type == MESSAGE_TYPE_RECEIVE_SUCCESS) ?
				hdmi_readb(HDMI_CEC_RX_DATA0+i) : hdmi_readb(HDMI_CEC_TX_DATA0+i);

	spin_lock_irqsave(&hdmi_cec->irq_lock, flags);
	list_add_tail(&event->ptr, &hdmi_cec->head);
	spin_unlock_irqrestore(&hdmi_cec->irq_lock, flags);
	wake_up(&hdmi_cec_queue);

error2:
	if (event_type == MESSAGE_TYPE_RECEIVE_SUCCESS) {
		hdmi_writeb(0x0, HDMI_CEC_LOCK);
	} else {
		mutex_lock(&hdmi_cec->lock);
		hdmi_cec->write_busy = false;
		hdmi_writeb(0, HDMI_CEC_TX_CNT);
		pr_debug("function : %s setting msg_len 0\n", __func__);
		mutex_unlock(&hdmi_cec->lock);
		wake_up(&hdmi_cec_queue);
	}

	pr_debug("function : %s write_busy: %d\n", __func__, hdmi_cec->write_busy);
}

static void mxc_hdmi_cec_worker(struct work_struct *work)
{
	u8 val;
	struct delayed_work *delay_work = to_delayed_work(work);
	struct hdmi_cec_priv *hdmi_cec =
		container_of(delay_work, struct hdmi_cec_priv, hdmi_cec_work);
	unsigned long flags;

	pr_debug("function : %s\n", __func__);
	if (hdmi_cec->latest_cec_stat && open_count) {
		pr_debug("function : %s nonzero\n", __func__);
		/* The current transmission is successful (for initiator only).*/
		if (hdmi_cec->latest_cec_stat & HDMI_IH_CEC_STAT0_DONE) {
			mxc_hdmi_cec_msg(MESSAGE_TYPE_SEND_SUCCESS, hdmi_cec);
		}
		/*A frame is not acknowledged in a directly addressed message. Or a frame is negatively acknowledged in
		a broadcast message (for initiator only).*/
		if (hdmi_cec->latest_cec_stat & HDMI_IH_CEC_STAT0_NACK) {
			mxc_hdmi_cec_msg(MESSAGE_TYPE_NOACK, hdmi_cec);
		}
		/*EOM is detected so that the received data is ready in the receiver data buffer*/
		if (hdmi_cec->latest_cec_stat & HDMI_IH_CEC_STAT0_EOM) {
			mxc_hdmi_cec_msg(MESSAGE_TYPE_RECEIVE_SUCCESS, hdmi_cec);
		}
		/*An error is notified by a follower. Abnormal logic data bit error (for follower).*/
		if (hdmi_cec->latest_cec_stat & HDMI_IH_CEC_STAT0_ERROR_FOLL) {
			hdmi_cec->receive_error++;
		}
		hdmi_cec->latest_cec_stat = 0;
	}

	val = HDMI_IH_CEC_STAT0_WAKEUP | HDMI_IH_CEC_STAT0_ERROR_FOLL | HDMI_IH_CEC_STAT0_ARB_LOST;
	spin_lock_irqsave(&hdmi_cec_root.i_lock, flags);
	hdmi_writeb(val, HDMI_IH_MUTE_CEC_STAT0);
	spin_unlock_irqrestore(&hdmi_cec_root.i_lock, flags);
	pr_debug("function : %s exit\n", __func__);
}

/*!
 * @brief open function for cec file operation
 *
 * @return  0 on success or negative error code on error
 */
static int hdmi_cec_open(struct inode *inode, struct file *filp)
{
	mutex_lock(&hdmi_cec_data.lock);
	if (open_count) {
		mutex_unlock(&hdmi_cec_data.lock);
		return -EBUSY;
	}
	open_count = 1;
	filp->private_data = (void *)(&hdmi_cec_data);
	hdmi_cec_data.Logical_address = 15;
	hdmi_cec_data.cec_state = false;
	hdmi_cec_data.write_busy = false;
	mutex_unlock(&hdmi_cec_data.lock);
	return 0;
}

static ssize_t hdmi_cec_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	struct hdmi_cec_priv *hdmi_cec = file->private_data;
	int ret = 0;

	if (!open_count)
		return -ENODEV;

	count = min(count, sizeof(struct hdmi_cec_event));
	do {
		unsigned long flags;
		struct hdmi_cec_event_list *event = NULL;

		spin_lock_irqsave(&hdmi_cec->irq_lock, flags);
		if (!list_empty(&hdmi_cec->head)) {
			event = list_first_entry(&hdmi_cec->head, struct hdmi_cec_event_list, ptr);
			list_del(&event->ptr);
		}
		spin_unlock_irqrestore(&hdmi_cec->irq_lock, flags);

		if (event) {
			ret = copy_to_user(buf, &event->data, count) ? -EFAULT : count;
			kfree(event);
		}
		else if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
		}
		else if (wait_event_interruptible(hdmi_cec_queue, (!list_empty(&hdmi_cec->head)))) {
			ret = -ERESTARTSYS;
		}
	} while(!ret);

	return ret;
}

static ssize_t hdmi_cec_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct hdmi_cec_priv *hdmi_cec = file->private_data;
	int ret = 0 , i = 0;
	u8 msg[MAX_MESSAGE_LEN];
	u8 val = 0;
	int timeout = 1500;

	if (!open_count)
		return -ENODEV;

	if (count > MAX_MESSAGE_LEN)
		return -E2BIG;

	memset(&msg, 0, MAX_MESSAGE_LEN);
	if (copy_from_user(&msg, buf, count))
		return -EFAULT;

	if (file->f_flags & O_NONBLOCK && hdmi_cec->write_busy)
		return -EAGAIN;
	else if (wait_event_interruptible(hdmi_cec_queue, (!hdmi_cec->write_busy)))
		return -ERESTARTSYS;

	mutex_lock(&hdmi_cec->lock);
	hdmi_cec->write_busy = true;

	hdmi_writeb(count, HDMI_CEC_TX_CNT);
	for (i = 0; i < count; i++)
		hdmi_writeb(msg[i], HDMI_CEC_TX_DATA0+i);

	do {
		val = hdmi_readb(HDMI_CEC_CTRL) | 0x01;
		hdmi_writeb(val, HDMI_CEC_CTRL);

		ret = wait_event_timeout(hdmi_cec_sent, !((val = hdmi_readb(HDMI_CEC_CTRL)) & 0x01), msecs_to_jiffies(timeout));
		if (hdmi_cec->send_error > 5 || ret < 2) {
			hdmi_writeb(0, HDMI_CEC_TX_CNT);
			hdmi_cec->write_busy = false;
			ret = -EIO;
		} else if (hdmi_cec->send_error > 0 && ret > 1) {
			timeout = jiffies_to_msecs(ret);
			ret = 0;
		} else if (ret > 1) {
			ret = count;
		}
	} while(!ret);

	mutex_unlock(&hdmi_cec->lock);
	wake_up(&hdmi_cec_queue);
	return ret;
}

static void hdmi_cec_hwenable(void)
{
	u8 val;

	if (!hdmi_cec_ready || hdmi_cec_data.cec_state)
		return;
	hdmi_cec_data.cec_state = true;

	val = hdmi_readb(HDMI_MC_CLKDIS);
	val &= ~HDMI_MC_CLKDIS_CECCLK_DISABLE;
	hdmi_writeb(val, HDMI_MC_CLKDIS);

	val = HDMI_IH_CEC_STAT0_ERROR_INIT | HDMI_IH_CEC_STAT0_NACK |
		HDMI_IH_CEC_STAT0_EOM | HDMI_IH_CEC_STAT0_DONE;
	hdmi_writeb(val, HDMI_CEC_POLARITY);

	val = HDMI_IH_CEC_STAT0_WAKEUP | HDMI_IH_CEC_STAT0_ERROR_FOLL |
		HDMI_IH_CEC_STAT0_ARB_LOST;
	hdmi_writeb(val, HDMI_CEC_MASK);
	hdmi_writeb(val, HDMI_IH_MUTE_CEC_STAT0);
	hdmi_writeb(0x0, HDMI_CEC_LOCK);
	hdmi_writeb(0x02, HDMI_CEC_CTRL);
}

static void hdmi_cec_hwdisable(void)
{
	u8 val;

	if(!hdmi_cec_ready || !hdmi_cec_data.cec_state)
		return;
	hdmi_cec_data.cec_state = false;

	hdmi_writeb(0x10, HDMI_CEC_CTRL);

	val = HDMI_IH_CEC_STAT0_WAKEUP | HDMI_IH_CEC_STAT0_ERROR_FOLL |
		HDMI_IH_CEC_STAT0_ERROR_INIT | HDMI_IH_CEC_STAT0_ARB_LOST |
		HDMI_IH_CEC_STAT0_NACK | HDMI_IH_CEC_STAT0_EOM |
		HDMI_IH_CEC_STAT0_DONE;
	hdmi_writeb(val, HDMI_CEC_MASK);
	hdmi_writeb(val, HDMI_IH_MUTE_CEC_STAT0);

	hdmi_writeb(0x0, HDMI_CEC_POLARITY);

	val = hdmi_readb(HDMI_MC_CLKDIS);
	val |= HDMI_MC_CLKDIS_CECCLK_DISABLE;
	hdmi_writeb(val, HDMI_MC_CLKDIS);
}

static long hdmi_cec_set_address(u_long arg, struct hdmi_cec_priv *hdmi_cec)
{
	u8 val;

	if (hdmi_cec->Logical_address == (u8)arg && hdmi_cec->cec_state)
		return 0;

	pr_debug("function : %s to %d\n", __func__, (u8)arg);

	if (arg <= 7) {
		val = 1 << (u8)arg;
		hdmi_writeb(val, HDMI_CEC_ADDR_L);
		hdmi_writeb(0, HDMI_CEC_ADDR_H);
	} else if (arg <= 15) {
		val = 1 << ((u8)arg - 8);
		hdmi_writeb(val, HDMI_CEC_ADDR_H);
		hdmi_writeb(0, HDMI_CEC_ADDR_L);
	} else
		return -EINVAL;

	hdmi_cec->Logical_address = (u8)arg;
	return 0;
}

/*!
 * @brief IO ctrl function for vpu file operation
 * @param cmd IO ctrl command
 * @return  0 on success or negative error code on error
 */
static long hdmi_cec_ioctl(struct file *filp, u_int cmd,
		     u_long arg)
{
	int ret = 0;
	struct hdmi_cec_priv *hdmi_cec = filp->private_data;

	pr_debug("function : %s\n", __func__);

	if (!open_count)
		return -ENODEV;

	switch (cmd) {
	case HDMICEC_IOC_SETLOGICALADDRESS:
		mutex_lock(&hdmi_cec->lock);
		ret = hdmi_cec_set_address(arg, hdmi_cec);
		mutex_unlock(&hdmi_cec->lock);
		break;

	case HDMICEC_IOC_STARTDEVICE:
		hdmi_cec_hwenable();
		break;

	case HDMICEC_IOC_STOPDEVICE:
		hdmi_cec_hwdisable();
		break;

	case HDMICEC_IOC_GETPHYADDRESS:
		ret = copy_to_user((void __user *)arg, &physical_address,
					4*sizeof(u8))?-EFAULT:0;
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

void hdmi_cec_start_device(void)
{
	pr_debug("function : %s\n", __func__);

	hdmi_cec_ready = 1;
	if(open_count)
		hdmi_cec_hwenable();
}
EXPORT_SYMBOL(hdmi_cec_start_device);

void hdmi_cec_stop_device(void)
{
	pr_debug("function : %s\n", __func__);

	if(open_count)
		hdmi_cec_hwdisable();
	hdmi_cec_ready = 0;
}
EXPORT_SYMBOL(hdmi_cec_stop_device);

/*!
* @brief Release function for vpu file operation
* @return  0 on success or negative error code on error
*/
static int hdmi_cec_release(struct inode *inode, struct file *filp)
{
	struct hdmi_cec_priv *hdmi_cec = filp->private_data;

	mutex_lock(&hdmi_cec->lock);
	hdmi_cec_set_address(15, hdmi_cec);
	if (open_count) {
		open_count = 0;
		while (!list_empty(&hdmi_cec->head)) {
			struct hdmi_cec_event_list *event = NULL;

			event = list_first_entry(&hdmi_cec->head, struct hdmi_cec_event_list, ptr);
			list_del(&event->ptr);
			kfree(event);
		}
		hdmi_cec_hwdisable();
	}
	mutex_unlock(&hdmi_cec->lock);
	return 0;
}

static unsigned int hdmi_cec_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;

	if (!hdmi_cec_data.cec_state)
		return POLLHUP;

	poll_wait(file, &hdmi_cec_queue, wait);

	if (!hdmi_cec_data.write_busy)
		mask = (POLLOUT | POLLWRNORM);
	if (!list_empty(&hdmi_cec_data.head))
		mask |= (POLLIN | POLLRDNORM);

	return mask;
}

const struct file_operations hdmi_cec_fops = {
	.owner = THIS_MODULE,
	.read = hdmi_cec_read,
	.write = hdmi_cec_write,
	.open = hdmi_cec_open,
	.unlocked_ioctl = hdmi_cec_ioctl,
	.release = hdmi_cec_release,
	.poll = hdmi_cec_poll,
};

static int hdmi_cec_dev_probe(struct platform_device *pdev)
{
	int err = 0;
	struct device *temp_class;
	struct resource *res;
	struct pinctrl *pinctrl;
	int irq = platform_get_irq(pdev, 0);

	hdmi_cec_major = register_chrdev(hdmi_cec_major, "mxc_hdmi_cec", &hdmi_cec_fops);
	if (hdmi_cec_major < 0) {
		dev_err(&pdev->dev, "hdmi_cec: unable to get a major for HDMI CEC\n");
		err = -EBUSY;
		goto out;
	}

	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (unlikely(res == NULL)) {
		dev_err(&pdev->dev, "hdmi_cec:No HDMI irq line provided\n");
		goto err_out_chrdev;
	}
	spin_lock_init(&hdmi_cec_data.irq_lock);

	err = devm_request_irq(&pdev->dev, irq, mxc_hdmi_cec_isr, IRQF_SHARED,
			dev_name(&pdev->dev), &hdmi_cec_data);
	if (err < 0) {
		dev_err(&pdev->dev, "hdmi_cec:Unable to request irq: %d\n", err);
		goto err_out_chrdev;
	}

	hdmi_cec_class = class_create(THIS_MODULE, "mxc_hdmi_cec");
	if (IS_ERR(hdmi_cec_class)) {
		err = PTR_ERR(hdmi_cec_class);
		goto err_out_chrdev;
	}

	temp_class = device_create(hdmi_cec_class, NULL,
			MKDEV(hdmi_cec_major, 0), NULL, "mxc_hdmi_cec");
	if (IS_ERR(temp_class)) {
		err = PTR_ERR(temp_class);
		goto err_out_class;
	}

	pinctrl = devm_pinctrl_get_select_default(&pdev->dev);
	if (IS_ERR(pinctrl)) {
		dev_err(&pdev->dev, "can't get/select CEC pinctrl\n");
		goto err_out_class;
	}

	init_waitqueue_head(&hdmi_cec_queue);
	init_waitqueue_head(&hdmi_cec_sent);

	INIT_LIST_HEAD(&hdmi_cec_data.head);

	mutex_init(&hdmi_cec_data.lock);
	platform_set_drvdata(pdev, &hdmi_cec_data);
	INIT_DELAYED_WORK(&hdmi_cec_data.hdmi_cec_work, mxc_hdmi_cec_worker);

	dev_info(&pdev->dev, "HDMI CEC initialized\n");
	hdmi_cec_ready = 1;
	goto out;

err_out_class:
	device_destroy(hdmi_cec_class, MKDEV(hdmi_cec_major, 0));
	class_destroy(hdmi_cec_class);
err_out_chrdev:
	unregister_chrdev(hdmi_cec_major, "mxc_hdmi_cec");
out:
	return err;
}

static int hdmi_cec_dev_remove(struct platform_device *pdev)
{
	if (hdmi_cec_major > 0) {
		device_destroy(hdmi_cec_class, MKDEV(hdmi_cec_major, 0));
		class_destroy(hdmi_cec_class);
		unregister_chrdev(hdmi_cec_major, "mxc_hdmi_cec");
		hdmi_cec_major = 0;
	}
	return 0;
}

static const struct of_device_id imx_hdmi_cec_match[] = {
	{ .compatible = "fsl,imx6q-hdmi-cec", },
	{ .compatible = "fsl,imx6dl-hdmi-cec", },
	{ /* sentinel */ }
};

static struct platform_driver mxc_hdmi_cec_driver = {
	.probe = hdmi_cec_dev_probe,
	.remove = hdmi_cec_dev_remove,
	.driver = {
		.name = "mxc_hdmi_cec",
		.of_match_table	= imx_hdmi_cec_match,
	},
};

module_platform_driver(mxc_hdmi_cec_driver);

MODULE_AUTHOR("Freescale Semiconductor, Inc.");
MODULE_DESCRIPTION("Linux HDMI CEC driver for Freescale i.MX/MXC");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:mxc_hdmi_cec");

