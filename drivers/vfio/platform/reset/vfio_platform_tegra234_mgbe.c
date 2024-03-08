// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO platform driver specialized for NVidia tegra234-mgbe reset
 * Code is inspired from dwxgmac2_dma.c and dwmac-tegra.c code
 *
 * Copyright (c) 2024 Red Hat, Inc.  All rights reserved.
 *     Author: Eric Auger <eric.auger@redhat.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/reset.h>
#include <linux/iopoll.h>
#include <linux/clk.h>

#include "../vfio_platform_private.h"

static const char *const mgbe_clks[] = {
	"rx-pcs", "tx", "tx-pcs", "mac-divider", "mac", "mgbe", "ptp-ref", "mac"
};

struct tegra_mgbe {
	struct clk_bulk_data *clks;
	struct reset_control *mac_rst;
	void __iomem *mac;
};

#define XGMAC_TX_CONFIG                 0x00000000
#define XGMAC_CONFIG_TE                 BIT(0)
#define XGMAC_RX_CONFIG                 0x00000004
#define XGMAC_CONFIG_RE                 BIT(0)
#define XGMAC_DMA_MODE			0x00003000
#define XGMAC_SWR			BIT(0)

#define XGMAC_DMA_CH_INT_EN(x)		(0x00003138 + (0x80 * (x)))
#define XGMAC_TIE			BIT(0)
#define XGMAC_RIE			BIT(6)
#define XGMAC_RBUE			BIT(7)
#define XGMAC_DMA_INT_DEFAULT_RX	(XGMAC_RBUE | XGMAC_RIE)
#define XGMAC_DMA_INT_DEFAULT_TX	(XGMAC_TIE)

#define XGMAC_DMA_CH_STATUS(x)		(0x00003160 + (0x80 * (x)))
#define XGMAC_DMA_CH_RX_CONTROL(x)      (0x00003108 + (0x80 * (x)))
#define XGMAC_RXST                      BIT(0)
#define XGMAC_DMA_CH_TX_CONTROL(x)      (0x00003104 + (0x80 * (x)))
#define XGMAC_TXST                      BIT(0)

#define XGMAC_INT_STATUS                0x000000b0
#define XGMAC_INT_EN                    0x000000b4

#define MGBE_WRAP_COMMON_INTR_ENABLE 0x8704

static int
toggle_reset(struct device *dev, const char *rst_str, struct reset_control *rst)
{
	int ret;

	ret = reset_control_assert(rst);
	if (ret < 0)
		dev_err(dev, "Failed to assert %s reset %d\n",
			rst_str, ret);
	usleep_range(2000, 4000);

	ret = reset_control_deassert(rst);
	if (ret < 0)
		dev_err(dev, "Failed to deassert %s reset %d\n", rst_str, ret);
	usleep_range(2000, 4000);
	return ret;
}

static void stop_dma(void __iomem *mac, uint channel)
{
	u32 value;

	/* DMA Stop RX */
	value = readl(mac + XGMAC_DMA_CH_RX_CONTROL(channel));
	value &= ~XGMAC_RXST;
	writel(value, mac + XGMAC_DMA_CH_RX_CONTROL(channel));

	value = readl(mac + XGMAC_RX_CONFIG);
	value &= ~XGMAC_CONFIG_RE;
	writel(value, mac + XGMAC_RX_CONFIG);

	usleep_range(10, 15);

	/* DMA Stop TX */
	value = readl(mac + XGMAC_DMA_CH_TX_CONTROL(channel));
	value &= ~XGMAC_RXST;
	writel(value, mac + XGMAC_DMA_CH_TX_CONTROL(channel));

	value = readl(mac + XGMAC_TX_CONFIG);
	value &= ~XGMAC_CONFIG_TE;
	writel(value, mac + XGMAC_TX_CONFIG);

	usleep_range(10, 15);
}

static int dma_sw_reset(void __iomem *mac)
{
	u32 value;

	value = readl(mac + XGMAC_DMA_MODE);
	writel(value | XGMAC_SWR, mac + XGMAC_DMA_MODE);
	return readl_poll_timeout(mac + XGMAC_DMA_MODE, value,
				  !(value & XGMAC_SWR), 0, 100000);
}

static void disable_dma_irq(void __iomem *mac, u32 channel)
{
	u32 intr_en, intr_status;

	intr_en = readl(mac + XGMAC_DMA_CH_INT_EN(channel));

	intr_en &= ~XGMAC_DMA_INT_DEFAULT_RX;
	intr_en &= ~XGMAC_DMA_INT_DEFAULT_TX;
	writel(intr_en, mac + XGMAC_DMA_CH_INT_EN(channel));
	usleep_range(10, 15);

	intr_status = readl(mac + XGMAC_DMA_CH_STATUS(channel));
	writel(0, mac + XGMAC_DMA_CH_STATUS(channel));
}

static int prepare_enable_clocks(struct device *dev, struct clk_bulk_data **clocks)
{
	struct clk_bulk_data *clks;
	int ret;

	clks = kcalloc(ARRAY_SIZE(mgbe_clks), sizeof(*clks), GFP_KERNEL);
	if (!clks)
		return -ENOMEM;

	for (int i = 0; i <  ARRAY_SIZE(mgbe_clks); i++)
		clks[i].id = mgbe_clks[i];

	ret = devm_clk_bulk_get(dev, ARRAY_SIZE(mgbe_clks), clks);
	if (ret < 0) {
		dev_err(dev, "Failed to get clocks %d\n", ret);
		return ret;
	}

	ret = clk_bulk_prepare_enable(ARRAY_SIZE(mgbe_clks), clks);
	if (ret < 0) {
		dev_err(dev, "Failed to prepare_enable clocks %d\n", ret);
		return ret;
	}
	*clocks = clks;
	return ret;
}

static int vfio_platform_tegra234_mgbe_init(struct vfio_platform_device *vpdev)
{
	struct tegra_mgbe *mgbe;
	struct vfio_platform_region *mac_regs;
	struct vfio_device *vdev = &vpdev->vdev;
	struct device *dev = vdev->dev;
	int ret = 0;

	mac_regs = vfio_platform_get_region(vpdev, "mac");
	if (!mac_regs)
		return -EINVAL;

	mgbe = devm_kmalloc(dev, sizeof(struct tegra_mgbe), GFP_KERNEL);
	if (!mgbe)
		return -ENOMEM;

	ret = prepare_enable_clocks(dev, &mgbe->clks);
	if (ret)
		return ret;

	mgbe->mac_rst = devm_reset_control_get(dev, "mac");
	if (IS_ERR(mgbe->mac_rst)) {
		dev_err(dev, "Failed to get mac reset %ld\n", PTR_ERR(mgbe->mac_rst));
		ret = PTR_ERR(mgbe->mac_rst);
		return ret;
	}

	mac_regs->ioaddr = ioremap(mac_regs->addr, mac_regs->size);
	if (!mac_regs->ioaddr)
		return -ENOMEM;

	mgbe->mac = mac_regs->ioaddr;
	vpdev->reset_opaque = mgbe;
	return ret;
}

static void vfio_platform_tegra234_mgbe_release(struct vfio_platform_device *vpdev)
{
	struct tegra_mgbe *mgbe = vpdev->reset_opaque;

	/* iounmap is done in vfio_platform_common */
	clk_bulk_disable_unprepare(ARRAY_SIZE(mgbe_clks), mgbe->clks);
	vpdev->reset_opaque = NULL;
}

static int vfio_platform_tegra234_mgbe_reset(struct vfio_platform_device *vpdev)
{
	struct tegra_mgbe *mgbe = vpdev->reset_opaque;
	struct vfio_device *vdev = &vpdev->vdev;
	struct device *dev = vdev->dev;
	int ret;

	if (!mgbe)
		return -ENODEV;

	toggle_reset(dev, "mac", mgbe->mac_rst);

	for (int i = 0; i < 10; i++)
		disable_dma_irq(mgbe->mac, i);

	writel(0, mgbe->mac + MGBE_WRAP_COMMON_INTR_ENABLE);

	for (int i = 0; i < 10; i++)
		stop_dma(mgbe->mac, i);

	ret = dma_sw_reset(mgbe->mac);
	if (ret)
		dev_err(dev, "Failed to reset the DMA %d\n", ret);

	return ret;
}

static const struct vfio_platform_of_reset_ops
vfio_platform_tegra234_mgbe_of_reset_ops = {
	.reset = vfio_platform_tegra234_mgbe_reset,
	.init = vfio_platform_tegra234_mgbe_init,
	.release = vfio_platform_tegra234_mgbe_release,
};

module_vfio_reset_handler("nvidia,tegra234-mgbe", vfio_platform_tegra234_mgbe_of_reset_ops);

MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eric Auger <eric.auger@redhat.com>");
MODULE_DESCRIPTION("Reset support for NVidia tegra234 mgbe vfio platform device");
