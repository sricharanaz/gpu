/*
 * OF helpers for IOMMU
 *
 * Copyright (c) 2012, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/export.h>
#include <linux/iommu.h>
#include <linux/limits.h>
#include <linux/of.h>
#include <linux/of_iommu.h>
#include <linux/of_pci.h>
#include <linux/slab.h>

static const struct of_device_id __iommu_of_table_sentinel
	__used __section(__iommu_of_table_end);

/**
 * of_get_dma_window - Parse *dma-window property and returns 0 if found.
 *
 * @dn: device node
 * @prefix: prefix for property name if any
 * @index: index to start to parse
 * @busno: Returns busno if supported. Otherwise pass NULL
 * @addr: Returns address that DMA starts
 * @size: Returns the range that DMA can handle
 *
 * This supports different formats flexibly. "prefix" can be
 * configured if any. "busno" and "index" are optionally
 * specified. Set 0(or NULL) if not used.
 */
int of_get_dma_window(struct device_node *dn, const char *prefix, int index,
		      unsigned long *busno, dma_addr_t *addr, size_t *size)
{
	const __be32 *dma_window, *end;
	int bytes, cur_index = 0;
	char propname[NAME_MAX], addrname[NAME_MAX], sizename[NAME_MAX];

	if (!dn || !addr || !size)
		return -EINVAL;

	if (!prefix)
		prefix = "";

	snprintf(propname, sizeof(propname), "%sdma-window", prefix);
	snprintf(addrname, sizeof(addrname), "%s#dma-address-cells", prefix);
	snprintf(sizename, sizeof(sizename), "%s#dma-size-cells", prefix);

	dma_window = of_get_property(dn, propname, &bytes);
	if (!dma_window)
		return -ENODEV;
	end = dma_window + bytes / sizeof(*dma_window);

	while (dma_window < end) {
		u32 cells;
		const void *prop;

		/* busno is one cell if supported */
		if (busno)
			*busno = be32_to_cpup(dma_window++);

		prop = of_get_property(dn, addrname, NULL);
		if (!prop)
			prop = of_get_property(dn, "#address-cells", NULL);

		cells = prop ? be32_to_cpup(prop) : of_n_addr_cells(dn);
		if (!cells)
			return -EINVAL;
		*addr = of_read_number(dma_window, cells);
		dma_window += cells;

		prop = of_get_property(dn, sizename, NULL);
		cells = prop ? be32_to_cpup(prop) : of_n_size_cells(dn);
		if (!cells)
			return -EINVAL;
		*size = of_read_number(dma_window, cells);
		dma_window += cells;

		if (cur_index++ == index)
			break;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(of_get_dma_window);

struct of_iommu_node {
	struct list_head list;
	struct device_node *np;
	const struct iommu_ops *ops;
};
static LIST_HEAD(of_iommu_list);
static DEFINE_SPINLOCK(of_iommu_lock);

void of_iommu_set_ops(struct device_node *np, const struct iommu_ops *ops)
{
	struct of_iommu_node *iommu = kzalloc(sizeof(*iommu), GFP_KERNEL);

	if (WARN_ON(!iommu))
		return;

	of_node_get(np);
	INIT_LIST_HEAD(&iommu->list);
	iommu->np = np;
	iommu->ops = ops;
	spin_lock(&of_iommu_lock);
	list_add_tail(&iommu->list, &of_iommu_list);
	spin_unlock(&of_iommu_lock);
}

const struct iommu_ops *of_iommu_get_ops(struct device_node *np)
{
	struct of_iommu_node *node;
	const struct iommu_ops *ops = NULL;

	spin_lock(&of_iommu_lock);
	list_for_each_entry(node, &of_iommu_list, list)
		if (node->np == np) {
			ops = node->ops;
			break;
		}
	spin_unlock(&of_iommu_lock);
	return ops;
}

static int __get_pci_rid(struct pci_dev *pdev, u16 alias, void *data)
{
	struct of_phandle_args *iommu_spec = data;
	struct device_node *np = pdev->bus->dev.of_node;

	iommu_spec->args[0] = alias;
	return np == iommu_spec->np;
}

const struct iommu_ops *of_iommu_configure(struct device *dev,
					   struct device_node *master_np)
{
	struct of_phandle_args iommu_spec;
	struct device_node *np = NULL;
	const struct iommu_ops *ops = NULL;
	int idx = 0;

	if (dev_is_pci(dev)) {
		/*
		 * Start by tracing the RID alias down the PCI topology as
		 * far as the host bridge whose OF node we have...
		 */
		iommu_spec.np = master_np;
		pci_for_each_dma_alias(to_pci_dev(dev), __get_pci_rid,
				       &iommu_spec);
		/*
		 * ...then find out what that becomes once it escapes the PCI
		 * bus into the system beyond, and which IOMMU it ends up at.
		 */
		if (of_pci_map_rid(master_np, "iommu-map", iommu_spec.args[0],
				   &np, iommu_spec.args))
			return NULL;

		iommu_spec.np = np;
		iommu_spec.args_count = 1;
		ops = of_iommu_get_ops(np);
		if (!ops || !ops->of_xlate || ops->of_xlate(dev, &iommu_spec))
			goto err_put_node;

		of_node_put(np);
		return ops;
	}

	/*
	 * We don't currently walk up the tree looking for a parent IOMMU.
	 * See the `Notes:' section of
	 * Documentation/devicetree/bindings/iommu/iommu.txt
	 */
	while (!of_parse_phandle_with_args(master_np, "iommus",
					   "#iommu-cells", idx,
					   &iommu_spec)) {
		np = iommu_spec.np;
		ops = of_iommu_get_ops(np);

		if (!ops) {
			const struct of_device_id *oid;

			oid = of_match_node(&__iommu_of_table, np);
			ops = oid ? ERR_PTR(-EPROBE_DEFER) : NULL;
			goto err_put_node;
		}

		if (!ops->of_xlate || ops->of_xlate(dev, &iommu_spec)) {
			ops = NULL;
			goto err_put_node;
		}

		of_node_put(np);
		idx++;
	}

	return ops;

err_put_node:
	of_node_put(np);
	return ops;
}

static int __init of_iommu_init(void)
{
	struct device_node *np;
	const struct of_device_id *match, *matches = &__iommu_of_table;

	for_each_matching_node_and_match(np, matches, &match) {
		const of_iommu_init_fn init_fn = match->data;

		if (init_fn && init_fn(np))
			pr_err("Failed to initialise IOMMU %s\n",
				of_node_full_name(np));
	}

	return 0;
}
postcore_initcall_sync(of_iommu_init);
