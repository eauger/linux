/*
 * Copyright (C) 2016 - ARM Ltd
 *
 * stage2 page table helpers
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ARM64_S2_PGTABLE_H_
#define __ARM64_S2_PGTABLE_H_

#include <asm/pgtable.h>

/* The PGDIR shift for a given page table with "n" levels. */
#define pt_levels_pgdir_shift(n)	ARM64_HW_PGTABLE_LEVEL_SHIFT(4 - (n))

/*
 * The hardware supports concatenation of up to 16 tables at stage2 entry level
 * and we use the feature whenever possible.
 *
 * Now, the minimum number of bits resolved at any level is (PAGE_SHIFT - 3).
 * On arm64, the smallest PAGE_SIZE supported is 4k, which means
 *             (PAGE_SHIFT - 3) > 4 holds for all page sizes.
 * This implies, the total number of page table levels at stage2 expected
 * by the hardware is actually the number of levels required for (IPA_SHIFT - 4)
 * in normal translations(e.g, stage1), since we cannot have another level in
 * the range (IPA_SHIFT, IPA_SHIFT - 4).
 */
#define stage2_pt_levels(ipa_shift)	ARM64_HW_PGTABLE_LEVELS((ipa_shift) - 4)

/*
 * The number of PTRS across all concatenated stage2 tables given by the
 * number of bits resolved at the initial level.
 */
#define __s2_pgd_ptrs(pa, lvls)	(1 << ((pa) - pt_levels_pgdir_shift((lvls))))

#define stage2_pgdir_shift(kvm)	\
		pt_levels_pgdir_shift(kvm_stage2_levels(kvm))
#define stage2_pgdir_size(kvm)		(_AC(1, UL) << stage2_pgdir_shift((kvm)))
#define stage2_pgdir_mask(kvm)		(~(stage2_pgdir_size((kvm)) - 1))
#define stage2_pgd_ptrs(kvm)	\
	__s2_pgd_ptrs(kvm_phys_shift(kvm), kvm_stage2_levels(kvm))


/*
 * kvm_mmmu_cache_min_pages is the number of stage2 page table translation
 * levels in addition to the PGD.
 */
#define kvm_mmu_cache_min_pages(kvm)	(kvm_stage2_levels(kvm) - 1)


/* PUD/PMD definitions if present */
#define __S2_PUD_SHIFT			ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
#define __S2_PUD_SIZE			(_AC(1, UL) << __S2_PUD_SHIFT)
#define __S2_PUD_MASK			(~(__S2_PUD_SIZE - 1))

#define __S2_PMD_SHIFT			ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
#define __S2_PMD_SIZE			(_AC(1, UL) << __S2_PMD_SHIFT)
#define __S2_PMD_MASK			(~(__S2_PMD_SIZE - 1))

#define __s2_pud_index(addr) \
	(((addr) >> __S2_PUD_SHIFT) & (PTRS_PER_PTE - 1))
#define __s2_pmd_index(addr) \
	(((addr) >> __S2_PMD_SHIFT) & (PTRS_PER_PTE - 1))

static inline int stage2_pgd_none(struct kvm *kvm, pgd_t pgd)
{
	return (kvm_stage2_levels(kvm) > 3) ? __raw_pgd_none(pgd) : 0;
}

static inline void stage2_pgd_clear(struct kvm *kvm, pgd_t *pgdp)
{
	if (kvm_stage2_levels(kvm) > 3)
		__raw_pgd_clear(pgdp);
}

static inline int stage2_pgd_present(struct kvm *kvm, pgd_t pgd)
{
	return kvm_stage2_levels(kvm) > 3 ? __raw_pgd_present(pgd) : 1;
}

static inline void stage2_pgd_populate(struct kvm *kvm, pgd_t *pgdp, pud_t *pud)
{
	if (kvm_stage2_levels(kvm) > 3)
		__raw_pgd_populate(pgdp, __pa(pud), PUD_TYPE_TABLE);
	else
		BUG();
}

static inline pud_t *stage2_pud_offset(struct kvm *kvm,
					 pgd_t *pgd, unsigned long address)
{
	if (kvm_stage2_levels(kvm) > 3) {
		phys_addr_t pud_phys = __raw_pgd_page_paddr(*pgd);

		pud_phys += __s2_pud_index(address) * sizeof(pud_t);
		return __va(pud_phys);
	}
	return (pud_t *)pgd;
}

static inline void stage2_pud_free(struct kvm *kvm, pud_t *pud)
{
	if (kvm_stage2_levels(kvm) > 3)
		__raw_pud_free(pud);
}

static inline int stage2_pud_table_empty(struct kvm *kvm, pud_t *pudp)
{
	return kvm_stage2_levels(kvm) > 3 && kvm_page_empty(pudp);
}

static inline phys_addr_t
stage2_pud_addr_end(struct kvm *kvm, phys_addr_t addr, phys_addr_t end)
{
	if (kvm_stage2_levels(kvm) > 3) {
		phys_addr_t boundary = (addr + __S2_PUD_SIZE) & __S2_PUD_MASK;

		return (boundary - 1 < end - 1) ? boundary : end;
	}
	return end;
}

static inline int stage2_pud_none(struct kvm *kvm, pud_t pud)
{
	return kvm_stage2_levels(kvm) > 2 ? __raw_pud_none(pud) : 0;
}

static inline void stage2_pud_clear(struct kvm *kvm, pud_t *pudp)
{
	if (kvm_stage2_levels(kvm) > 2)
		__raw_pud_clear(pudp);
}

static inline int stage2_pud_present(struct kvm *kvm, pud_t pud)
{
	return kvm_stage2_levels(kvm) > 2 ? __raw_pud_present(pud) : 1;
}

static inline void stage2_pud_populate(struct kvm *kvm, pud_t *pudp, pmd_t *pmd)
{
	if (kvm_stage2_levels(kvm) > 2)
		__raw_pud_populate(pudp, __pa(pmd), PMD_TYPE_TABLE);
	else
		BUG();
}

static inline pmd_t *stage2_pmd_offset(struct kvm *kvm,
					 pud_t *pud, unsigned long address)
{
	if (kvm_stage2_levels(kvm) > 2) {
		phys_addr_t pmd_phys = __raw_pud_page_paddr(*pud);

		pmd_phys += __s2_pmd_index(address) * sizeof(pmd_t);
		return __va(pmd_phys);
	}
	return (pmd_t *)pud;
}

static inline void stage2_pmd_free(struct kvm *kvm, pmd_t *pmd)
{
	if (kvm_stage2_levels(kvm) > 2)
		__raw_pmd_free(pmd);
}

static inline int stage2_pmd_table_empty(struct kvm *kvm, pmd_t *pmdp)
{
	return kvm_stage2_levels(kvm) > 2 && kvm_page_empty(pmdp);
}

static inline phys_addr_t
stage2_pmd_addr_end(struct kvm *kvm, phys_addr_t addr, phys_addr_t end)
{
	if (kvm_stage2_levels(kvm) > 2) {
		phys_addr_t boundary = (addr + __S2_PMD_SIZE) & __S2_PMD_MASK;

		return (boundary - 1 < end - 1) ? boundary : end;
	}
	return end;
}

static inline int stage2_pud_huge(struct kvm *kvm, pud_t pud)
{
	return kvm_stage2_levels(kvm) > 2 ? __raw_pud_huge(pud) : 0;
}

#define stage2_pte_table_empty(kvm, ptep)	kvm_page_empty(ptep)

#define stage2_pgd_size(kvm)		(stage2_pgd_ptrs(kvm) * sizeof(pgd_t))

static inline unsigned long stage2_pgd_index(struct kvm *kvm, phys_addr_t addr)
{
	return (addr >> stage2_pgdir_shift(kvm)) & (stage2_pgd_ptrs(kvm) - 1);
}

static inline phys_addr_t
stage2_pgd_addr_end(struct kvm *kvm, phys_addr_t addr, phys_addr_t end)
{
	phys_addr_t boundary;

	boundary = (addr + stage2_pgdir_size(kvm)) & stage2_pgdir_mask(kvm);
	return (boundary - 1 < end - 1) ? boundary : end;
}

#endif	/* __ARM64_S2_PGTABLE_H_ */
