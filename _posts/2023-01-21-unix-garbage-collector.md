---
layout: post
title:  "Luyên thuyên về cơ chế dọn rác của Unix garbage collector"
categories: knowledge
tags: linux-internal
author: th3_5had0w@Sarmat
mathjax: true
---

* content
{:toc}

Đêm 30 tháng 12 năm 2022 âm lịch
Thiên địa vô tư, tích thiện tự nhiên thiện
Thánh hiền hữu giáo, tu thân khả dĩ vinh




# References count của file structure

Trong linux, Khi mở một file, kernel sẽ sử dụng file structure để represent cho file đó. Ở trên userland thì khi invoke thành công các hàm khởi tạo network socket hoặc họ hàng của function open() như open, openat,... sẽ trả về cho ta một số nguyên gọi là file descriptor number (thông thường là lớn hơn 2 vì 0 là standard input, 1 là standard output, 2 là standard error output). File descriptor number đó sẽ được sử dụng để index vào một table struct files_struct, vị trí được index ở trên table sẽ là một pointer trỏ đến file structure represent cho file mà ta vừa mở.

Giả định khi ta mở một file (tạm gọi là A), thì file structure represent cho file A có một thuộc tính mang tên là f_count. mục đích của thuộc tính này là để đếm số lượng reference đến file A.

```cpp
struct file {
	union {
		struct llist_node	fu_llist;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
	struct inode		*f_inode;	/* cached value */
	const struct file_operations	*f_op;

	/*
	 * Protects f_ep, f_flags.
	 * Must not be taken from IRQ context.
	 */
	spinlock_t		f_lock;
	enum rw_hint		f_write_hint;
	atomic_long_t		f_count; // <-- reference counting
	unsigned int 		f_flags;
	fmode_t			f_mode;
	struct mutex		f_pos_lock;
	loff_t			f_pos;
	struct fown_struct	f_owner;
	const struct cred	*f_cred;
	struct file_ra_state	f_ra;

	u64			f_version;
#ifdef CONFIG_SECURITY
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others */
	void			*private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct hlist_head	*f_ep;
#endif /* #ifdef CONFIG_EPOLL */
	struct address_space	*f_mapping;
	errseq_t		f_wb_err;
	errseq_t		f_sb_err; /* for syncfs */
} __randomize_layout
  __attribute__((aligned(4)));	/* lest something weird decides that 2 is OK */
```