---
layout: post
title:  "Luyên thuyên về cơ chế dọn rác của Unix garbage collector"
categories: knowledge
tags: linux-internal
author: th3_5had0w@Sarmat
mathjax: true
---

References count của file structure

Trong linux, Khi mở một file, kernel sẽ sử dụng file structure để represent cho file đó. Ở trên userland thì khi invoke thành công các hàm khởi tạo network socket hoặc họ hàng của function open() như open, openat,... sẽ trả về cho ta một số nguyên gọi là file descriptor number (thông thường là lớn hơn 2 vì 0 là standard input, 1 là standard output, 2 là standard error output). File descriptor number đó sẽ được sử dụng để index vào một table struct files_struct, vị trí được index ở trên table sẽ là một pointer trỏ đến file structure represent cho file mà ta vừa mở.