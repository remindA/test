#!/usr/bin/env python3.5

# -*- coding:utf-8 -*-

# decode()
#   用法: bytes.decode(encoding="utf-8", error="strict")
#   作用: 将bytes转为encoding的string对象
#   返回: string对象

s = "牛亚犇123"
b = s.encode("utf-8", "strict")
ss = b.decode("utf-8", "strict")
print(b)
print(ss)




