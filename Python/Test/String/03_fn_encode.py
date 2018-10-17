#!/usr/bin/env python3.5

# -*- coding:utf-8 -*-

# encode()
#   用法: string.encode(encoding="utf-8", error="strict")
#   作用: 将string转为encoding的bytes对象
#   返回: bytes对象

str = "牛亚犇123"
print(str.encode("utf-8", "strict"))
print(str.encode("gbk", "strict"))


