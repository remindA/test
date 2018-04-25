local str = "niuyaben　\"and\" wuhuan"
print(str)

local s = string.gsub(str, "\"", ",")
print(s)


local s = 'adc"dww'
print(s)
local b = string.gsub(s, '"', "\'")
print(b)

