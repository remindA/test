local function add(a, b)
    return a + b
end

print(getfenv())
print(getfenv(add))
