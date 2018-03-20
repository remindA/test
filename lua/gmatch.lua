local logs = "123\nabc\n456\ndef\n";
local i = 1;
for val in logs:gmatch("[^\n]+") do
    print(i, val)
    i = i + 1
end
