

--点的定义和调用

person = { money = 1000}

function person.spend(self, cost)
    self.money = self.money - cost or 0
end

--冒号的定义和调用
person.spend(person, 100)
print(person.money)

function person:work(time)
    self.money = self.money + time * 50
end

person:work(10)
cat:work(10)
print(person.money)


users = {{"name","passwd"}}

function users:add(name, passwd)
    self[#self+1] = {name, passwd}
end

    
