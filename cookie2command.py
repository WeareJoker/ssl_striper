cookie_command = ""

raw_cookies = input("Cookie: ")

for cookie in raw_cookies.split(';'):
    eq_index = cookie.find('=')

    cookie_command += 'document.cookie="%s=%s";' % (cookie[:eq_index], cookie[eq_index + 1:])

print("------------------------------------")
print(cookie_command[:-1])
