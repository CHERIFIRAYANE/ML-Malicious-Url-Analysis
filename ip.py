import re

def contains_ip_address(url):
    match = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5]))|'
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2}))|'
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    if match:
        return 1
    else:
        return 0

print(contains_ip_address('http://192.168.1.1'))  # Should print 1
print(contains_ip_address('http://0xC0.0xA8.0x01.0x01'))  # Should print 1
print(contains_ip_address('http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]'))  # Should print 1
print(contains_ip_address('www.queensouha.com'))  # Should print 1