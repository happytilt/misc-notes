import requests
import time
import sys

r = requests.get('https://httpbin.org/get')

print(r.headers['Server'])
print(r.status_code)
print(r.elapsed)
print(r.cookies)
print(r.content)
print(r.text)

r = requests.get('https://httpbin.org/get', params={'id':'1'}, headers={'Accept':'application/json', 'testhead':'yo, gurt'})
print(r.url)
print(r.text)

r = requests.delete('https://httpbin.org/delete')
print(r.text)

r = requests.post('https://httpbin.org/post', data={'gurt':'yo'})
print(r.text)

files = {'file': open('picture.png', 'rb')}
r = requests.post('https://httpbin.org/post', files=files)
print(r.content)

r = requests.post('https://httpbin.org/post', auth=('username', 'password'))
print(r.text)

r = requests.get('https://httpbin.org/cookies', cookies={'me':'yogurt'})
print(r.text)
c = requests.session()
c.cookies.update({'gurt':'yo'})
print(c.get('https://httpbin.org/cookies').text)

print(c.get('https://httpbin.org/cookies').json())

r = requests.get('https://tryhackme-badges.s3.amazonaws.com/happytilt.png')
with open('thm-badge.png', 'wb') as img:
    img.write(r.content)