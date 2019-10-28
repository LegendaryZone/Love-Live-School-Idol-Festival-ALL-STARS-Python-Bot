# -*- coding: utf-8 -*-
import requests
import re

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SIFID(object):
	def __init__(self,user,pasw):
		self.user=user
		self.pasw=pasw
		self.s=requests.session()
		self.s.verify=False
		self.token=None
		self.s.headers.update({'Upgrade-Insecure-Requests':'1','User-Agent':'Mozilla/5.0 (Linux; Android 7.1.1; Nexus 9 Build/N9F27H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.107 Safari/537.36'})
		res=self.doLogin()
		if ' class="error-ico' in res.content:
			print '[-] login wrong ..'
			return None
		self.getToken(res)
		
	def giveMeToken(self):
		return self.token
		
	def doLogin(self):
		return self.s.post('https://www.sifid.net/login',data={'email':self.user,'password':self.pasw})
	
	def getToken(self,r):
		token=re.search('<input type="hidden" name="token" value="(.*)">',r.content).group(1)
		r=self.s.post('https://www.sifid.net/allow',data={'token':token},allow_redirects=False)
		self.token= re.sub('.*code=','',r.headers['Location'])

if __name__ == "__main__":
	a=SIFID('main@gmail.com','password')
	print a.token