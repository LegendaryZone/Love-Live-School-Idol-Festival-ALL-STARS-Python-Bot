# -*- coding: utf-8 -*-
import sqlite3
import os.path

class Database(object):
	def __init__(self):
		self.sqlite_file='accounts.db'
		if not os.path.isfile(self.sqlite_file):
			self.createDb()

	def createDb(self):
		conn = sqlite3.connect(self.sqlite_file)
		c = conn.cursor()
		c.execute('''CREATE TABLE `accounts` (`id` INTEGER PRIMARY KEY AUTOINCREMENT,`password` TEXT,`coin`	INTEGER,`free_stone` INTEGER);''')
		conn.commit()
		conn.close()
		
	def addAccount(self,id,pw,coin,free_stone):
		conn = sqlite3.connect(self.sqlite_file)
		c = conn.cursor()
		c.execute("INSERT OR REPLACE INTO accounts (id,password,coin,free_stone) VALUES (%s,'%s',%s,%s)"%(id,pw,coin,free_stone))
		conn.commit()
		conn.close()

	def getAllAccounts(self,limit=None):
		conn = sqlite3.connect(self.sqlite_file)
		c = conn.cursor()
		if limit:
			c.execute("select id,password from accounts where free_stone>%s"%(limit))
		else:
			c.execute("select id,password from accounts")
		all_rows = c.fetchall()
		conn.close()
		return all_rows
		
if __name__ == '__main__':
	db=Database()
	db.createDb()