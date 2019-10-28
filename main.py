# -*- coding: utf-8 -*-
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from hashlib import sha1
import base64
import hashlib
import hmac
import io
import json
import os
import random
import re
import requests
import sys
import time
import inspect
import socket
import struct
from db import Database

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class API(object):
	def __init__(self):
		self.s=requests.Session()
		self.s.headers.update({'Content-Type':'application/json','User-Agent':'allstars/5 CFNetwork/808.2.16 Darwin/16.3.0','Accept-Language':'en-gb'})
		self.s.verify=False
		if 'win' in sys.platform:
			self.s.proxies.update({'http': 'http://127.0.0.1:8888','https': 'https://127.0.0.1:8888',})
		self.game_api='https://jp-real-prod-v4tadlicuqeeumke.api.game25.klabgames.net/ep1010'
		self.auth_count=1
		self.startupkey='G5OdK4KdQO5UM2nL'
		self.publicKey='''-----BEGIN PUBLIC KEY-----
						MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ZUSWq8LCuF2JclEp6uuW9+yd
						dLQvb2420+F8rxIF8+W53BiF8g9m6nCETdRw7RVnzNABevMndCCTD6oQ6a2w0Qpo
						KeT26578UCWtGp74NGg2Q2fHYFMAhTytVk48qO4ViCN3snFs0AURU06niM98MIcE
						Unj9vj6kOBlOGv4JWQIDAQAB
						-----END PUBLIC KEY-----'''
		self.id=1
		self.db=Database()

	def exportPlayer(self,coin,free_stone,file=False):
		self.db.addAccount(self.user_id,base64.b64encode(self.pw),coin,free_stone)

	def setproxy(self,prox=None):
		self.s.proxies.update({'http': 'http://127.0.0.1:8888','https': 'https://127.0.0.1:8888',})

	def rndHex(self,n):
		res= ''.join([random.choice('0123456789ABCDEF') for x in range(n)]).lower()
		if n==32:	self.log('rndHex called %s'%(res))
		return res

	def rndBytes(self,n):
		return os.urandom(n)
		
	def generateMaskData(self):
		key = RSA.importKey(self.publicKey)
		cipher = PKCS1_OAEP.new(key)
		self.rndkey=self.rndBytes(32)
		self.log('rndkey:%s'%(self.rndkey.encode('hex')))
		return base64.encodestring(cipher.encrypt(self.rndkey)).replace('\n','')

	def xor(self,v1,v2):
		return ''.join([chr(ord(a) ^ ord(b)).encode('hex') for (a,b) in zip(v1, v2)]).decode('hex')
		
	def md5(self,s):
		m = hashlib.md5()
		m.update(s)
		return m.hexdigest()

	def resemara_id(self):
		return self.md5('?%s-%s-%s-%s-%s com.klab.lovelive.allstars'%(self.rndHex(8).upper(),self.rndHex(4).upper(),self.rndHex(4).upper(),self.rndHex(4).upper(),self.rndHex(12).upper())).upper()

	def calcDigest(self,raw,key=None):
		if not key:	key=self.startupkey
		if hasattr(self,'key'):	key=self.key
		raw=raw.replace('https://jp-real-prod-v4tadlicuqeeumke.api.game25.klabgames.net/ep1010','')
		hashed = hmac.new(key, raw, sha1)
		return hashed.digest().encode("hex").rstrip('\n')

	def log(self,msg):
		print '[%s]%s'%(time.strftime('%H:%M:%S'),msg.encode('utf-8'))
		
	def setUserId(self,id):
		self.user_id=id
		
	def setPassword(self,pw):
		self.startupkey=base64.b64decode(pw)
		
	def save(self,d,f):
		with io.open(f, 'a', encoding='utf8') as the_file:
			the_file.write('%s\n'%(unicode(d)))

	def genRandomIP(self):
		return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

	def callAPI(self,url,data,key=None):
		self.log('%s() called'%(inspect.stack()[1][3]))
		uris=[]
		uris.append('p=i')
		if hasattr(self,'mv'):
			uris.append('mv=%s'%(self.mv))
		uris.append('id=%s'%(self.id))
		if hasattr(self,'user_id'):
			uris.append('u=%s'%(self.user_id))
			if self.id>1:	uris.append('t=%s'%(int(time.time()*1000)))
		finurl=self.game_api+url+'?'+'&'.join(uris)
		data='[%s,"%s"]'%(data,self.calcDigest('%s %s'%(re.sub('.*ep[0-9]*','',finurl),data),key))
		r=self.s.post(finurl,data=data)
		if r.status_code<>200:
			self.log('bad status code:%s'%(r.status_code))
			return None
		jdata=json.loads(r.content)
		if jdata[2]==1 and 'authorization_count' in jdata[3]:
			self.auth_count=jdata[3]['authorization_count']+1
			return self.login()
		if 'update_info' in jdata[3] and 'user' in jdata[3]['update_info']:
			self.userid=jdata[3]['update_info']['user']['id']
			self.log('welcome %s:%s'%(jdata[3]['update_info']['user']['id'],jdata[3]['update_info']['user']['name']))
		if 'user_id' in jdata[3]:
			self.user_id=jdata[3]['user_id']
		if 'authorization_key' in r.content:
			self.log('authorization_key:%s'%(base64.b64decode(jdata[3]['authorization_key']).encode('hex')))
			self.key=self.xor(self.rndkey,base64.b64decode(jdata[3]['authorization_key']))
			self.pw=self.key
			self.log('password:%s'%(base64.b64encode(self.pw)))
		if 'session_key' in jdata[3]:
			self.log('session_key:%s'%(base64.b64decode(jdata[3]['session_key']).encode('hex')))
			self.key=self.xor(self.rndkey,base64.b64decode(jdata[3]['session_key']))
		if 'master_version' in jdata[3]:
			self.mv=jdata[3]['master_version']['version']
		self.id+=1
		time.sleep(1)
		return jdata

	def startup(self):
		res=self.login_startup('{"mask":"%s","resemara_detection_identifier":"%s","time_difference":10800}'%(self.generateMaskData(),self.resemara_id()))
		self.mv=res[1]
		self.user_id=res[3]['user_id']
		self.log('hello %s'%(res[3]['user_id']))
		return res

	def login(self):
		res= self.login_login('{"user_id":%s,"auth_count":%s,"mask":"%s","asset_state":""}'%(self.user_id,self.auth_count,self.generateMaskData()))
		self.mv=res[1]
		return res

	def livePartners_fetch(self):
		return self.callAPI('/livePartners/fetch',None)

	def gacha_fetchGachaMenu(self):
		return self.callAPI('/gacha/fetchGachaMenu',None)

	def tutorial_phaseEnd(self):
		return self.callAPI('/tutorial/phaseEnd',None)

	def notice_fetchNotice(self):
		return self.callAPI('/notice/fetchNotice',None)

	def present_fetch(self):
		res= self.callAPI('/present/fetch',None)
		ids=[]
		for i in res[3]['present_items']:
			ids.append(i['id'])
		if len(ids)>=1:
			res= self.present_receive('{"ids":[%s]}'%(','.join([str(x) for x in ids])))
		return res

	def shop_fetchShopSnsCoin(self):
		return self.callAPI('/shop/fetchShopSnsCoin',None)

	def shop_fetchShopTop(self):
		return self.callAPI('/shop/fetchShopTop',None)

	def shop_fetchShopPack(self):
		return self.callAPI('/shop/fetchShopPack',None)

	def bootstrap_getClearedPlatformAchievement(self):
		return self.callAPI('/bootstrap/getClearedPlatformAchievement',None)

	def shop_fetchShopItemExchange(self):
		return self.callAPI('/shop/fetchShopItemExchange',None)

	def emblem_fetchEmblem(self):
		return self.callAPI('/emblem/fetchEmblem',None)

	def mission_fetchMission(self):
		return self.callAPI('/mission/fetchMission',None)

	def live_fetchLiveMusicSelect(self):
		return self.callAPI('/live/fetchLiveMusicSelect',None)
	
	def login_startup(self,data):
		return self.callAPI('/login/startup',data)

	def login_login(self,data):
		return self.callAPI('/login/login',data)

	def terms_agreement(self,data):
		return self.callAPI('/terms/agreement',data)

	def asset_getPackUrl(self,data):
		return self.callAPI('/asset/getPackUrl',data)

	def userProfile_setProfile(self,data):
		return self.callAPI('/userProfile/setProfile',data)

	def userProfile_setProfileBirthday(self,data):
		return self.callAPI('/userProfile/setProfileBirthday',data)

	def story_finishUserStoryMain(self,data):
		return self.callAPI('/story/finishUserStoryMain',data)

	def live_start(self,data):
		return self.callAPI('/live/start',data)

	def ruleDescription_saveRuleDescription(self,data):
		return self.callAPI('/ruleDescription/saveRuleDescription',data)

	def live_finish(self,data):
		return self.callAPI('/live/finish',data)

	def communicationMember_setFavoriteMember(self,data):
		return self.callAPI('/communicationMember/setFavoriteMember',data)

	def bootstrap_fetchBootstrap(self,data):
		return self.callAPI('/bootstrap/fetchBootstrap',data)

	def navi_tapLovePoint(self,data):
		return self.callAPI('/navi/tapLovePoint',data)

	def navi_saveUserNaviVoice(self,data):
		return self.callAPI('/navi/saveUserNaviVoice',data)

	def trainingTree_fetchTrainingTree(self,data):
		return self.callAPI('/trainingTree/fetchTrainingTree',data)

	def trainingTree_levelUpCard(self,data):
		return self.callAPI('/trainingTree/levelUpCard',data)

	def trainingTree_activateTrainingTreeCell(self,data):
		return self.callAPI('/trainingTree/activateTrainingTreeCell',data)

	def communicationMember_finishUserStorySide(self,data):
		return self.callAPI('/communicationMember/finishUserStorySide',data)

	def card_updateCardNewFlag(self,data):
		return self.callAPI('/card/updateCardNewFlag',data)

	def liveDeck_saveDeckAll(self,data):
		return self.callAPI('/liveDeck/saveDeckAll',data)

	def liveDeck_saveSuit(self,data):
		return self.callAPI('/liveDeck/saveSuit',data)

	def gacha_draw(self,data):
		return self.callAPI('/gacha/draw',data)

	def loginBonus_readLoginBonus(self,data):
		return self.callAPI('/loginBonus/readLoginBonus',data)

	def notice_fetchNoticeDetail(self,data):
		return self.callAPI('/notice/fetchNoticeDetail',data)

	def present_receive(self,data):
		return self.callAPI('/present/receive',data)

	def eventMarathon_fetchEventMarathon(self,data):
		return self.callAPI('/eventMarathon/fetchEventMarathon',data)

	def mission_clearMissionNewBadge(self,data):
		return self.callAPI('/mission/clearMissionNewBadge',data)

	def infoTrigger_read(self,data):
		return self.callAPI('/infoTrigger/read',data)

	def unlockScene_saveUnlockedScene(self,data):
		return self.callAPI('/unlockScene/saveUnlockedScene',data)

	def card_changeIsAwakeningImage(self,data):
		return self.callAPI('/card/changeIsAwakeningImage',data)
	
	def getDailyBonus(self,s3):
		if s3[3]['fetch_bootstrap_login_bonus_response']:
			for i in s3[3]['fetch_bootstrap_login_bonus_response']:
				if 'event_2d_login_bonuses' in i:
					login_bonus_type=3
				elif 'birthday_login_bonuses' in i:
					login_bonus_type=5
				elif 'beginner_login_bonuses' in i:
					login_bonus_type=2
				elif 'login_bonuses' in i:
					login_bonus_type=1
				for q in s3[3]['fetch_bootstrap_login_bonus_response'][i]:
					self.readLoginBonus('{"login_bonus_id":%s,"login_bonus_type":%s}'%(q['login_bonus_id'],login_bonus_type))

	def dailylogin(self):
		self.login()
		s3=self.bootstrap_fetchBootstrap('{"bootstrap_fetch_types":[2,3,4,5,9,10],"device_token":"","device_name":""}')
		self.getDailyBonus(s3)
		self.present_fetch()
	
	def reroll(self,name='Mila432'):
		self.startup()
		self.login()
		self.terms_agreement('{"terms_version":1}')
		self.userProfile_setProfile('{"device_token":"","name":"%s"}'%(name))
		self.userProfile_setProfile('{"device_token":"","nickname":"%s"}'%(name))
		self.userProfile_setProfileBirthday('{"day":1,"month":1}')
		self.story_finishUserStoryMain('{"is_auto_mode":false,"cell_id":1001}')
		s1=self.live_start('{"deck_id":1,"cell_id":1002,"partner_card_master_id":0,"live_difficulty_id":30001301,"lp_magnification":1,"is_auto_play":false,"partner_user_id":0}')
		self.ruleDescription_saveRuleDescription('{"rule_description_master_ids":[1]}')
		self.live_finish('{"live_id":'+str(s1[3]['live']['live_id'])+',"resume_finish_info":{"cached_judge_result":[]},"live_score":{"use_debuf_active_skill_count":0,"target_score":35000,"use_sp_skill_count":1,"use_buf_active_skill_count":12,"current_score":46825,"change_squad_count":0,"card_stat_dict":[100011001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100011001,"recast_squad_effect_count":0},100041001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100041001,"recast_squad_effect_count":0},100031001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100031001,"recast_squad_effect_count":0},100061001,{"skill_triggered_count":5,"appeal_count":18,"got_voltage":13218,"card_master_id":100061001,"recast_squad_effect_count":0},100021001,{"skill_triggered_count":6,"appeal_count":18,"got_voltage":15346,"card_master_id":100021001,"recast_squad_effect_count":0},100081001,{"skill_triggered_count":7,"appeal_count":18,"got_voltage":12277,"card_master_id":100081001,"recast_squad_effect_count":0},100091001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100091001,"recast_squad_effect_count":0},100051001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100051001,"recast_squad_effect_count":0},100071001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100071001,"recast_squad_effect_count":0}],"use_voltage_active_skill_count":0,"use_heal_active_skill_count":0,"remaining_stamina":6530,"live_power":1040,"turn_stat_dict":[1,{"note_id":1,"current_life":6577,"appended_shield":0,"healed_life_percent":0,"current_voltage":730,"stamina_damage":1,"healed_life":0},2,{"note_id":2,"current_life":6576,"appended_shield":0,"healed_life_percent":0,"current_voltage":1533,"stamina_damage":1,"healed_life":0},3,{"note_id":3,"current_life":6575,"appended_shield":0,"healed_life_percent":0,"current_voltage":2197,"stamina_damage":1,"healed_life":0},4,{"note_id":4,"current_life":6574,"appended_shield":0,"healed_life_percent":0,"current_voltage":2927,"stamina_damage":1,"healed_life":0},5,{"note_id":5,"current_life":6573,"appended_shield":0,"healed_life_percent":0,"current_voltage":3657,"stamina_damage":1,"healed_life":0},6,{"note_id":6,"current_life":6572,"appended_shield":0,"healed_life_percent":0,"current_voltage":4387,"stamina_damage":1,"healed_life":0},7,{"note_id":7,"current_life":6571,"appended_shield":0,"healed_life_percent":0,"current_voltage":5117,"stamina_damage":1,"healed_life":0},8,{"note_id":8,"current_life":6570,"appended_shield":0,"healed_life_percent":0,"current_voltage":5920,"stamina_damage":1,"healed_life":0},9,{"note_id":9,"current_life":6569,"appended_shield":0,"healed_life_percent":0,"current_voltage":6650,"stamina_damage":1,"healed_life":0},10,{"note_id":10,"current_life":6568,"appended_shield":0,"healed_life_percent":0,"current_voltage":7314,"stamina_damage":1,"healed_life":0},11,{"note_id":11,"current_life":6567,"appended_shield":0,"healed_life_percent":0,"current_voltage":8190,"stamina_damage":1,"healed_life":0},12,{"note_id":12,"current_life":6566,"appended_shield":0,"healed_life_percent":0,"current_voltage":8986,"stamina_damage":1,"healed_life":0},13,{"note_id":13,"current_life":6566,"appended_shield":0,"healed_life_percent":0,"current_voltage":9716,"stamina_damage":0,"healed_life":0},14,{"note_id":14,"current_life":6566,"appended_shield":0,"healed_life_percent":0,"current_voltage":10592,"stamina_damage":0,"healed_life":0},15,{"note_id":15,"current_life":6565,"appended_shield":0,"healed_life_percent":0,"current_voltage":11388,"stamina_damage":1,"healed_life":0},16,{"note_id":16,"current_life":6564,"appended_shield":0,"healed_life_percent":0,"current_voltage":12052,"stamina_damage":1,"healed_life":0},17,{"note_id":17,"current_life":6563,"appended_shield":0,"healed_life_percent":0,"current_voltage":12928,"stamina_damage":1,"healed_life":0},18,{"note_id":18,"current_life":6562,"appended_shield":0,"healed_life_percent":0,"current_voltage":13658,"stamina_damage":1,"healed_life":0},19,{"note_id":19,"current_life":6561,"appended_shield":0,"healed_life_percent":0,"current_voltage":14454,"stamina_damage":1,"healed_life":0},20,{"note_id":20,"current_life":6560,"appended_shield":0,"healed_life_percent":0,"current_voltage":15330,"stamina_damage":1,"healed_life":0},21,{"note_id":21,"current_life":6559,"appended_shield":0,"healed_life_percent":0,"current_voltage":15994,"stamina_damage":1,"healed_life":0},22,{"note_id":22,"current_life":6558,"appended_shield":0,"healed_life_percent":0,"current_voltage":16790,"stamina_damage":1,"healed_life":0},23,{"note_id":24,"current_life":6557,"appended_shield":0,"healed_life_percent":0,"current_voltage":16790,"stamina_damage":1,"healed_life":0},24,{"note_id":0,"current_life":6556,"appended_shield":0,"healed_life_percent":0,"current_voltage":16790,"stamina_damage":1,"healed_life":0},25,{"note_id":26,"current_life":6554,"appended_shield":0,"healed_life_percent":0,"current_voltage":17520,"stamina_damage":2,"healed_life":0},26,{"note_id":0,"current_life":6554,"appended_shield":0,"healed_life_percent":0,"current_voltage":18323,"stamina_damage":0,"healed_life":0},27,{"note_id":28,"current_life":6552,"appended_shield":0,"healed_life_percent":0,"current_voltage":19053,"stamina_damage":2,"healed_life":0},28,{"note_id":0,"current_life":6552,"appended_shield":0,"healed_life_percent":0,"current_voltage":19783,"stamina_damage":0,"healed_life":0},29,{"note_id":30,"current_life":6550,"appended_shield":0,"healed_life_percent":0,"current_voltage":20659,"stamina_damage":2,"healed_life":0},30,{"note_id":0,"current_life":6550,"appended_shield":0,"healed_life_percent":0,"current_voltage":21455,"stamina_damage":0,"healed_life":0},31,{"note_id":31,"current_life":6550,"appended_shield":0,"healed_life_percent":0,"current_voltage":22185,"stamina_damage":0,"healed_life":0},32,{"note_id":32,"current_life":6550,"appended_shield":0,"healed_life_percent":0,"current_voltage":22988,"stamina_damage":0,"healed_life":0},33,{"note_id":33,"current_life":6549,"appended_shield":0,"healed_life_percent":0,"current_voltage":23784,"stamina_damage":1,"healed_life":0},34,{"note_id":34,"current_life":6548,"appended_shield":0,"healed_life_percent":0,"current_voltage":24448,"stamina_damage":1,"healed_life":0},35,{"note_id":35,"current_life":6547,"appended_shield":0,"healed_life_percent":0,"current_voltage":31637,"stamina_damage":1,"healed_life":0},36,{"note_id":36,"current_life":6546,"appended_shield":0,"healed_life_percent":0,"current_voltage":32367,"stamina_damage":1,"healed_life":0},37,{"note_id":37,"current_life":6545,"appended_shield":0,"healed_life_percent":0,"current_voltage":33242,"stamina_damage":1,"healed_life":0},38,{"note_id":38,"current_life":6544,"appended_shield":0,"healed_life_percent":0,"current_voltage":34205,"stamina_damage":1,"healed_life":0},39,{"note_id":39,"current_life":6543,"appended_shield":0,"healed_life_percent":0,"current_voltage":35001,"stamina_damage":1,"healed_life":0},40,{"note_id":40,"current_life":6542,"appended_shield":0,"healed_life_percent":0,"current_voltage":35731,"stamina_damage":1,"healed_life":0},41,{"note_id":42,"current_life":6540,"appended_shield":0,"healed_life_percent":0,"current_voltage":36534,"stamina_damage":2,"healed_life":0},42,{"note_id":0,"current_life":6540,"appended_shield":0,"healed_life_percent":0,"current_voltage":37264,"stamina_damage":0,"healed_life":0},43,{"note_id":43,"current_life":6539,"appended_shield":0,"healed_life_percent":0,"current_voltage":38060,"stamina_damage":1,"healed_life":0},44,{"note_id":44,"current_life":6538,"appended_shield":0,"healed_life_percent":0,"current_voltage":38936,"stamina_damage":1,"healed_life":0},45,{"note_id":45,"current_life":6537,"appended_shield":0,"healed_life_percent":0,"current_voltage":39600,"stamina_damage":1,"healed_life":0},46,{"note_id":46,"current_life":6536,"appended_shield":0,"healed_life_percent":0,"current_voltage":40131,"stamina_damage":1,"healed_life":0},47,{"note_id":48,"current_life":6534,"appended_shield":0,"healed_life_percent":0,"current_voltage":41227,"stamina_damage":2,"healed_life":0},48,{"note_id":0,"current_life":6534,"appended_shield":0,"healed_life_percent":0,"current_voltage":41891,"stamina_damage":0,"healed_life":0},49,{"note_id":49,"current_life":6534,"appended_shield":0,"healed_life_percent":0,"current_voltage":42687,"stamina_damage":0,"healed_life":0},50,{"note_id":50,"current_life":6534,"appended_shield":0,"healed_life_percent":0,"current_voltage":43892,"stamina_damage":0,"healed_life":0},51,{"note_id":51,"current_life":6533,"appended_shield":0,"healed_life_percent":0,"current_voltage":44423,"stamina_damage":1,"healed_life":0},52,{"note_id":52,"current_life":6532,"appended_shield":0,"healed_life_percent":0,"current_voltage":45219,"stamina_damage":1,"healed_life":0},53,{"note_id":53,"current_life":6531,"appended_shield":0,"healed_life_percent":0,"current_voltage":46095,"stamina_damage":1,"healed_life":0},54,{"note_id":54,"current_life":6530,"appended_shield":0,"healed_life_percent":0,"current_voltage":46825,"stamina_damage":1,"healed_life":0},0,{"note_id":0,"current_life":6578,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0},55,{"note_id":0,"current_life":6530,"appended_shield":0,"healed_life_percent":0,"current_voltage":46825,"stamina_damage":0,"healed_life":0}],"highest_combo_count":9,"combo_count":3,"wave_stat":[],"result_dict":[1,{"judge_type":20,"card_master_id":0,"voltage":730},2,{"judge_type":20,"card_master_id":0,"voltage":803},3,{"judge_type":14,"card_master_id":0,"voltage":664},4,{"judge_type":20,"card_master_id":0,"voltage":730},5,{"judge_type":14,"card_master_id":0,"voltage":730},6,{"judge_type":20,"card_master_id":0,"voltage":730},7,{"judge_type":20,"card_master_id":0,"voltage":730},8,{"judge_type":20,"card_master_id":0,"voltage":803},9,{"judge_type":20,"card_master_id":0,"voltage":730},10,{"judge_type":14,"card_master_id":0,"voltage":664},11,{"judge_type":30,"card_master_id":0,"voltage":876},12,{"judge_type":30,"card_master_id":0,"voltage":796},13,{"judge_type":20,"card_master_id":0,"voltage":730},14,{"judge_type":30,"card_master_id":0,"voltage":876},15,{"judge_type":30,"card_master_id":0,"voltage":796},16,{"judge_type":14,"card_master_id":0,"voltage":664},17,{"judge_type":30,"card_master_id":0,"voltage":876},18,{"judge_type":20,"card_master_id":0,"voltage":730},19,{"judge_type":30,"card_master_id":0,"voltage":796},20,{"judge_type":30,"card_master_id":0,"voltage":876},21,{"judge_type":14,"card_master_id":0,"voltage":664},22,{"judge_type":30,"card_master_id":0,"voltage":796},23,{"judge_type":10,"card_master_id":0,"voltage":0},24,{"judge_type":10,"card_master_id":0,"voltage":0},25,{"judge_type":20,"card_master_id":0,"voltage":730},26,{"judge_type":20,"card_master_id":0,"voltage":803},27,{"judge_type":20,"card_master_id":0,"voltage":730},28,{"judge_type":20,"card_master_id":0,"voltage":730},29,{"judge_type":30,"card_master_id":0,"voltage":876},30,{"judge_type":30,"card_master_id":0,"voltage":796},31,{"judge_type":20,"card_master_id":0,"voltage":730},32,{"judge_type":20,"card_master_id":0,"voltage":803},33,{"judge_type":30,"card_master_id":0,"voltage":796},34,{"judge_type":14,"card_master_id":0,"voltage":664},35,{"judge_type":14,"card_master_id":0,"voltage":1205},36,{"judge_type":14,"card_master_id":0,"voltage":730},37,{"judge_type":30,"card_master_id":0,"voltage":875},38,{"judge_type":30,"card_master_id":0,"voltage":963},39,{"judge_type":30,"card_master_id":0,"voltage":796},40,{"judge_type":20,"card_master_id":0,"voltage":730},41,{"judge_type":20,"card_master_id":0,"voltage":803},42,{"judge_type":20,"card_master_id":0,"voltage":730},43,{"judge_type":30,"card_master_id":0,"voltage":796},44,{"judge_type":30,"card_master_id":0,"voltage":876},45,{"judge_type":14,"card_master_id":0,"voltage":664},46,{"judge_type":12,"card_master_id":0,"voltage":531},47,{"judge_type":14,"card_master_id":0,"voltage":1096},48,{"judge_type":14,"card_master_id":0,"voltage":664},49,{"judge_type":30,"card_master_id":0,"voltage":796},50,{"judge_type":20,"card_master_id":0,"voltage":1205},51,{"judge_type":12,"card_master_id":0,"voltage":531},52,{"judge_type":30,"card_master_id":0,"voltage":796},53,{"judge_type":30,"card_master_id":0,"voltage":876},54,{"judge_type":20,"card_master_id":0,"voltage":730}],"is_perfect_full_combo":false,"is_perfect_live":false},"live_finish_status":1}')
		self.story_finishUserStoryMain('{"is_auto_mode":false,"cell_id":1003}')
		s1=self.live_start('{"deck_id":2,"cell_id":1004,"partner_card_master_id":0,"live_difficulty_id":31007301,"lp_magnification":1,"is_auto_play":false,"partner_user_id":0}')
		self.ruleDescription_saveRuleDescription('{"rule_description_master_ids":[2]}')
		self.live_finish('{"live_id":'+str(s1[3]['live']['live_id'])+',"resume_finish_info":{"cached_judge_result":[]},"live_score":{"use_debuf_active_skill_count":0,"target_score":40000,"use_sp_skill_count":1,"use_buf_active_skill_count":5,"current_score":56586,"change_squad_count":0,"card_stat_dict":[101011001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":101011001,"recast_squad_effect_count":0},101021001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":101021001,"recast_squad_effect_count":0},101051001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":101051001,"recast_squad_effect_count":0},101091001,{"skill_triggered_count":6,"appeal_count":23,"got_voltage":13962,"card_master_id":101091001,"recast_squad_effect_count":0},101031001,{"skill_triggered_count":5,"appeal_count":22,"got_voltage":17539,"card_master_id":101031001,"recast_squad_effect_count":0},101071001,{"skill_triggered_count":6,"appeal_count":22,"got_voltage":20086,"card_master_id":101071001,"recast_squad_effect_count":0},101041001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":101041001,"recast_squad_effect_count":0},101061001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":101061001,"recast_squad_effect_count":0},101081001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":101081001,"recast_squad_effect_count":0}],"use_voltage_active_skill_count":0,"use_heal_active_skill_count":6,"remaining_stamina":5812,"live_power":1047,"turn_stat_dict":[1,{"note_id":1,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":707,"stamina_damage":0,"healed_life":0},2,{"note_id":2,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":1485,"stamina_damage":0,"healed_life":0},3,{"note_id":3,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":2663,"stamina_damage":0,"healed_life":0},4,{"note_id":4,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":3370,"stamina_damage":0,"healed_life":0},5,{"note_id":5,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":4148,"stamina_damage":0,"healed_life":0},6,{"note_id":6,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":4862,"stamina_damage":0,"healed_life":0},7,{"note_id":7,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":5569,"stamina_damage":0,"healed_life":150},8,{"note_id":8,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":6347,"stamina_damage":0,"healed_life":0},9,{"note_id":9,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":7632,"stamina_damage":0,"healed_life":0},10,{"note_id":10,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":8221,"stamina_damage":0,"healed_life":0},11,{"note_id":11,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":8999,"stamina_damage":0,"healed_life":0},12,{"note_id":12,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":10284,"stamina_damage":0,"healed_life":0},13,{"note_id":13,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":10932,"stamina_damage":0,"healed_life":0},14,{"note_id":14,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":11580,"stamina_damage":0,"healed_life":0},15,{"note_id":15,"current_life":5812,"appended_shield":200,"healed_life_percent":0,"current_voltage":12436,"stamina_damage":0,"healed_life":0},16,{"note_id":16,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":13143,"stamina_damage":0,"healed_life":150},17,{"note_id":17,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":13921,"stamina_damage":0,"healed_life":0},18,{"note_id":18,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":14777,"stamina_damage":0,"healed_life":0},19,{"note_id":19,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":15366,"stamina_damage":0,"healed_life":0},20,{"note_id":20,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":16014,"stamina_damage":0,"healed_life":0},21,{"note_id":21,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":16728,"stamina_damage":0,"healed_life":0},22,{"note_id":22,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":17376,"stamina_damage":0,"healed_life":0},23,{"note_id":23,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":18445,"stamina_damage":0,"healed_life":0},24,{"note_id":24,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":19301,"stamina_damage":0,"healed_life":0},25,{"note_id":25,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":20008,"stamina_damage":0,"healed_life":0},26,{"note_id":26,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":20786,"stamina_damage":0,"healed_life":0},27,{"note_id":27,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":21642,"stamina_damage":0,"healed_life":0},28,{"note_id":28,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":22231,"stamina_damage":0,"healed_life":0},29,{"note_id":29,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":23009,"stamina_damage":0,"healed_life":0},30,{"note_id":30,"current_life":5812,"appended_shield":200,"healed_life_percent":0,"current_voltage":23865,"stamina_damage":0,"healed_life":0},31,{"note_id":31,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":24572,"stamina_damage":0,"healed_life":150},32,{"note_id":32,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":25350,"stamina_damage":0,"healed_life":0},33,{"note_id":33,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":26134,"stamina_damage":0,"healed_life":0},34,{"note_id":34,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":26841,"stamina_damage":0,"healed_life":0},35,{"note_id":35,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":27619,"stamina_damage":0,"healed_life":0},36,{"note_id":36,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":28475,"stamina_damage":0,"healed_life":0},37,{"note_id":37,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":29123,"stamina_damage":0,"healed_life":150},38,{"note_id":38,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":29771,"stamina_damage":0,"healed_life":0},39,{"note_id":39,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":30627,"stamina_damage":0,"healed_life":0},40,{"note_id":40,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":31334,"stamina_damage":0,"healed_life":0},41,{"note_id":41,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":32112,"stamina_damage":0,"healed_life":0},42,{"note_id":42,"current_life":5812,"appended_shield":220,"healed_life_percent":0,"current_voltage":37895,"stamina_damage":0,"healed_life":0},43,{"note_id":43,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":37895,"stamina_damage":0,"healed_life":0},44,{"note_id":44,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":38679,"stamina_damage":0,"healed_life":0},45,{"note_id":45,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":39463,"stamina_damage":0,"healed_life":0},46,{"note_id":46,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":39463,"stamina_damage":0,"healed_life":0},47,{"note_id":47,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":40111,"stamina_damage":0,"healed_life":0},48,{"note_id":48,"current_life":5812,"appended_shield":200,"healed_life_percent":0,"current_voltage":40967,"stamina_damage":0,"healed_life":0},49,{"note_id":49,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":41556,"stamina_damage":0,"healed_life":0},50,{"note_id":50,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":42334,"stamina_damage":0,"healed_life":0},51,{"note_id":51,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":43619,"stamina_damage":0,"healed_life":0},52,{"note_id":52,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":44326,"stamina_damage":0,"healed_life":150},53,{"note_id":53,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":45039,"stamina_damage":0,"healed_life":0},54,{"note_id":55,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":45753,"stamina_damage":0,"healed_life":0},55,{"note_id":0,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":46342,"stamina_damage":0,"healed_life":0},56,{"note_id":56,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":47508,"stamina_damage":0,"healed_life":0},57,{"note_id":57,"current_life":5812,"appended_shield":200,"healed_life_percent":0,"current_voltage":48364,"stamina_damage":0,"healed_life":0},58,{"note_id":58,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":49071,"stamina_damage":0,"healed_life":0},59,{"note_id":59,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":49849,"stamina_damage":0,"healed_life":0},60,{"note_id":61,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":50705,"stamina_damage":0,"healed_life":0},61,{"note_id":60,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":51294,"stamina_damage":0,"healed_life":0},62,{"note_id":62,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":52007,"stamina_damage":0,"healed_life":0},63,{"note_id":63,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":52721,"stamina_damage":0,"healed_life":0},64,{"note_id":64,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":53428,"stamina_damage":0,"healed_life":150},65,{"note_id":65,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":54594,"stamina_damage":0,"healed_life":0},66,{"note_id":66,"current_life":5812,"appended_shield":200,"healed_life_percent":0,"current_voltage":55879,"stamina_damage":0,"healed_life":0},67,{"note_id":67,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":56586,"stamina_damage":0,"healed_life":0},0,{"note_id":0,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0},68,{"note_id":0,"current_life":5812,"appended_shield":0,"healed_life_percent":0,"current_voltage":56586,"stamina_damage":0,"healed_life":0}],"highest_combo_count":9,"combo_count":4,"wave_stat":[],"result_dict":[1,{"judge_type":30,"card_master_id":0,"voltage":707},2,{"judge_type":30,"card_master_id":0,"voltage":778},3,{"judge_type":20,"card_master_id":0,"voltage":1178},4,{"judge_type":30,"card_master_id":0,"voltage":707},5,{"judge_type":30,"card_master_id":0,"voltage":778},6,{"judge_type":14,"card_master_id":0,"voltage":714},7,{"judge_type":30,"card_master_id":0,"voltage":707},8,{"judge_type":30,"card_master_id":0,"voltage":778},9,{"judge_type":30,"card_master_id":0,"voltage":1285},10,{"judge_type":14,"card_master_id":0,"voltage":589},11,{"judge_type":30,"card_master_id":0,"voltage":778},12,{"judge_type":30,"card_master_id":0,"voltage":1285},13,{"judge_type":20,"card_master_id":0,"voltage":648},14,{"judge_type":14,"card_master_id":0,"voltage":648},15,{"judge_type":30,"card_master_id":0,"voltage":856},16,{"judge_type":30,"card_master_id":0,"voltage":707},17,{"judge_type":30,"card_master_id":0,"voltage":778},18,{"judge_type":30,"card_master_id":0,"voltage":856},19,{"judge_type":14,"card_master_id":0,"voltage":589},20,{"judge_type":14,"card_master_id":0,"voltage":648},21,{"judge_type":14,"card_master_id":0,"voltage":714},22,{"judge_type":20,"card_master_id":0,"voltage":648},23,{"judge_type":20,"card_master_id":0,"voltage":1069},24,{"judge_type":30,"card_master_id":0,"voltage":856},25,{"judge_type":30,"card_master_id":0,"voltage":707},26,{"judge_type":30,"card_master_id":0,"voltage":778},27,{"judge_type":30,"card_master_id":0,"voltage":856},28,{"judge_type":14,"card_master_id":0,"voltage":589},29,{"judge_type":30,"card_master_id":0,"voltage":778},30,{"judge_type":30,"card_master_id":0,"voltage":856},31,{"judge_type":30,"card_master_id":0,"voltage":707},32,{"judge_type":30,"card_master_id":0,"voltage":778},33,{"judge_type":20,"card_master_id":0,"voltage":784},34,{"judge_type":30,"card_master_id":0,"voltage":707},35,{"judge_type":30,"card_master_id":0,"voltage":778},36,{"judge_type":30,"card_master_id":0,"voltage":856},37,{"judge_type":20,"card_master_id":0,"voltage":648},38,{"judge_type":14,"card_master_id":0,"voltage":648},39,{"judge_type":30,"card_master_id":0,"voltage":856},40,{"judge_type":30,"card_master_id":0,"voltage":707},41,{"judge_type":30,"card_master_id":0,"voltage":778},42,{"judge_type":14,"card_master_id":0,"voltage":784},43,{"judge_type":10,"card_master_id":0,"voltage":0},44,{"judge_type":20,"card_master_id":0,"voltage":784},45,{"judge_type":14,"card_master_id":0,"voltage":784},46,{"judge_type":10,"card_master_id":0,"voltage":0},47,{"judge_type":14,"card_master_id":0,"voltage":648},48,{"judge_type":30,"card_master_id":0,"voltage":856},49,{"judge_type":14,"card_master_id":0,"voltage":589},50,{"judge_type":30,"card_master_id":0,"voltage":778},51,{"judge_type":30,"card_master_id":0,"voltage":1285},52,{"judge_type":30,"card_master_id":0,"voltage":707},53,{"judge_type":20,"card_master_id":0,"voltage":713},54,{"judge_type":14,"card_master_id":0,"voltage":714},55,{"judge_type":14,"card_master_id":0,"voltage":589},56,{"judge_type":30,"card_master_id":0,"voltage":1166},57,{"judge_type":30,"card_master_id":0,"voltage":856},58,{"judge_type":30,"card_master_id":0,"voltage":707},59,{"judge_type":30,"card_master_id":0,"voltage":778},60,{"judge_type":14,"card_master_id":0,"voltage":589},61,{"judge_type":30,"card_master_id":0,"voltage":856},62,{"judge_type":20,"card_master_id":0,"voltage":713},63,{"judge_type":14,"card_master_id":0,"voltage":714},64,{"judge_type":30,"card_master_id":0,"voltage":707},65,{"judge_type":30,"card_master_id":0,"voltage":1166},66,{"judge_type":30,"card_master_id":0,"voltage":1285},67,{"judge_type":30,"card_master_id":0,"voltage":707}],"is_perfect_full_combo":false,"is_perfect_live":false},"live_finish_status":1}')
		self.communicationMember_setFavoriteMember('{"member_master_id":1}')
		self.bootstrap_fetchBootstrap('{"bootstrap_fetch_types":[2,3,4,5,9,10],"device_token":"","device_name":""}')
		self.navi_tapLovePoint('{"member_master_id":1}')
		self.navi_saveUserNaviVoice('{"navi_voice_master_ids":[100010004]}')
		self.trainingTree_fetchTrainingTree('{"card_master_id":100012001}')
		self.trainingTree_levelUpCard('{"card_master_id":100012001,"additional_level":1}')
		self.trainingTree_activateTrainingTreeCell('{"cell_master_ids":[17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1],"card_master_id":100012001,"pay_type":1}')
		self.card_updateCardNewFlag('{"card_master_ids":[100012001]}')
		self.liveDeck_saveDeckAll('{"card_with_suit":[100012001,null,102071001,null,102081001,null,101031001,null,101061001,null,101051001,null,100051001,100051001,100091001,100091001,100081001,100081001],"deck_id":1,"squad_dict":[101,{"card_master_ids":[100012001,101061001,101051001],"user_accessory_ids":[null,null,null]},102,{"card_master_ids":[102081001,101031001,100051001],"user_accessory_ids":[null,null,null]},103,{"card_master_ids":[102071001,100091001,100081001],"user_accessory_ids":[null,null,null]}]}')
		self.liveDeck_saveSuit('{"card_index":1,"deck_id":1,"suit_master_id":100012001}')
		self.livePartners_fetch()
		s1=self.live_start('{"deck_id":1,"cell_id":1005,"partner_card_master_id":0,"live_difficulty_id":31001101,"lp_magnification":1,"is_auto_play":false,"partner_user_id":0}')
		self.live_finish('{"live_id":'+str(s1[3]['live']['live_id'])+',"resume_finish_info":{"cached_judge_result":[]},"live_score":{"use_debuf_active_skill_count":0,"target_score":50000,"use_sp_skill_count":1,"use_buf_active_skill_count":14,"current_score":80003,"change_squad_count":0,"card_stat_dict":[100012001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100012001,"recast_squad_effect_count":0},102071001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":102071001,"recast_squad_effect_count":0},102081001,{"skill_triggered_count":9,"appeal_count":21,"got_voltage":18035,"card_master_id":102081001,"recast_squad_effect_count":0},101031001,{"skill_triggered_count":7,"appeal_count":21,"got_voltage":19398,"card_master_id":101031001,"recast_squad_effect_count":0},101061001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":101061001,"recast_squad_effect_count":0},101051001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":101051001,"recast_squad_effect_count":0},100051001,{"skill_triggered_count":7,"appeal_count":20,"got_voltage":17998,"card_master_id":100051001,"recast_squad_effect_count":0},100091001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100091001,"recast_squad_effect_count":0},100081001,{"skill_triggered_count":0,"appeal_count":0,"got_voltage":0,"card_master_id":100081001,"recast_squad_effect_count":0}],"use_voltage_active_skill_count":0,"use_heal_active_skill_count":0,"remaining_stamina":7405,"live_power":1341,"turn_stat_dict":[1,{"note_id":1,"current_life":7464,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":27,"healed_life":0},2,{"note_id":2,"current_life":7437,"appended_shield":0,"healed_life_percent":0,"current_voltage":713,"stamina_damage":27,"healed_life":0},3,{"note_id":3,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":713,"stamina_damage":27,"healed_life":0},4,{"note_id":4,"current_life":7410,"appended_shield":200,"healed_life_percent":0,"current_voltage":1986,"stamina_damage":0,"healed_life":0},5,{"note_id":5,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":2764,"stamina_damage":0,"healed_life":0},6,{"note_id":6,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":3565,"stamina_damage":0,"healed_life":0},7,{"note_id":7,"current_life":7410,"appended_shield":200,"healed_life_percent":0,"current_voltage":4413,"stamina_damage":0,"healed_life":0},8,{"note_id":8,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":5191,"stamina_damage":0,"healed_life":0},9,{"note_id":9,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":6152,"stamina_damage":0,"healed_life":0},10,{"note_id":10,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":7055,"stamina_damage":0,"healed_life":0},11,{"note_id":11,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":8084,"stamina_damage":0,"healed_life":0},12,{"note_id":13,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":9007,"stamina_damage":0,"healed_life":0},13,{"note_id":14,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":10060,"stamina_damage":0,"healed_life":0},14,{"note_id":15,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":11255,"stamina_damage":0,"healed_life":0},15,{"note_id":16,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":13106,"stamina_damage":0,"healed_life":0},16,{"note_id":17,"current_life":7410,"appended_shield":200,"healed_life_percent":0,"current_voltage":14099,"stamina_damage":0,"healed_life":0},17,{"note_id":18,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":15004,"stamina_damage":0,"healed_life":0},18,{"note_id":19,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":15885,"stamina_damage":0,"healed_life":0},19,{"note_id":20,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":16662,"stamina_damage":0,"healed_life":0},20,{"note_id":21,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":17446,"stamina_damage":0,"healed_life":0},21,{"note_id":22,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":18327,"stamina_damage":0,"healed_life":0},22,{"note_id":23,"current_life":7410,"appended_shield":200,"healed_life_percent":0,"current_voltage":29104,"stamina_damage":0,"healed_life":0},23,{"note_id":25,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":29817,"stamina_damage":0,"healed_life":0},24,{"note_id":26,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":30778,"stamina_damage":0,"healed_life":0},25,{"note_id":27,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":31530,"stamina_damage":0,"healed_life":0},26,{"note_id":28,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":32765,"stamina_damage":0,"healed_life":0},27,{"note_id":29,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":33688,"stamina_damage":0,"healed_life":0},28,{"note_id":30,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":34591,"stamina_damage":0,"healed_life":0},29,{"note_id":31,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":35414,"stamina_damage":0,"healed_life":0},30,{"note_id":32,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":36375,"stamina_damage":0,"healed_life":0},31,{"note_id":33,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":37203,"stamina_damage":0,"healed_life":0},32,{"note_id":35,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":38448,"stamina_damage":0,"healed_life":0},33,{"note_id":36,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":39555,"stamina_damage":0,"healed_life":0},34,{"note_id":37,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":40548,"stamina_damage":0,"healed_life":0},35,{"note_id":38,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":41378,"stamina_damage":0,"healed_life":0},36,{"note_id":39,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":42356,"stamina_damage":0,"healed_life":0},37,{"note_id":40,"current_life":7410,"appended_shield":220,"healed_life_percent":0,"current_voltage":57046,"stamina_damage":0,"healed_life":0},38,{"note_id":42,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":57830,"stamina_damage":0,"healed_life":0},39,{"note_id":43,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":58711,"stamina_damage":0,"healed_life":0},40,{"note_id":44,"current_life":7410,"appended_shield":200,"healed_life_percent":0,"current_voltage":59539,"stamina_damage":0,"healed_life":0},41,{"note_id":45,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":60568,"stamina_damage":0,"healed_life":0},42,{"note_id":46,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":61575,"stamina_damage":0,"healed_life":0},43,{"note_id":47,"current_life":7410,"appended_shield":200,"healed_life_percent":0,"current_voltage":62478,"stamina_damage":0,"healed_life":0},44,{"note_id":48,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":63610,"stamina_damage":0,"healed_life":0},45,{"note_id":50,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":64491,"stamina_damage":0,"healed_life":0},46,{"note_id":51,"current_life":7410,"appended_shield":200,"healed_life_percent":0,"current_voltage":65424,"stamina_damage":0,"healed_life":0},47,{"note_id":52,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":66279,"stamina_damage":0,"healed_life":0},48,{"note_id":53,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":67160,"stamina_damage":0,"healed_life":0},49,{"note_id":54,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":68093,"stamina_damage":0,"healed_life":0},50,{"note_id":55,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":68877,"stamina_damage":0,"healed_life":0},51,{"note_id":56,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":69934,"stamina_damage":0,"healed_life":0},52,{"note_id":57,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":70927,"stamina_damage":0,"healed_life":0},53,{"note_id":58,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":71832,"stamina_damage":0,"healed_life":0},54,{"note_id":59,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":72755,"stamina_damage":0,"healed_life":0},55,{"note_id":61,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":73507,"stamina_damage":0,"healed_life":0},56,{"note_id":62,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":74742,"stamina_damage":0,"healed_life":0},57,{"note_id":63,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":75703,"stamina_damage":0,"healed_life":0},58,{"note_id":64,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":76531,"stamina_damage":0,"healed_life":0},59,{"note_id":65,"current_life":7410,"appended_shield":0,"healed_life_percent":0,"current_voltage":77354,"stamina_damage":0,"healed_life":0},60,{"note_id":66,"current_life":7405,"appended_shield":0,"healed_life_percent":0,"current_voltage":78277,"stamina_damage":5,"healed_life":0},61,{"note_id":67,"current_life":7405,"appended_shield":200,"healed_life_percent":0,"current_voltage":79180,"stamina_damage":0,"healed_life":0},62,{"note_id":68,"current_life":7405,"appended_shield":0,"healed_life_percent":0,"current_voltage":80003,"stamina_damage":0,"healed_life":0},63,{"note_id":0,"current_life":7405,"appended_shield":0,"healed_life_percent":0,"current_voltage":80003,"stamina_damage":0,"healed_life":0},64,{"note_id":0,"current_life":0,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0},65,{"note_id":0,"current_life":0,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0},66,{"note_id":0,"current_life":0,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0},67,{"note_id":0,"current_life":0,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0},68,{"note_id":0,"current_life":0,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0},0,{"note_id":0,"current_life":7491,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0},69,{"note_id":0,"current_life":0,"appended_shield":0,"healed_life_percent":0,"current_voltage":0,"stamina_damage":0,"healed_life":0}],"highest_combo_count":11,"combo_count":7,"wave_stat":[1,true,2,true,3,false],"result_dict":[1,{"judge_type":10,"card_master_id":0,"voltage":0},2,{"judge_type":20,"card_master_id":0,"voltage":713},3,{"judge_type":10,"card_master_id":0,"voltage":0},4,{"judge_type":30,"card_master_id":0,"voltage":1273},5,{"judge_type":30,"card_master_id":0,"voltage":778},6,{"judge_type":14,"card_master_id":0,"voltage":801},7,{"judge_type":30,"card_master_id":0,"voltage":848},8,{"judge_type":30,"card_master_id":0,"voltage":778},9,{"judge_type":30,"card_master_id":0,"voltage":961},10,{"judge_type":30,"card_master_id":0,"voltage":903},11,{"judge_type":14,"card_master_id":0,"voltage":1029},12,{"judge_type":1,"card_master_id":0,"voltage":0},13,{"judge_type":14,"card_master_id":0,"voltage":923},14,{"judge_type":30,"card_master_id":0,"voltage":1053},15,{"judge_type":14,"card_master_id":0,"voltage":1195},16,{"judge_type":30,"card_master_id":0,"voltage":1107},17,{"judge_type":30,"card_master_id":0,"voltage":993},18,{"judge_type":30,"card_master_id":0,"voltage":905},19,{"judge_type":14,"card_master_id":0,"voltage":881},20,{"judge_type":14,"card_master_id":0,"voltage":777},21,{"judge_type":20,"card_master_id":0,"voltage":784},22,{"judge_type":14,"card_master_id":0,"voltage":881},23,{"judge_type":14,"card_master_id":0,"voltage":777},24,{"judge_type":1,"card_master_id":0,"voltage":0},25,{"judge_type":20,"card_master_id":0,"voltage":713},26,{"judge_type":30,"card_master_id":0,"voltage":961},27,{"judge_type":14,"card_master_id":0,"voltage":752},28,{"judge_type":30,"card_master_id":0,"voltage":1235},29,{"judge_type":20,"card_master_id":0,"voltage":923},30,{"judge_type":30,"card_master_id":0,"voltage":903},31,{"judge_type":30,"card_master_id":0,"voltage":823},32,{"judge_type":30,"card_master_id":0,"voltage":961},33,{"judge_type":20,"card_master_id":0,"voltage":828},34,{"judge_type":1,"card_master_id":0,"voltage":0},35,{"judge_type":20,"card_master_id":0,"voltage":1245},36,{"judge_type":30,"card_master_id":0,"voltage":1107},37,{"judge_type":30,"card_master_id":0,"voltage":993},38,{"judge_type":20,"card_master_id":0,"voltage":830},39,{"judge_type":20,"card_master_id":0,"voltage":978},40,{"judge_type":14,"card_master_id":0,"voltage":862},41,{"judge_type":1,"card_master_id":0,"voltage":0},42,{"judge_type":20,"card_master_id":0,"voltage":784},43,{"judge_type":20,"card_master_id":0,"voltage":881},44,{"judge_type":20,"card_master_id":0,"voltage":828},45,{"judge_type":14,"card_master_id":0,"voltage":1029},46,{"judge_type":30,"card_master_id":0,"voltage":1007},47,{"judge_type":30,"card_master_id":0,"voltage":903},48,{"judge_type":20,"card_master_id":0,"voltage":1132},49,{"judge_type":1,"card_master_id":0,"voltage":0},50,{"judge_type":14,"card_master_id":0,"voltage":881},51,{"judge_type":30,"card_master_id":0,"voltage":933},52,{"judge_type":30,"card_master_id":0,"voltage":855},53,{"judge_type":14,"card_master_id":0,"voltage":881},54,{"judge_type":30,"card_master_id":0,"voltage":933},55,{"judge_type":20,"card_master_id":0,"voltage":784},56,{"judge_type":30,"card_master_id":0,"voltage":1057},57,{"judge_type":30,"card_master_id":0,"voltage":993},58,{"judge_type":30,"card_master_id":0,"voltage":905},59,{"judge_type":14,"card_master_id":0,"voltage":923},60,{"judge_type":1,"card_master_id":0,"voltage":0},61,{"judge_type":14,"card_master_id":0,"voltage":752},62,{"judge_type":30,"card_master_id":0,"voltage":1235},63,{"judge_type":30,"card_master_id":0,"voltage":961},64,{"judge_type":20,"card_master_id":0,"voltage":828},65,{"judge_type":30,"card_master_id":0,"voltage":823},66,{"judge_type":20,"card_master_id":0,"voltage":923},67,{"judge_type":30,"card_master_id":0,"voltage":903},68,{"judge_type":30,"card_master_id":0,"voltage":823}],"is_perfect_full_combo":false,"is_perfect_live":false},"live_finish_status":1}')
		self.gacha_fetchGachaMenu()
		self.gacha_draw('{"gacha_draw_master_id":1}')
		self.bootstrap_fetchBootstrap('{"bootstrap_fetch_types":[2,3,4,5,9,10],"device_token":"","device_name":""}')
		self.tutorial_phaseEnd()
		self.bootstrap_fetchBootstrap('{"bootstrap_fetch_types":[2,3,4,5,9,10,11],"device_token":"","device_name":""}')
		self.loginBonus_readLoginBonus('{"login_bonus_id":40003,"login_bonus_type":3}')
		self.loginBonus_readLoginBonus('{"login_bonus_id":40002,"login_bonus_type":2}')
		self.loginBonus_readLoginBonus('{"login_bonus_id":1000001,"login_bonus_type":1}')
		self.navi_saveUserNaviVoice('{"navi_voice_master_ids":[100010123,100010113]}')
		self.bootstrap_fetchBootstrap('{"bootstrap_fetch_types":[2,3,4,5,9,10],"device_token":"","device_name":""}')
		self.notice_fetchNoticeDetail('{"notice_id":1000033}')
		self.notice_fetchNotice()
		self.present_fetch()
		self.ruleDescription_saveRuleDescription('{"rule_description_master_ids":[20]}')
		r2=self.bootstrap_fetchBootstrap('{"bootstrap_fetch_types":[2,3,4,5,9,10],"device_token":"","device_name":""}')[3]['user_model_diff']['user_status']
		self.exportPlayer(r2['game_money'],r2['free_sns_coin'])

if __name__ == "__main__":
	a=API()
	a.setUserId('100004543')
	a.setPassword('S+53xfP+gDzNMGRtBYvqN2A2+yd9Hnlb1INLBr2S7e0=')
	a.dailylogin()
	#a.reroll()