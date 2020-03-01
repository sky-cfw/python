'''
Desc: 本模块用于提供常用的一些工具库函数
Date: 2020/03/01
Auth: skycfwu
Feat: 
'''
import sys,os
import io
import logging

def SystemInit():
	'''系统初始化'''
	#日志格式初始化
	logging.basicConfig( handlers=[logging.FileHandler(sys.argv[0].replace( '.py', '.log' ), encoding='utf-8')], format='[%(asctime)s] [%(processName)s:%(process)d] [%(threadName)s:%(thread)d] [%(filename)s:%(funcName)s:%(lineno)d] [%(levelname)s]: %(message)s', level=logging.DEBUG )
	logging.debug("日志初始化ok!")
	
	#标准输出编码修改为utf8
	sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
	logging.debug("标准输出初始化ok!")
	
	return

def ReadFile( filename ):
	'''读取文件中的全部内容，并返回'''
	try:
		with open( filename ) as f:
			data = f.read()
	except fileNotFoundError:
		logging.debug( "sorry, the file %s does not exist!", filename )
		return False, None
	else:
		return True, data