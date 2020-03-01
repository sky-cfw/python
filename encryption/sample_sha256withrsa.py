"""
sha256rsa签名计算及验签
"""
import sys,os
import io
import logging
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64

class CHashWithRSA():
    '''
    sha256rsa签名计算及验签
    hash_type:指定hash算法的类型，如：
    key:加密key
    private_key:私钥
    public_key：公钥
    '''
    def __init__( self, hash_type, key, data, private_key, public_key ):
        '''签名验签各属性初始化'''
        self.hash_type = hash_type
        self.key = key
        self.data = data
        self.private_key = private_key
        self.public_key = public_key


    def sign( self ):
        '''接收原始数据，返回签名结果'''
        #计算摘要
        raw_data = self.data + "&" + self.key
        print( "raw_data: %s\n" % raw_data )
        h = SHA256.new()
        h.update( raw_data.encode('utf-8') )
        print( "sha256 hex: %s\n" % h.hexdigest().upper() )

        #计算签名
        rsa_obj = RSA.importKey( self.private_key )
        signer = PKCS1_v1_5.new( rsa_obj )
        sig = base64.b64encode( signer.sign( h ) )
        print( "sig: %s\n\n" % sig )
        return sig


    def verify( self, sig ):
        '''接收原始数据，返回验签结果'''
        #计算摘要
        raw_data = self.data + "&" + self.key
        print( "raw_data: %s\n" % raw_data )
        h = SHA256.new()
        h.update( raw_data.encode('utf-8') )
        print( "sha256 hex: %s\n" % h.hexdigest().upper() )

        #验签
        rsa_obj = RSA.importKey( self.public_key )
        verifier = PKCS1_v1_5.new( rsa_obj )
        res = verifier.verify( h, base64.b64decode(sig) )
        print( "res: %d\n\n" % res )
        return res

def read_file( filename ):
    '''读取文件内容'''
    with open( filename ) as f:
        pk = f.read()
    return pk


def dict_sort( data ):
    '''字典排序'''
    dicted_data = dict( sorted( k.split( '=' ) for k in data.split( '&' ) ) )
    #print( dicted_data )
    sorted_data = ''
    for k, v in dicted_data.items():
        sorted_data += k + '=' + v + '&'
    sorted_data = sorted_data[:-1]
    print( "\nsorted_data: %s\n" % sorted_data )
    return sorted_data


def main():
    key = input( "please input offerid secretkey: " )
    data = input( "please input data: " )
    sorted_data = dict_sort( data )
    prk = read_file( 'pkcs1_rsa_pri_key_2048.pem' )
    puk = read_file( 'rsa_pub_key_2048.pem' )
    hash_with_rsa = CHashWithRSA( 'SHA256', key, data, prk, puk )
    sig = hash_with_rsa.sign()
    res = hash_with_rsa.verify( sig )

if __name__ == '__main__':
    main()
