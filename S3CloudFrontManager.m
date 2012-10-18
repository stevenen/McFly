//
//  S3CloudFrontManager.m
//
//
//  Created by Stefano Cocco on 18/10/12.
//
//

#import "S3CloudFrontManager.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

#define KEY_PAIR_ID @"keyPairId"
#define KEY_PAIR_PRIVATE_KEY_NAME @"keyPairPrivateKeyName"
#define SUB_DOMAIN @"currentSubDomain"

@interface S3CloudFrontManager(Private)
- (NSString *)getSignedURL;
- (NSString *)encodeStringForCloudFront:(NSString *)signiture;
- (NSString *)getSignature:(NSString *)resourceURL expiresOn:(NSTimeInterval)expiresOn privateKey:(NSString *)keyPairPrivateKeyName;
- (NSString *)base64forData:(NSData*)theData;
@end
@implementation S3CloudFrontManager

+ (S3CloudFrontManager *)sharedInstance
{
	static S3CloudFrontManager *sharedSingleton;
	
	@synchronized(self)
	{
		if (!sharedSingleton)
		{
			sharedSingleton = [[S3CloudFrontManager alloc] init];
		}
	}
	return sharedSingleton;
}

- (NSString*)signatureURLForResource:(NSString*) resourceName
{
    currentResource = [NSString stringWithFormat:@"%@", resourceName];
    currentDomain = SUB_DOMAIN;
    currentKeyPairId = KEY_PAIR_ID;
    currentKeyPairPrivateKeyName = KEY_PAIR_PRIVATE_KEY_NAME;
    
    return [self getSignedURL];
}

- (NSString*)signatureURLForResource:(NSString*) resourceName subDomain:(NSString*)aSubDomain keyPairId:(NSString*) aKeyPairId privateKeyName:(NSString*) aPrivateKeyName
{
    currentResource = [NSString stringWithFormat:@"%@", resourceName];
    currentDomain = [NSString stringWithFormat:@"%@", aSubDomain];;
    currentKeyPairId = [NSString stringWithFormat:@"%@", aKeyPairId];;
    currentKeyPairPrivateKeyName = [NSString stringWithFormat:@"%@", aPrivateKeyName];
    
    return [self getSignedURL];
}

- (NSString *)getSignedURL
{
    NSTimeInterval epochTime = [[[NSDate date] dateByAddingTimeInterval:60*60*24] timeIntervalSince1970];
    NSString *resourceURL = [NSString stringWithFormat:@"http://%@.cloudfront.net/%@", currentDomain, currentResource];
    
    return [NSString stringWithFormat:@"%@?Expires=%.0f&Signature=%@&Key-Pair-Id=%@",
            resourceURL,
            epochTime,
            [self getSignature:resourceURL expiresOn:epochTime privateKey:currentKeyPairPrivateKeyName],
            currentKeyPairId];
}

- (NSString *)encodeStringForCloudFront:(NSString *)signiture
{
    signiture = [signiture stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    signiture = [signiture stringByReplacingOccurrencesOfString:@"=" withString:@"_"];
    signiture = [signiture stringByReplacingOccurrencesOfString:@"/" withString:@"~"];
    
    return signiture;
}

// This method is based on the code snippet posted on <http://stackoverflow.com/questions/2699338/phps-openssl-sign-generates-different-signature-than-sscryptos-sign> by romeouald <http://stackoverflow.com/users/1038384/romeouald>
- (NSString *)getSignature:(NSString *)resourceURL expiresOn:(NSTimeInterval)expiresOn privateKey:(NSString *)keyPairPrivateKeyName
{
    NSString * signString = [NSString stringWithFormat:@"{\"Statement\":[{\"Resource\":\"%@\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":%.0f}}}]}", resourceURL, expiresOn];
    NSString *filePath = [[NSBundle mainBundle] pathForResource:keyPairPrivateKeyName ofType:@"pem"];
    NSData *privateKeyData = [NSData dataWithContentsOfFile:filePath];
    if (!privateKeyData) {
        NSLog(@"Error loading pem file.");
        return nil;
    }
    
    BIO *publicBIO = NULL;
    EVP_PKEY *privateKey = NULL;
    
    if (!(publicBIO = BIO_new_mem_buf((unsigned char *)[privateKeyData bytes], [privateKeyData length]))) {
        NSLog(@"BIO_new_mem_buf() failed!");
        return nil;
    }
    
    if (!PEM_read_bio_PrivateKey(publicBIO, &privateKey, NULL, NULL)) {
        NSLog(@"PEM_read_bio_PrivateKey() failed!");
        return nil;
    }
    
    const char * data = [signString cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned int length = [signString length];
    int outlen;
    unsigned char * outbuf[EVP_MAX_MD_SIZE];
    const EVP_MD * digest = EVP_sha1();
    EVP_MD_CTX md_ctx;
    
    EVP_MD_CTX_init(&md_ctx);
    EVP_SignInit(&md_ctx, digest);
    EVP_SignUpdate(&md_ctx, data, length);
    if (EVP_SignFinal(&md_ctx, (unsigned char*) outbuf, (unsigned int *) &outlen, privateKey)) {
        NSLog(@"Signed successfully.");
    }
    EVP_MD_CTX_cleanup(&md_ctx);
    EVP_PKEY_free(privateKey);
    
    NSData * signature = [NSData dataWithBytes:outbuf length:outlen];
    
    return [self encodeStringForCloudFront:[self base64forData:signature]];
}

-(NSString *)base64forData:(NSData*)theData
{
    NSMutableString *result;
    unsigned char   *raw;
    unsigned long   length;
    short           i, nCharsToWrite;
    long            cursor;
    unsigned char   inbytes[3], outbytes[4];
    
    length = [theData length];
    
    if (length < 1) {
        return @"";
    }
    
    result = [NSMutableString stringWithCapacity:length];
    raw    = (unsigned char *)[theData bytes];
    // Take 3 chars at a time, and encode to 4
    for (cursor = 0; cursor < length; cursor += 3) {
        for (i = 0; i < 3; i++) {
            if (cursor + i < length) {
                inbytes[i] = raw[cursor + i];
            }
            else{
                inbytes[i] = 0;
            }
        }
        
        outbytes[0] = (inbytes[0] & 0xFC) >> 2;
        outbytes[1] = ((inbytes[0] & 0x03) << 4) | ((inbytes[1] & 0xF0) >> 4);
        outbytes[2] = ((inbytes[1] & 0x0F) << 2) | ((inbytes[2] & 0xC0) >> 6);
        outbytes[3] = inbytes[2] & 0x3F;
        
        nCharsToWrite = 4;
        
        switch (length - cursor) {
            case 1:
                nCharsToWrite = 2;
                break;
                
            case 2:
                nCharsToWrite = 3;
                break;
        }
        for (i = 0; i < nCharsToWrite; i++) {
            [result appendFormat:@"%c", base64EncodingTable[outbytes[i]]];
        }
        for (i = nCharsToWrite; i < 4; i++) {
            [result appendString:@"="];
        }
    }
    
    return [NSString stringWithString:result]; // convert to immutable string
}

static char        base64EncodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

@end
