//
//  S3CloudFrontManager.h
// 
//
//  Created by Stefano Cocco on 18/10/12.
//
//

#import <Foundation/Foundation.h>

@interface S3CloudFrontManager : NSObject
{
    NSString* currentResource;
    NSString* currentDomain;
    NSString* currentKeyPairId;
    NSString* currentKeyPairPrivateKeyName;
}

+ (S3CloudFrontManager *)sharedInstance;

//Use default define in .m file
- (NSString*)signatureURLForResource:(NSString*) resourceName;

- (NSString*)signatureURLForResource:(NSString*) resourceName subDomain:(NSString*)aSubDomain keyPairId:(NSString*) aKeyPairId privateKeyName:(NSString*) aPrivateKeyName;
@end
