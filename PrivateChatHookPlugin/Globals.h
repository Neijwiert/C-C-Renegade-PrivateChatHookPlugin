#pragma once

#define Stringify(x) #x

extern bool ShowPrivateChatInConsole;
extern bool LogEveryone;
extern int ChatEventAddress;
extern int ChatHookEventVectorAddress;
extern bool VanillaHasPrivateChatCheck;

/* FOR MD5 HASHING */
#define MD5_HASH_BUFSIZE 1024
#define MD5_HASH_MD5LEN  16
#define MD5_HASH_ENCODED_LEN 32

/* HOOKING STUFF */
#define BANDTEST_IMAGE_BASE_ADDRESS 0x12000000L
#define VANILLA_4_50_CHAT_EVENT_ADDRESS 0x1217D3D0L
#define VANILLA_4_40_CHAT_EVENT_ADDRESS 0x1217D3D0L
#define VANILLA_4_30_CHAT_EVENT_ADDRESS 0x1217D370L
#define VANILLA_4_2_4_CHAT_EVENT_ADDRESS 0x12179A80L
#define BANDTEST_MODULE_NAME L"BandTest.dll"

#define SCRIPTS_IMAGE_BASE_ADDRESS 0x11000000L
#define DA_SCRIPTS_IMAGE_BASE_ADDRESS SCRIPTS_IMAGE_BASE_ADDRESS
#define VANILLA_4_50_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS 0x1129549CL
#define VANILLA_4_40_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS 0x1128E2ACL
#define VANILLA_4_30_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS 0x1127606CL
#define VANILLA_4_2_4_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS 0x1123692CL
#define DA_1_92_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS 0x112FF9C8L
#define DA_1_90_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS 0x112DD570L
#define DA_1_8_1_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS 0x111DED80L
#define SCRIPTS_MODULE_NAME L"Scripts.dll"

#define DA_IMAGE_BASE_ADDRESS 0x11000000L
#define DA_1_92_CHAT_EVENT_ADDRESS 0x110017A0L
#define DA_1_90_CHAT_EVENT_ADDRESS DA_1_92_CHAT_EVENT_ADDRESS
#define DA_1_8_1_CHAT_EVENT_ADDRESS 0x110017A0L
#define DA_MODULE_NAME L"da.dll"

/* MODULE HASHES */
#define VANILLA_4_50_BANDTEST_MD5_HASH "2f9925a1a06da88b6647643d92dcd66a"
#define VANILLA_4_40_BANDTEST_MD5_HASH "612bfd4fc1e139379adbe67c18502bb2"
#define VANILLA_4_30_BANDTEST_MD5_HASH "80dd9ca734427499fdbb08579550538a"
#define VANILLA_4_2_4_BANDTEST_MD5_HASH "2a56ef4b1eb685154567e5c3e7508521"

#define VANILLA_4_50_SCRIPTS_MD5_HASH "9e3acd8913272e6b0ec520f3db09e8bd"
#define VANILLA_4_40_SCRIPTS_MD5_HASH "25fc0e0f0178f36e8420d72cccf4611c"
#define VANILLA_4_30_SCRIPTS_MD5_HASH "c4ab04e28167895b0a9eb636362fdbae"
#define VANILLA_4_2_4_SCRIPTS_MD5_HASH "fcf4de0e2dfc4145bee4d739082018be"

#define DA_1_92_DA_MD5_HASH "3bf8dab22b5f98e1ef52935f8c559db4"
#define DA_1_90_DA_MD5_HASH DA_1_92_DA_MD5_HASH
#define DA_1_8_1_DA_MD5_HASH "d6b1689d214a23635ac092596a633a57"

#define DA_4_50_SCRIPTS_MD5_HASH "8cc95fdd9a2e4cab0aba5e25288ef061"
#define DA_4_30_SCRIPTS_MD5_HASH "e31ee7851d22bf4c83fea173b5847edd"
#define DA_4_2_4_SCRIPTS_MD5_HASH "521f598f1639a32dccf7c2a73efe9135"