/*
* A Command & Conquer: Renegade SSGM Plugin, enabling you to receive private chat messages
* Copyright(C) 2017  Neijwiert
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.If not, see <http://www.gnu.org/licenses/>.
*/

#include "General.h"
#include "PrivateChatHookPlugin.h"
#include "CommandPCH.h"
#include "Globals.h"

#include <MinHook.h>

#include <gmlog.h>
#include <gmgame.h>
#include <Wincrypt.h>

struct DAEventClass;

typedef bool(__cdecl *_ChatEvent)(cCsTextObj *textObj);
typedef bool(__cdecl *_DAChatEvent)(int PlayerID, TextMessageEnum Type, wchar_t *Message, int ReceiverID);
typedef bool(__thiscall *_DAEventClass_Chat_Event)(DAEventClass *_this, cPlayer *Player, TextMessageEnum Type, const wchar_t *Message, int ReceiverID);

struct DAEventClassVTable
{
	DWORD_PTR Settings_Loaded_Event;
	_DAEventClass_Chat_Event Chat_Event;
};

struct DAEventClass
{
	DAEventClassVTable *vPtr;
};

struct DAEventStruct
{
	DAEventClass *Base;
	int Priority;
};

struct cCsTextObj
{
	BYTE base[sizeof(cNetEvent)];
	int senderId;
	TextMessageEnum type;
	WideStringClass message;
	int receiverId;
};

static PrivateChatHookPlugin privateChatHookPlugin;

static _ChatEvent originalChatEvent = NULL;
static _DAChatEvent originalDAChatEvent = NULL;
static DWORD_PTR chatFunctionAddress = NULL;
static SimpleDynVecClass<Plugin *> *registeredPluginsForChat = NULL;
static DynamicVectorClass<DAEventStruct *> *daRegisteredPluginsForChat = NULL;

bool GetModuleFilePath(LPCWSTR moduleName, WideStringClass &result)
{
	HMODULE handle = GetModuleHandleW(moduleName);
	if (handle == NULL)
	{
		return false;
	}

	int bufferSize = MAX_PATH;
	bool exitLoop = false;
	bool ret = false;

	while (!exitLoop)
	{
		LPWSTR buffer = new WCHAR[bufferSize];
		GetModuleFileNameW(handle, buffer, bufferSize);

		DWORD lastError = GetLastError();
		if (lastError == ERROR_SUCCESS)
		{
			result = buffer;
			ret = true;
			exitLoop = true;
		}
		else
		{
			if (lastError == ERROR_INSUFFICIENT_BUFFER)
			{
				bufferSize *= 2;
			}
			else
			{
				exitLoop = true;
				ret = false;
			}
		}

		delete[] buffer;
	}

	return ret;
}

bool GetModuleMD5Hash(LPCWSTR moduleName, StringClass &result)
{
	WideStringClass moduleFilePath;
	if (!GetModuleFilePath(moduleName, moduleFilePath))
	{
		return false;
	}

	HANDLE hFile = CreateFileW(moduleFilePath.Peek_Buffer(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	HCRYPTPROV hProv = 0;
	if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		CloseHandle(hFile);

		return false;
	}

	HCRYPTHASH hHash = 0;
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);

		return false;
	}

	BOOL bResult = FALSE;
	BYTE rgbFile[MD5_HASH_BUFSIZE];
	DWORD cbRead = 0;

	bResult = ReadFile(hFile, rgbFile, MD5_HASH_BUFSIZE, &cbRead, NULL);
	while (bResult)
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);

			return false;
		}

		bResult = ReadFile(hFile, rgbFile, MD5_HASH_BUFSIZE, &cbRead, NULL);
	}

	if (!bResult)
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);

		return false;
	}

	DWORD cbHash = MD5_HASH_MD5LEN;
	BYTE rgbHash[MD5_HASH_MD5LEN];

	StringClass tmp(static_cast<int>(MD5_HASH_ENCODED_LEN + sizeof('\0')));

	static CHAR rgbDigits[] = "0123456789abcdef";
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			tmp += rgbDigits[rgbHash[i] >> 4];
			tmp += rgbDigits[rgbHash[i] & 0xf];
		}
	}
	else
	{
		return false;
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	result = tmp;

	return true;
}

PrivateChatHookPlugin::PrivateChatHookPlugin() : minHookInitialized(false), hookedChat(false), hookedChatEvents(false), isDragonadeServer(false), checkedVersion(false), scriptsVersion(SCRIPTS_VERSION_UNKNOWN), bandTestVersion(BANDTEST_VERSION_UNKNOWN), daVersion(DA_VERSION_UNKNOWN)
{
	InitCommands();

	RegisterEvent(EVENT_GLOBAL_INI, this);
	RegisterEvent(EVENT_CHAT_HOOK, this);
	RegisterEvent(EVENT_PLAYER_LEAVE_HOOK, this);

	MH_STATUS status = MH_Initialize();
	if (status != MH_OK)
	{
		Console_Output("PrivateChatHookPlugin: Failed to initialize MinHook\n");

		return;
	}

	this->minHookInitialized = true;
}

PrivateChatHookPlugin::~PrivateChatHookPlugin()
{
	if (!UnhookChat())
	{
		Console_Output("PrivateChatHookPlugin: Failed to unhook chat\n");
	}

	if (this->minHookInitialized)
	{
		MH_STATUS status = MH_Uninitialize();
		if (status != MH_OK)
		{
			Console_Output("PrivateChatHookPlugin: Failed to unitialize MinHook\n");
		}
	}

	UnregisterEvent(EVENT_PLAYER_LEAVE_HOOK, this);
	UnregisterEvent(EVENT_CHAT_HOOK, this);
	UnregisterEvent(EVENT_GLOBAL_INI, this);

	DeInitCommands();
}

void PrivateChatHookPlugin::OnLoadGlobalINISettings(INIClass *SSGMIni)
{
	ShowPrivateChatInConsole = SSGMIni->Get_Bool(Stringify(PrivateChatHookPlugin), Stringify(ShowPrivateChatInConsole), false);
	LogEveryone = SSGMIni->Get_Bool(Stringify(PrivateChatHookPlugin), Stringify(LogEveryone), true);
	ChatEventAddress = SSGMIni->Get_Int(Stringify(PrivateChatHookPlugin), Stringify(ChatEventAddress), 0);
	ChatHookEventVectorAddress = SSGMIni->Get_Int(Stringify(PrivateChatHookPlugin), Stringify(ChatHookEventVectorAddress), 0);

	if (this->minHookInitialized)
	{
		if (!DetermineVersion())
		{
			Console_Output("PrivateChatHookPlugin: Failed to version check\n");

			return;
		}

		if (!HookChat())
		{
			Console_Output("PrivateChatHookPlugin: Failed to hook chat\n");

			return;
		}

		if (!HookChatEvents())
		{
			Console_Output("PrivateChatHookPlugin: Failed to hook chat events\n");

			return;
		}
	}
}

bool PrivateChatHookPlugin::OnChat(int PlayerID, TextMessageEnum Type, const wchar_t *Message, int recieverID)
{
	if (Type == TEXT_MESSAGE_PRIVATE && recieverID != -1)
	{
		cPlayer *senderPlayer = Find_Player(PlayerID);
		cPlayer *receiverPlayer = Find_Player(recieverID);

		if (senderPlayer && receiverPlayer)
		{
			GameObject *senderPlayerObj = senderPlayer->Get_GameObj();
			GameObject *receiverPlayerObj = receiverPlayer->Get_GameObj();

			if (senderPlayerObj && receiverPlayerObj)
			{
				if (LogEveryone || IsLoggingEnabledForPlayer(PlayerID) || IsLoggingEnabledForPlayer(recieverID))
				{
					SSGMGameLog::Log_Gamelog("CHAT;PRIVATE;%d;%d;%ls", senderPlayerObj->Get_Network_ID(), receiverPlayerObj->Get_Network_ID(), Message);

					if (ShowPrivateChatInConsole)
					{
						Console_Output("%ls -> %ls: %ls\n", senderPlayer->Get_Name().Peek_Buffer(), receiverPlayer->Get_Name().Peek_Buffer(), Message);
					}
				}
			}
		}
	}

	return true;
}

void PrivateChatHookPlugin::OnPlayerLeave(int PlayerID)
{
	RemoveLoggingForPlayer(PlayerID);
}

bool PrivateChatHookPlugin::DetermineVersion()
{
	if (this->checkedVersion)
	{
		return true;
	}

	this->isDragonadeServer = (GetModuleHandleW(DA_MODULE_NAME) != NULL);

	if (this->isDragonadeServer)
	{
		StringClass scriptsModuleHash;
		if (GetModuleMD5Hash(SCRIPTS_MODULE_NAME, scriptsModuleHash))
		{
			if (scriptsModuleHash.Compare(DA_4_50_SCRIPTS_MD5_HASH) == 0)
			{
				this->scriptsVersion = SCRIPTS_VERSION_DA_1_92;
			}
			else if (scriptsModuleHash.Compare(DA_4_30_SCRIPTS_MD5_HASH) == 0)
			{
				this->scriptsVersion = SCRIPTS_VERSION_DA_1_90;
			}
			else if (scriptsModuleHash.Compare(DA_4_2_4_SCRIPTS_MD5_HASH) == 0)
			{
				this->scriptsVersion = SCRIPTS_VERSION_DA_1_8_1;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}


		StringClass daModuleHash;
		if (GetModuleMD5Hash(DA_MODULE_NAME, daModuleHash))
		{
			if (daModuleHash.Compare(DA_1_92_DA_MD5_HASH) == 0)
			{
				this->daVersion = DA_VERSION_DA_1_92;
			}
			else if (daModuleHash.Compare(DA_1_90_DA_MD5_HASH) == 0)
			{
				this->daVersion = DA_VERSION_DA_1_90;
			}
			else if (daModuleHash.Compare(DA_1_8_1_DA_MD5_HASH) == 0)
			{
				this->daVersion = DA_VERSION_DA_1_8_1;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	else
	{
		StringClass scriptsModuleHash;
		if (GetModuleMD5Hash(SCRIPTS_MODULE_NAME, scriptsModuleHash))
		{
			if (scriptsModuleHash.Compare(VANILLA_4_50_SCRIPTS_MD5_HASH) == 0)
			{
				this->scriptsVersion = SCRIPTS_VERSION_VANILLA_4_50;
			}
			else if (scriptsModuleHash.Compare(VANILLA_4_40_SCRIPTS_MD5_HASH) == 0)
			{
				this->scriptsVersion = SCRIPTS_VERSION_VANILLA_4_40;
			}
			else if (scriptsModuleHash.Compare(VANILLA_4_30_SCRIPTS_MD5_HASH) == 0)
			{
				this->scriptsVersion = SCRIPTS_VERSION_VANILLA_4_30;
			}
			else if (scriptsModuleHash.Compare(VANILLA_4_2_4_SCRIPTS_MD5_HASH) == 0)
			{
				this->scriptsVersion = SCRIPTS_VERSION_VANILLA_4_2_4;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}

		StringClass bandTestModuleHash;
		if (GetModuleMD5Hash(BANDTEST_MODULE_NAME, bandTestModuleHash))
		{
			if (bandTestModuleHash.Compare(VANILLA_4_50_BANDTEST_MD5_HASH) == 0)
			{
				this->bandTestVersion = BANDTEST_VERSION_VANILLA_4_50;
			}
			else if (bandTestModuleHash.Compare(VANILLA_4_40_BANDTEST_MD5_HASH) == 0)
			{
				this->bandTestVersion = BANDTEST_VERSION_VANILLA_4_40;
			}
			else if (bandTestModuleHash.Compare(VANILLA_4_30_BANDTEST_MD5_HASH) == 0)
			{
				this->bandTestVersion = BANDTEST_VERSION_VANILLA_4_30;
			}
			else if (bandTestModuleHash.Compare(VANILLA_4_2_4_BANDTEST_MD5_HASH) == 0)
			{
				this->bandTestVersion = BANDTEST_VERSION_VANILLA_4_2_4;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	this->checkedVersion = true;

	return true;
}

bool PrivateChatHookPlugin::HookChat()
{
	if (this->hookedChat)
	{
		return true;
	}

	if (this->isDragonadeServer)
	{
		HMODULE daHandle = GetModuleHandleW(DA_MODULE_NAME);
		if (daHandle == NULL)
		{
			return false;
		}

		DWORD_PTR chatEventAddress;
		switch (this->daVersion)
		{
			case DA_VERSION_DA_1_92:
			case DA_VERSION_DA_1_90:
				chatEventAddress = DA_1_92_CHAT_EVENT_ADDRESS;

				break;
			case DA_VERSION_DA_1_8_1:
				chatEventAddress = DA_1_8_1_CHAT_EVENT_ADDRESS;

				break;
			default:
				chatEventAddress = static_cast<DWORD_PTR>(ChatEventAddress);

				break;
		}

		DWORD_PTR moduleBase = reinterpret_cast<DWORD_PTR>(daHandle);
		if (ChatEventAddress == 0)
		{
			if (chatEventAddress == static_cast<DWORD_PTR>(ChatEventAddress))
			{
				return false;
			}

			DWORD_PTR daChatFunctionOffset = chatEventAddress - DA_IMAGE_BASE_ADDRESS;
			chatFunctionAddress = moduleBase + daChatFunctionOffset;
		}
		else
		{
			chatFunctionAddress = moduleBase + ChatEventAddress;
		}

		MH_STATUS status = MH_CreateHook(reinterpret_cast<LPVOID>(chatFunctionAddress), &DAChatEvent, reinterpret_cast<LPVOID *>(&originalDAChatEvent));
		if (status != MH_OK)
		{
			return false;
		}
	}
	else
	{
		HMODULE bandTestHandle = GetModuleHandleW(BANDTEST_MODULE_NAME);
		if (bandTestHandle == NULL)
		{
			return false;
		}

		DWORD chatEventAddress;
		switch (this->bandTestVersion)
		{
			case BANDTEST_VERSION_VANILLA_4_50:
				chatEventAddress = VANILLA_4_50_CHAT_EVENT_ADDRESS;

				break;
			case BANDTEST_VERSION_VANILLA_4_40:
				chatEventAddress = VANILLA_4_40_CHAT_EVENT_ADDRESS;

				break;
			case BANDTEST_VERSION_VANILLA_4_30:
				chatEventAddress = VANILLA_4_30_CHAT_EVENT_ADDRESS;

				break;
			case BANDTEST_VERSION_VANILLA_4_2_4:
				chatEventAddress = VANILLA_4_2_4_CHAT_EVENT_ADDRESS;

				break;
			default:
				chatEventAddress = static_cast<DWORD_PTR>(ChatEventAddress);

				break;
		}

		DWORD_PTR moduleBase = reinterpret_cast<DWORD_PTR>(bandTestHandle);
		if (ChatEventAddress == 0)
		{
			if (chatEventAddress == static_cast<DWORD_PTR>(ChatEventAddress))
			{
				return false;
			}

			DWORD_PTR chatFunctionOffset = chatEventAddress - BANDTEST_IMAGE_BASE_ADDRESS;
			chatFunctionAddress = moduleBase + chatFunctionOffset;
		}
		else
		{
			chatFunctionAddress = moduleBase + ChatEventAddress;
		}

		MH_STATUS status = MH_CreateHook(reinterpret_cast<LPVOID>(chatFunctionAddress), &ChatEvent, reinterpret_cast<LPVOID *>(&originalChatEvent));
		if (status != MH_OK)
		{
			return false;
		}
	}

	MH_STATUS status = MH_EnableHook(MH_ALL_HOOKS);
	if (status != MH_OK)
	{
		return false;
	}

	this->hookedChat = true;

	return true;
}

bool PrivateChatHookPlugin::UnhookChat()
{
	if (this->hookedChat)
	{
		MH_STATUS status = MH_RemoveHook(reinterpret_cast<LPVOID>(chatFunctionAddress));
		if (status != MH_OK)
		{
			return false;
		}
	}

	return true;
}

bool PrivateChatHookPlugin::HookChatEvents()
{
	if (this->hookedChatEvents)
	{
		return true;
	}

	HMODULE scriptsHandle = GetModuleHandleW(SCRIPTS_MODULE_NAME);
	if (scriptsHandle == NULL)
	{
		return false;
	}

	if (this->isDragonadeServer)
	{
		DWORD_PTR chatHookCountAddress;
		switch (this->scriptsVersion)
		{
			case SCRIPTS_VERSION_DA_1_92:
				chatHookCountAddress = DA_1_92_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS;

				break;
			case SCRIPTS_VERSION_DA_1_90:
				chatHookCountAddress = DA_1_90_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS;

				break;
			case SCRIPTS_VERSION_DA_1_8_1:
				chatHookCountAddress = DA_1_8_1_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS;

				break;
			default:
				chatHookCountAddress = static_cast<DWORD_PTR>(ChatHookEventVectorAddress);

				break;
		}

		DWORD_PTR moduleBase = reinterpret_cast<DWORD_PTR>(scriptsHandle);
		if (ChatHookEventVectorAddress == 0)
		{
			if (chatHookCountAddress == static_cast<DWORD_PTR>(ChatHookEventVectorAddress))
			{
				return false;
			}

			DWORD_PTR registeredEventsEventChatHookCountOffset = chatHookCountAddress - DA_SCRIPTS_IMAGE_BASE_ADDRESS;
			DWORD_PTR registeredEventsEventChatHookCountAddress = moduleBase + registeredEventsEventChatHookCountOffset;

			daRegisteredPluginsForChat = reinterpret_cast<DynamicVectorClass<DAEventStruct *> *>(registeredEventsEventChatHookCountAddress - sizeof(bool[2]) - sizeof(bool) - sizeof(bool) - sizeof(int) - sizeof(DAEventStruct **) - sizeof(void *));
		}
		else
		{
			DWORD_PTR registeredEventsEventChatHookVectorAddress = moduleBase + ChatHookEventVectorAddress;

			daRegisteredPluginsForChat = reinterpret_cast<DynamicVectorClass<DAEventStruct *> *>(registeredEventsEventChatHookVectorAddress);
		}
	}
	else
	{
		DWORD_PTR chatHookCountAddress;
		switch (this->scriptsVersion)
		{
			case SCRIPTS_VERSION_VANILLA_4_50:
				chatHookCountAddress = VANILLA_4_50_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS;

				break;
			case SCRIPTS_VERSION_VANILLA_4_40:
				chatHookCountAddress = VANILLA_4_40_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS;

				break;
			case SCRIPTS_VERSION_VANILLA_4_30:
				chatHookCountAddress = VANILLA_4_30_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS;

				break;
			case SCRIPTS_VERSION_VANILLA_4_2_4:
				chatHookCountAddress = VANILLA_4_2_4_REGISTERED_EVENTS_EVENT_CHAT_HOOK_COUNT_ADDRESS;

				break;
			default:
				chatHookCountAddress = static_cast<DWORD_PTR>(ChatHookEventVectorAddress);

				break;
		}

		DWORD_PTR moduleBase = reinterpret_cast<DWORD_PTR>(scriptsHandle);
		if (ChatHookEventVectorAddress == 0)
		{
			if (chatHookCountAddress == static_cast<DWORD_PTR>(ChatHookEventVectorAddress))
			{
				return false;
			}

			DWORD_PTR registeredEventsEventChatHookCountOffset = chatHookCountAddress - SCRIPTS_IMAGE_BASE_ADDRESS;
			DWORD_PTR registeredEventsEventChatHookCountAddress = moduleBase + registeredEventsEventChatHookCountOffset;

			registeredPluginsForChat = reinterpret_cast<SimpleDynVecClass<Plugin *> *>(registeredEventsEventChatHookCountAddress - sizeof(int) - sizeof(Plugin **) - sizeof(void *));
		}
		else
		{
			DWORD_PTR registeredEventsEventChatHookVectorAddress = moduleBase + ChatHookEventVectorAddress;

			registeredPluginsForChat = reinterpret_cast<SimpleDynVecClass<Plugin *> *>(registeredEventsEventChatHookVectorAddress);
		}
	}

	this->hookedChatEvents = true;

	return true;
}

bool PrivateChatHookPlugin::ChatEvent(cCsTextObj *textObj)
{
	bool result = originalChatEvent(textObj);

	if (result)
	{
		if (VanillaHasPrivateChatCheck || privateChatHookPlugin.bandTestVersion == BANDTEST_VERSION_VANILLA_4_2_4)
		{
			if (textObj->receiverId != -2 && textObj->receiverId != -3 && textObj->receiverId != -1)
			{
				if (textObj->type == TEXT_MESSAGE_PRIVATE)
				{
					for (int x = 0; x < registeredPluginsForChat->Count(); x++)
					{
						if (!(*registeredPluginsForChat)[x]->OnChat(textObj->senderId, textObj->type, textObj->message, textObj->receiverId))
						{
							result = false;

							break;
						}
					}
				}
			}
		}
	}

	return result;
}

bool PrivateChatHookPlugin::DAChatEvent(int PlayerID, TextMessageEnum Type, wchar_t *Message, int receiverID)
{
	bool result = originalDAChatEvent(PlayerID, Type, Message, receiverID);

	if (Type != TEXT_MESSAGE_PRIVATE)
	{
		return result;
	}

	cPlayer *senderPlayerClass = Find_Player(PlayerID);
	if (!senderPlayerClass)
	{
		return result;
	}

	if (receiverID != -2 && receiverID != -3 && receiverID != -1)
	{
		if (Message[0] == L'!' || Message[0] == L'/')
		{
			char *shortMessage = const_cast<char *>(WideCharToChar(Message));

			char *shortMessagePtr = shortMessage + 1;
			while (shortMessagePtr[0] != ' ' && shortMessagePtr[0] != '\0')
			{
				shortMessagePtr++;
			}

			shortMessagePtr[0] = '\0';

			if (!_stricmp(shortMessage, "/host") || !_stricmp(shortMessage, "/h") || !_stricmp(shortMessage, "!h") || !_stricmp(shortMessage, "!host") && Message[strlen(shortMessage)])
			{
				receiverID = -1;
			}

			delete[] shortMessage;
		}

		if (receiverID != -1)
		{
			cPlayer *receiverPlayerClass = Find_Player(receiverID);
			if (receiverPlayerClass && PlayerID != receiverID)
			{
				for (int x = 0; x < daRegisteredPluginsForChat->Count(); x++)
				{
					DAEventClass *daEventClass = (*daRegisteredPluginsForChat)[x]->Base;
					if (!daEventClass->vPtr->Chat_Event(daEventClass, senderPlayerClass, Type, Message, receiverID))
					{
						return false;
					}
				}
			}
		}
	}

	return result;
}

extern "C" __declspec(dllexport) Plugin* Plugin_Init()
{
	return &privateChatHookPlugin;
}
