/*	Renegade Scripts.dll
	Copyright 2013 Tiberian Technologies

	This file is part of the Renegade scripts.dll
	The Renegade scripts.dll is free software; you can redistribute it and/or modify it under
	the terms of the GNU General Public License as published by the Free
	Software Foundation; either version 2, or (at your option) any later
	version. See the file COPYING for more details.
	In addition, an exemption is given to allow Run Time Dynamic Linking of this code with any closed source module that does not contain code covered by this licence.
	Only the source code to the module(s) containing the licenced code has to be released.
*/
#pragma once

#include <gmplugin.h>
#include <cNetEvent.h>

enum ScriptsVersion
{
	SCRIPTS_VERSION_VANILLA_4_50,
	SCRIPTS_VERSION_VANILLA_4_40,
	SCRIPTS_VERSION_VANILLA_4_30,
	SCRIPTS_VERSION_VANILLA_4_2_4,
	SCRIPTS_VERSION_DA_1_92,
	SCRIPTS_VERSION_DA_1_90,
	SCRIPTS_VERSION_DA_1_8_1,
	SCRIPTS_VERSION_UNKNOWN
};

enum BandTestVersion
{
	BANDTEST_VERSION_VANILLA_4_50,
	BANDTEST_VERSION_VANILLA_4_40,
	BANDTEST_VERSION_VANILLA_4_30,
	BANDTEST_VERSION_VANILLA_4_2_4,
	BANDTEST_VERSION_UNKNOWN
};

enum DAVersion
{
	DA_VERSION_DA_1_92,
	DA_VERSION_DA_1_90,
	DA_VERSION_DA_1_8_1,
	DA_VERSION_UNKNOWN
};

struct cCsTextObj;

class PrivateChatHookPlugin : public Plugin
{
	public:
		PrivateChatHookPlugin();
		~PrivateChatHookPlugin();

		virtual void OnLoadGlobalINISettings(INIClass *SSGMIni);
		virtual bool OnChat(int PlayerID, TextMessageEnum Type, const wchar_t *Message, int recieverID);
		virtual void OnPlayerLeave(int PlayerID);

		bool DetermineVersion();
		bool HookChat();
		bool UnhookChat();
		bool HookChatEvents();

	private:
		static bool __cdecl ChatEvent(cCsTextObj *textObj);
		static bool __cdecl DAChatEvent(int PlayerID, TextMessageEnum Type, wchar_t *Message, int receiverID);

		bool minHookInitialized;
		bool hookedChat;
		bool hookedChatEvents;
		bool isDragonadeServer;
		bool checkedVersion;
		ScriptsVersion scriptsVersion;
		BandTestVersion bandTestVersion;
		DAVersion daVersion;
};
