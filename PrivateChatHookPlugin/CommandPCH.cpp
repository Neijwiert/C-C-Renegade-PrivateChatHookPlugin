#include "General.h"
#include "CommandPCH.h"
#include "Globals.h"

#include <CommandLineParser.h>
#include <engine_player.h>

#define PCHALL_CONSOLE_FUNCTION_NAME "PCHALL"
#define PCHADD_CONSOLE_FUNCTION_NAME "PCHADD"
#define PCHREMOVE_CONSOLE_FUNCTION_NAME "PCHREMOVE"
#define PCHALL_CONSOLE_FUNCTION_HELP "PCHALL - Prints all names for players currently being logged"
#define PCHADD_CONSOLE_FUNCTION_HELP "PCHADD <clientId> - Enables private chat logging for client"
#define PCHREMOVE_CONSOLE_FUNCTION_HELP "PCHREMOVE <clientId> - Disables private chat logging for client"

static SimpleDynVecClass<int> loggingPlayers;

void InitCommands()
{
	ConsoleFunctionList.Add(new CommandPCHALL());
	ConsoleFunctionList.Add(new CommandPCHADD());
	ConsoleFunctionList.Add(new CommandPCHREMOVE());
}

void DeInitCommands()
{
	Delete_Console_Function(PCHALL_CONSOLE_FUNCTION_NAME);
	Delete_Console_Function(PCHADD_CONSOLE_FUNCTION_NAME);
	Delete_Console_Function(PCHREMOVE_CONSOLE_FUNCTION_NAME);
}

bool IsLoggingEnabledForPlayer(int playerId)
{
	return (loggingPlayers.Find_Index(playerId) != -1);
}

void RemoveLoggingForPlayer(int playerId)
{
	int index = loggingPlayers.Find_Index(playerId);
	if (index != -1)
	{
		loggingPlayers.Delete_Range(index, 1);
	}
}

int getClientIdByIdentifier(const char* clientIdentifier)
{
	TT_ASSERT(clientIdentifier);

	const cPlayer* player = Find_Player(atoi(clientIdentifier));

	int result;
	if (player)
	{
		result = player->Get_Id();
	}
	else
	{
		result = -1;
	}

	return result;
}

bool isClientId(const int id)
{
	return (id > 0 && id < 128 && Find_Player(id));
}

const char *CommandPCHALL::Get_Name()
{
	return PCHALL_CONSOLE_FUNCTION_NAME;
}

const char *CommandPCHALL::Get_Help()
{
	return PCHALL_CONSOLE_FUNCTION_HELP;
}

void CommandPCHALL::Activate(const char *pArgs)
{
	for (int x = 0; x < loggingPlayers.Count(); x++)
	{
		cPlayer *playerClass = Find_Player(loggingPlayers[x]);
		if (playerClass)
		{
			Console_Output("%ls (%d)\n", playerClass->Get_Name().Peek_Buffer(), loggingPlayers[x]);
		}
	}
}

void CommandPCHBase::Activate(const char *pArgs)
{
	CommandLineParser arguments(pArgs);
	const char* clientIdentifier = arguments.getString();
	if (!clientIdentifier || clientIdentifier[0] == '\0')
	{
		Console_Output("Please enter a client identifier.");
	}
	else
	{
		const int clientId = getClientIdByIdentifier(clientIdentifier);
		if (!isClientId(clientId))
		{
			Console_Output("Please enter a valid client identifier.");
		}
		else
		{
			HandleClientId(clientId);
		}
	}
}

const char *CommandPCHADD::Get_Name()
{
	return PCHADD_CONSOLE_FUNCTION_NAME;
}

const char *CommandPCHADD::Get_Help()
{
	return PCHADD_CONSOLE_FUNCTION_HELP;
}

void CommandPCHADD::HandleClientId(int clientId)
{
	int index = loggingPlayers.Find_Index(clientId);
	if (index == -1)
	{
		loggingPlayers.Add(clientId);
	}
}

const char *CommandPCHREMOVE::Get_Name()
{
	return PCHREMOVE_CONSOLE_FUNCTION_NAME;
}

const char *CommandPCHREMOVE::Get_Help()
{
	return PCHREMOVE_CONSOLE_FUNCTION_HELP;
}

void CommandPCHREMOVE::HandleClientId(int clientId)
{
	int index = loggingPlayers.Find_Index(clientId);
	if (index != -1)
	{
		loggingPlayers.Delete_Range(index, 1);
	}
}