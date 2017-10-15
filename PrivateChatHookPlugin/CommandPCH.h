#pragma once

#include <engine_tt.h>

void InitCommands();
void DeInitCommands();
bool IsLoggingEnabledForPlayer(int playerId);
void RemoveLoggingForPlayer(int playerId);

class CommandPCHALL : public ConsoleFunctionClass
{
	public:
		virtual const char *Get_Name();
		virtual const char *Get_Help();
		virtual void Activate(const char *pArgs);
};

class CommandPCHBase abstract : public ConsoleFunctionClass
{
	public:
		virtual void Activate(const char *pArgs);

	protected:
		virtual void HandleClientId(int clientId) = 0;
};

class CommandPCHADD : public CommandPCHBase
{
	public:
		virtual const char *Get_Name();
		virtual const char *Get_Help();
	
	protected:
		virtual void HandleClientId(int clientId);
};

class CommandPCHREMOVE : public CommandPCHBase
{
	public:
		virtual const char *Get_Name();
		virtual const char *Get_Help();
		
	protected:
		virtual void HandleClientId(int clientId);
};