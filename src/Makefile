CC = g++
CFLAGS = -Wall -g

object_files = FanotifyEvents.o\
			   FileSystem.o\
			   cli_helper.o\
			   jsmn.o\
			   FileTransport.o\
			   Trust.o\
			   QueryHistory.o\
			   SelfProtectService.o\
			   TokenManager.o\
			   TokenCache.o\
			   FileManagerCallbacks.o\
			   FileManagerBackups.o\
			   FileManager.o
self_protect_targets = FanotifyEvents/FanotifyEvents.o\
					   FileSystem/FileSystem.o\
					   CLI_Interface/cli_helper.o\
					   json/jsmn.o\
					   FileTransport/FileTransport.o\
					   Trust/Trust.o\
					   QueryHistory/QueryHistory.o\
					   SelfProtectService/SelfProtectService.o\
					   TokenManager/TokenManager.o\
					   TokenManager/TokenCache.o\
					   FileManager/FileManagerCallbacks.o\
					   FileManager/FileManagerBackups.o\
					   FileManager/FileManager.o

sysd_monitor_obj_files = SysdServiceMonitor.o
sysd_monitor_targets = Sysd/SysdServiceMonitor.o

sysd_monitor_client_obj_files = SysdClient.o\
								cli_helper.o\
								jsmn.o\
								TokenManager.o\
			   					TokenCache.o
sysd_monitor_client_targets = Sysd/SysdClient.o\
							  CLI_Interface/cli_helper.o\
							  json/jsmn.o\
							  TokenManager/TokenManager.o\
					   		  TokenManager/TokenCache.o\

query_history_client_obj_files = QueryHistory.o\
								 jsmn.o\
								 QueryHistoryClient.o
query_history_client_targets = QueryHistory/QueryHistory.o\
							   json/jsmn.o\
							   QueryHistory/QueryHistoryClient.o

linker_lib = -lcurl\
			 -lcrypto\
			 -lssl

self_protect: $(self_protect_targets)
	$(CC) $(CFLAGS) $(object_files) -o /usr/bin/self_protect $(linker_lib)

FileManager/FileManagerCallbacks.o: FileManager/FileManagerCallbacks.cpp FileManager/include/FileManagerCallbacks.hpp
	$(CC) $(CFLAGS) -c FileManager/FileManagerCallbacks.cpp

FileManager/FileManagerBackups.o: FileManager/FileManagerBackups.cpp FileManager/include/FileManagerBackups.hpp
	$(CC) $(CFLAGS) -c FileManager/FileManagerBackups.cpp

SelfProtectService/SelfProtectService.o: SelfProtectService/SelfProtectService.cpp SelfProtectService/include/SelfProtectService.hpp
	$(CC) $(CFLAGS) -c SelfProtectService/SelfProtectService.cpp

CLI_Interface/CLI_Interface.o: CLI_Interface/CLI_Interface.cpp CLI_Interface/include/CLI_Interface.hpp
	$(CC) $(CFLAGS) -c CLI_Interface/CLI_Interface.cpp

TokenManager/TokenManager.o: TokenManager/TokenManager.cpp TokenManager/include/TokenManager.hpp
	$(CC) $(CFLAGS) -c TokenManager/TokenManager.cpp

TokenManager/TokenCache.o: TokenManager/TokenCache.cpp TokenManager/include/TokenCache.hpp
	$(CC) $(CFLAGS) -c TokenManager/TokenCache.cpp

FileManager/FileManager.o: FileManager/FileManager.cpp FileManager/include/FileManager.hpp
	$(CC) $(CFLAGS) -c FileManager/FileManager.cpp

FanotifyEvents/FanotifyEvents.o: FanotifyEvents/FanotifyEvents.cpp FanotifyEvents/include/FanotifyEvents.hpp
	$(CC) $(CFLAGS) -c FanotifyEvents/FanotifyEvents.cpp

FileSystem/FileSystem.o: FileSystem/FileSystem.cpp FileSystem/include/FileSystem.hpp
	$(CC) $(CFLAGS) -c FileSystem/FileSystem.cpp

CLI_Interface/cli_helper.o: CLI_Interface/cli_helper.c CLI_Interface/include/cli_helper.h
	$(CC) $(CFLAGS) -c CLI_Interface/cli_helper.c

json/jsmn.o: json/jsmn.c json/include/jsmn.h
	$(CC) $(CFLAGS) -c json/jsmn.c

FileTransport/FileTransport.o: FileTransport/FileTransport.cpp FileTransport/include/FileTransport.hpp
	$(CC) $(CFLAGS) -c FileTransport/FileTransport.cpp

Trust/Trust.o: Trust/Trust.cpp Trust/include/Trust.hpp
	$(CC) $(CFLAGS) -c Trust/Trust.cpp

QueryHistory/QueryHistory.o: QueryHistory/QueryHistory.cpp QueryHistory/include/QueryHistory.hpp
	$(CC) $(CFLAGS) -c QueryHistory/QueryHistory.cpp

sysd_monitor: $(sysd_monitor_targets)
	$(CC) $(CFLAGS) $(sysd_monitor_obj_files) -o /usr/bin/sysd_service_monitor $(linker_lib)

Sysd/SysdServiceMonitor.o: Sysd/SysdServiceMonitor.cpp
	$(CC) $(CFLAGS) -c Sysd/SysdServiceMonitor.cpp

sysd_monitor_client: $(sysd_monitor_client_targets)
	$(CC) $(CFLAGS) $(sysd_monitor_client_obj_files) -o /usr/bin/sysd_client $(linker_lib)

Sysd/SysdClient.o: Sysd/SysdClient.cpp
	$(CC) $(CFLAGS) -c Sysd/SysdClient.cpp

query_history_client: $(query_history_client_targets)
	$(CC) $(CFLAGS) $(query_history_client_obj_files) -o /opt/self_protect/bin/attempts_history $(linker_lib)

QueryHistory/QueryHistoryClient.o: QueryHistory/QueryHistoryClient.cpp
	$(CC) $(CFLAGS) -c QueryHistory/QueryHistoryClient.cpp

clean:
	rm *.o
