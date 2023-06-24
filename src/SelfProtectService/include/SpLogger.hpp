#ifndef SP_LOGGER_H
#define SP_LOGGER_H

#include <stdio.h>
#include <cstdarg>
#include <string.h>
#include <limits.h>
#include "../../SelfProtectService/include/SpConstants.hpp"

#define SP_LOG_FILEPATH                     "/var/log/selfprotect.log"

/* __VA_ARGS__ is only available in C++ 11 and onwards */
#if __cplusplus <= 199711L
#define SP_LOG_NOT_SUPPORTED                {\
                                                FILE *fp = fopen(SP_LOG_FILEPATH, "a+");\
                                                fprintf(fp, "%s\n", "Logging not supported");\
                                                fclose(fp);\
                                            }

#define sp_info(t, fmt, ...)                SP_LOG_NOT_SUPPORTED
#define sp_error(t, fmt, ...)               SP_LOG_NOT_SUPPORTED
#define sp_debug(t, fmt, ...)               SP_LOG_NOT_SUPPORTED
#define sp_warn(t, fmt, ...)                SP_LOG_NOT_SUPPORTED
#else
#define LOG_LOC_MAX_LEN                     128
#define LOG_MSG_MAX_LEN                     PATH_MAX + LOG_LOC_MAX_LEN + 1

/**
 * Gets code location (i.e file name, line number, date, time, etc.) for logging. 
 * This would be the location of the top caller in the call stack
 *
 * @param lv[in]    log level
 * @param t[in]     log type
 * @param str[out]  string to be populated with code location
 * @param len[in]   length of string to be populated
 * @param date[in]  current date
 * @param time[in]  current time
 * @param func[in]  function location
 * @param file[in]  file location
 * @param line[in]  line number
 */
#define LOG_LOCATION_FMT(lv, t, str, len, date, time, func, file, line)\
                                            ({\
                                                snprintf(str, len, "[%s %s]-[%s][%s]---[%s:%d@%s]: ", date,\
                                                                                                      time,\
                                                                                                      lv,\
                                                                                                      t,\
                                                                                                      file,\
                                                                                                      line,\
                                                                                                      func);\
                                            })

/**
 * Logs to a designated log file.
 *
 * @param lv    log level
 * @param t     log type
 * @param date  current date
 * @param time  current time
 * @param func  function location
 * @param file  file location
 * @param line  line number
 * @param fmt   formatted string message to write to log file (works like printf)
 * @param arg   variadic arguments for the formatted string
 */
#define SP_LOG(lv, t, date, time, func, file, line, fmt, ...)\
                                            ({\
                                                char log_msg[LOG_MSG_MAX_LEN];\
                                                FILE *fp = fopen(SP_LOG_FILEPATH, "a+");\
                                                \
                                                LOG_LOCATION_FMT(lv, t, log_msg, LOG_MSG_MAX_LEN, date, time, func, file, line);\
                                                fprintf(fp, "%s", log_msg);\
                                                snprintf(log_msg, LOG_MSG_MAX_LEN, fmt, ##__VA_ARGS__);\
                                                fprintf(fp, "%s\n", log_msg);\
                                                fclose(fp);\
                                            })

#define sp_info(t, fmt, ...)                SP_LOG(SP_INFO, t, __DATE__, __TIME__, __FUNCTION__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define sp_error(t, fmt, ...)               SP_LOG(SP_ERROR, t, __DATE__, __TIME__, __FUNCTION__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
/* only log debug and warn if debug macro is defined */
#ifdef DEBUG
#define sp_debug(t, fmt, ...)               SP_LOG(SP_DEBUG, t, __DATE__, __TIME__, __FUNCTION__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define sp_warn(t, fmt, ...)                SP_LOG(SP_WARN, t, __DATE__, __TIME__, __FUNCTION__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define sp_debug(t, fmt, ...)               do{} while(0)
#define sp_warn(t, fmt, ...)                do{} while(0)
#endif
/**
 * Logs an event separator to the log file
 */
#define SP_LOG_SEPARATE_EVENT               {\
                                                FILE *fp = fopen(SP_LOG_FILEPATH, "a+");\
                                                fprintf(fp, "%s\n", "-------------------------------------------------------------------------");\
                                                fclose(fp);\
                                            }

#endif

#endif