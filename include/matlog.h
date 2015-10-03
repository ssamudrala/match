#ifndef _MATLOG_H
#define _MATLOG_H

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#define MAT_LOG_EMERG   LOG_EMERG
#define MAT_LOG_ALERT   LOG_ALERT
#define MAT_LOG_CRIT    LOG_CRIT
#define MAT_LOG_ERR     LOG_ERR
#define MAT_LOG_WARNING LOG_WARNING
#define MAT_LOG_NOTICE  LOG_NOTICE
#define MAT_LOG_INFO    LOG_INFO
#define MAT_LOG_DEBUG   LOG_DEBUG

#define MAT_LOG_UPTO(upto) LOG_UPTO((upto))

/* Remove, at compile-time, MAT_LOG messages above MAT_LOG_LEVEL */
#ifndef MAT_LOG_LEVEL
#define MAT_LOG_LEVEL MAT_LOG_DEBUG
#endif

#define MATLOG_STRINGIFY_(x)   #x
/** Turns its parameter into a string, e.g.: MATLOG_STRINGIFY(var) => "var" */
#define MATLOG_STRINGIFY(x)    MATLOG_STRINGIFY_(x)

#ifndef MAT_LOG_WITH_LOCATION
#define MAT_LOG_WITH_LOCATION 0
#else	/* MAT_LOG_WITH_LOCATION */
#define MAT_LOG_WITH_LOCATION 1
#endif	/* MAT_LOG_WITH_LOCATION */

#ifndef MAT_LOG_FUNC
#if MAT_LOG_WITH_LOCATION
#define MAT_LOG_FUNC mat_syslog_with_location
#else	/* MAT_LOG_WITH_LOCATION */
#define MAT_LOG_FUNC mat_syslog
#endif	/* MAT_LOG_WITH_LOCATION */
#endif	/* MAT_LOG_FUNC */

#ifndef MAT_LOG_FUNC_ARGS
#if MAT_LOG_WITH_LOCATION
#define MAT_LOG_FUNC_ARGS(level, file, line, func, fmt, ...) \
	level, file, line, func, fmt, __VA_ARGS__
#else	/* MAT_LOG_WITH_LOCATION */
#define MAT_LOG_FUNC_ARGS(level, file, line, func, fmt, ...) \
	level, fmt, __VA_ARGS__
#endif	/* MAT_LOG_WITH_LOCATION */
#endif	/* MAT_LOG_FUNC_ARGS */

/**
 * Macro for logging messages.
 *
 * The MAT_LOG macro is helpful to remove debug/log messages at
 * compile time. Messages with level below MAT_LOG_LEVEL are
 * never emitted, and when compiled with optimization, are not
 * present in the compiled output.
 *
 * Integration with application logging is facilitated using
 * MAT_LOG_FUNC and MAT_LOG_FUNC(level, file, line, func, fmt, ...)
 * macros. Those macros could be defined externally by users
 * before including matlog.h. The logging function called
 * is defined by MAT_LOG_FUNC and its argument list is expanded
 * by MAT_LOG_FUNC_ARGS() macro.
 * This header file provides selection between mat_syslog and
 * mat_syslog_with_location functions. The default logging
 * function is mat_syslog. mat_syslog_with_location could be
 * selected by setting MAT_LOG_WITH_LOCATION before including
 * matlog.h.
 * Applications could have full control of logging including
 * augmentation of the formatting string and its arguments
 * by defining MAT_LOG_FUNC and MAT_LOG_FUNC_ARGS.
 * To offer such flexibility, a level of indirection is needed.
 * An internal _MAT_LOG() macro is used for isolating the
 * formatting string and separating it from its variable
 * argument list. There is one complication arising from that.
 * See note above MAT_LOG().
 */
#define _MAT_LOG(level, fmt, ...)					\
	do {								\
		if (level <= MAT_LOG_LEVEL)	{			\
			MAT_LOG_FUNC(					\
				MAT_LOG_FUNC_ARGS(level,		\
						  __FILE__, MATLOG_STRINGIFY(__LINE__), __func__, \
						  fmt "%s", __VA_ARGS__)); \
		}							\
	} while (0)

/*
 * The variadic part of MAT_LOG() macro must contain printf formatting
 * string and optional matching argument list. ISO C99, however, does
 * not allow for empty argument list. The variable part of the argument
 * list of the nested _MAT_LOG() would become empty when MAT_LOG()
 * is called with a fixed string instead of a formatting string.
 * This would result with compiler error:
 * error: ISO C99 requires rest arguments to be used
 * To overcome this, a trailing empty string argument is added adter
 * __VA_ARGS__. _MAT_LOG() above isolates the format string and append "%s"
 * control to match the trailing empty string.
 * level argument is one of abbreviated syslog priority levels
 * {EMERG | ALERT | CRIT | ERR | WARNING | NOTICE | INFO | DEBUG}
 * level argument is concatenated with MAT_LOG_ prefix within the
 * expansion of MAT_LOG(). The concatenation could not be deferred to
 * the nested _MAT_LOG() to prevent pre-matured expansion of
 * an abbreviated level symbol. A notable case is when -DDEBUG is
 * defined.
 */
#define MAT_LOG(level, ...) _MAT_LOG(MAT_LOG_ ## level, __VA_ARGS__, "")


void mat_closelog(void);
void mat_openlog(const char *name);
void mat_syslog(int level, const char *format, ...);
void mat_syslog_with_location(int level,
			      const char *file, const char *line, const char *func,
			      const char *format, ...);
void mat_vsyslog(int level, const char *format, va_list args);
void mat_vsyslog_with_location(int level,
			       const char *file, const char *line, const char *func,
			       const char *format, va_list args);

/* typdefs to allow for overriding default functions */
typedef void (*mat_closelog_func_t)(void);
typedef void (*mat_openlog_func_t)(const char *name);
typedef void (*mat_syslog_func_t)(int level, const char *format, va_list args);
typedef void (*mat_syslog_with_location_func_t)(int level,
						const char *file, const char *line, const char *func,
						const char *format, va_list args);

void mat_setlogmask(unsigned mask);
void mat_set_log_functions(mat_closelog_func_t closelog,
                           mat_openlog_func_t openlog,
                           mat_syslog_func_t syslog,
                           mat_syslog_with_location_func_t syslog_with_location);
void mat_set_log_stream(FILE *stream);

/* wrapper to syslog */
void mat_closelog_syslog(void);
void mat_openlog_syslog(const char *name);
void mat_syslog_syslog(int level, const char *format, va_list args);
void mat_syslog_with_location_syslog(int level,
				     const char *file, const char *line, const char *func,
				     const char *format, va_list args);

void mat_closelog_file(void);
void mat_openlog_file(const char *name);
void mat_syslog_file(int level, const char *format, va_list args);
void mat_syslog_with_location_file(int level,
				   const char *file, const char *line, const char *func,
				   const char *format, va_list args);

void mat_closelog_nop(void);
void mat_openlog_nop(const char *name);
void mat_syslog_nop(int level, const char *format, va_list args);
void mat_syslog_with_location_nop(int level,
				  const char *file, const char *line, const char *func,
				  const char *format, va_list args);

struct mat_logger {
	mat_closelog_func_t closelog;
	mat_openlog_func_t openlog;
	mat_syslog_func_t syslog;
	mat_syslog_with_location_func_t syslog_with_location;
	unsigned logmask;
	FILE *stream;
};

#endif /* _MATLOG_H */
