#ifndef LOG_H
#define LOG_H

typedef enum log_level {
	LOG_DEBUG,
	LOG_INFO,
	LOG_WARNING,
	LOG_ERROR,
} log_level_t;

#ifndef NO_LOG
int log_init(const char* log_filename, log_level_t level);
void log_printf(log_level_t level, const char* format, ...);
void log_close(void);
#else
#define log_init(X, Y)	((int)0)
#define log_printf (void)sizeof
#define log_printf_addr (void)sizeof
#define log_close() ((void)0)
#endif

#endif
