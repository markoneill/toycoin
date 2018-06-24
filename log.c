#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "log.h"

#ifndef NO_LOG
FILE* g_log_file = NULL;
log_level_t g_log_level = LOG_WARNING;

void level_printf(log_level_t level);

int log_init(const char* log_filename, log_level_t level) {
	FILE* new_log_file;
	g_log_level = level;
	if (log_filename == NULL) {
		g_log_file = stdout;
		return 0;
	}

	new_log_file = fopen(log_filename, "a");
	if (new_log_file == NULL) {
		return -1;
	}
	g_log_file = new_log_file;
	return 0;
}

void log_printf(log_level_t level, const char* format, ...) {
	va_list args;
	if (level < g_log_level) {
		return;
	}
	if (g_log_file == NULL) {
		return;
	}
	level_printf(level);
	va_start(args, format);
	vfprintf(g_log_file, format, args);
	fflush(g_log_file);
	va_end(args);
	return;
}

void log_close(void) {
	if (g_log_file != stdout) {
		fclose(g_log_file);
	}
	g_log_file = NULL;
	return;
}

void level_printf(log_level_t level) {
	char level_str[32];
	switch(level) {
		case LOG_DEBUG:
			strcpy(level_str, "DEBUG:   ");
			break;
		case LOG_INFO:
			strcpy(level_str, "INFO:    ");
			break;
		case LOG_WARNING:
			strcpy(level_str, "WARNING: ");
			break;
		case LOG_ERROR:
			strcpy(level_str, "ERROR:   ");
			break;
	}
	fprintf(g_log_file, "%s", level_str);
	return;
}

#endif

