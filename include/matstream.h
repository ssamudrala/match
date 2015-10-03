#ifndef _MATSTREAM_H
#define _MATSTREAM_H

#include <stdio.h>
#include <stdarg.h>

struct mat_stream;

struct mat_stream *mat_stream_stdout(void);
struct mat_stream *mat_stream_stderr(void);
struct mat_stream *mat_stream_logger(void);
struct mat_stream *mat_stream_file(FILE *fp);

void mat_stream_printf(struct mat_stream *matsp, const char *format, ...);
void mat_stream_vprintf(struct mat_stream *matsp, const char *format, va_list args);
FILE *mat_stream_get_fp(struct mat_stream *matsp);
void mat_stream_flush(struct mat_stream *matsp);

#endif	/* _MATSTREAM_H */
