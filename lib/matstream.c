#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>

#include <matlog.h>
#include <matstream.h>

#define __unused __attribute__((__unused__))

static struct mat_stream *_matstream_stdout = NULL;
static struct mat_stream *_matstream_stderr = NULL;
static struct mat_stream *_matstream_logger = NULL;

typedef void (*mat_stream_close_func_t)(struct mat_stream *stream);
typedef void (*mat_stream_open_func_t)(struct mat_stream *stream, const char *name);
typedef void (*mat_stream_printf_func_t)(struct mat_stream *stream,
					 const char *format, ...);
typedef void (*mat_stream_vprintf_func_t)(struct mat_stream *stream,
					  const char *format, va_list args);
typedef void (*mat_stream_flush_func_t)(struct mat_stream *stream);
typedef FILE * (*mat_stream_get_fp_func_t)(struct mat_stream *stream);
typedef void (*mat_stream_delete_func_t)(struct mat_stream *stream);

struct mat_stream_operations {
	mat_stream_delete_func_t delete;
	mat_stream_open_func_t open;
	mat_stream_close_func_t close;
	mat_stream_printf_func_t printf;
	mat_stream_vprintf_func_t vprintf;
	mat_stream_flush_func_t flush;
	mat_stream_get_fp_func_t get_fp;
};

struct mat_stream {
	const struct mat_stream_operations *op;
	void *ctx;
};


static void mat_stream_construct(struct mat_stream *matsp,
				 const struct mat_stream_operations *op,
				 void *ctx)
{
	if (!matsp)
		return;

	matsp->op = op;
	matsp->ctx = ctx;
}


struct mat_stream_stdio {
	struct mat_stream base;
	FILE *fp;
	int verbose;
};


static void mat_stream_stdio_close(struct mat_stream *matsp)
{
	struct mat_stream_stdio *matstdp = (struct mat_stream_stdio *)matsp;
	FILE *fp;

	if (!matsp || !matsp->op || (mat_stream_stdio_close != matsp->op->close))
		return;

	fp = matstdp->fp;
	matstdp->fp = NULL;

	if ((fp != stdout) && (fp != stderr))
		fclose(fp);
}


static void mat_stream_stdio_open(struct mat_stream *matsp, const char *name)
{
	struct mat_stream_stdio *matstdp = (struct mat_stream_stdio *)matsp;
	FILE *fp;

	if (!matsp || !matsp->op || (mat_stream_stdio_open != matsp->op->open))
		return;

	fp = fopen(name, "w");
	matstdp->fp = fp;
}


static FILE *mat_stream_stdio_get_fp(struct mat_stream *matsp)
{
	struct mat_stream_stdio *matstdp = (struct mat_stream_stdio *)matsp;


	if (!matsp || !matsp->op || (mat_stream_stdio_get_fp != matsp->op->get_fp))
		return NULL;

	return matstdp->fp;
}


static void mat_stream_stdio_vprintf(struct mat_stream *matsp,
				     const char *format, va_list args)
{
	struct mat_stream_stdio *matstdp = (struct mat_stream_stdio *)matsp;
	FILE *fp;

	if (!matsp || !matsp->op || (mat_stream_stdio_vprintf != matsp->op->vprintf))
		return;

	fp = matstdp->fp;
	if (!fp)
		return;

	vfprintf(fp, format, args);
}


static void mat_stream_stdio_printf(struct mat_stream *matsp,
				    const char *format, ...)
{
	struct mat_stream_stdio *matstdp = (struct mat_stream_stdio *)matsp;
	FILE *fp;
	va_list args;


	if (!matsp || !matsp->op || (mat_stream_stdio_printf != matsp->op->printf))
		return;

	fp = matstdp->fp;
	if (!fp)
		return;

	va_start(args, format);
	vfprintf(fp, format, args);
	va_end(args);
}


static void mat_stream_stdio_flush(struct mat_stream *matsp)
{
	struct mat_stream_stdio *matstdp = (struct mat_stream_stdio *)matsp;
	FILE *fp;


	if (!matsp || !matsp->op || (mat_stream_stdio_flush != matsp->op->flush))
		return;

	fp = matstdp->fp;
	if (!fp)
		return;

	fflush(fp);
}


static void mat_stream_stdio_delete(struct mat_stream *matsp)
{
	struct mat_stream_stdio *matstdp = (struct mat_stream_stdio *)matsp;
	FILE *fp;


	if (!matsp || !matsp->op || (mat_stream_stdio_delete != matsp->op->delete))
		return;

	fp = matstdp->fp;
	if (!fp)
		return;

	fflush(fp);
	fclose(fp);

	free(matstdp);
}


static const struct mat_stream_operations mat_stream_stdio_ops = {
	.delete = mat_stream_stdio_delete,
	.open = mat_stream_stdio_open,
	.close = mat_stream_stdio_close,
	.get_fp = mat_stream_stdio_get_fp,
	.printf = mat_stream_stdio_printf,
	.vprintf = mat_stream_stdio_vprintf,
	.flush = mat_stream_stdio_flush
};

static struct mat_stream_stdio *mat_stream_stdio_new(FILE *fp, int verbose)
{
	struct mat_stream_stdio *matstdp;

	matstdp = calloc(1, sizeof(*matstdp));
	if (!matstdp)
		return NULL;

	mat_stream_construct(&matstdp->base, &mat_stream_stdio_ops, NULL);

	matstdp->fp = fp;
	matstdp->verbose = verbose;

	return matstdp;
}


struct mat_stream_logger {
	struct mat_stream base;
	int level;
	char *buf_base;
	size_t capacity;
	char *write_ptr;
	size_t write_size;
};


static void mat_stream_logger_flush(struct mat_stream *matsp)
{
	struct mat_stream_logger *matlogp = (struct mat_stream_logger *)matsp;


	if (!matsp || !matsp->op || (mat_stream_logger_flush != matsp->op->flush))
		return;

	if (!matlogp->write_ptr || (matlogp->write_size <= 0))
		return;

	*matlogp->write_ptr = '\0';
	mat_syslog(matlogp->level, "%s", matlogp->buf_base);

	matlogp->write_ptr = matlogp->buf_base;
	matlogp->write_size = matlogp->capacity;
}


static void mat_stream_logger_close(struct mat_stream *matsp)
{
	if (!matsp || !matsp->op || (mat_stream_logger_close != matsp->op->close))
		return;

	mat_stream_logger_flush(matsp);
	mat_closelog();
}


static void mat_stream_logger_open(struct mat_stream *matsp, const char *name)
{
	if (!matsp || !matsp->op || (mat_stream_logger_open != matsp->op->open))
		return;

	mat_openlog(name);
}


static FILE *mat_stream_logger_get_fp(struct mat_stream *matsp)
{
	if (!matsp || !matsp->op || (mat_stream_logger_get_fp != matsp->op->get_fp))
		return NULL;

	return NULL;
}


static void mat_stream_logger_vprintf(struct mat_stream *matsp,
				     const char *format, va_list args)
{
	struct mat_stream_logger *matlogp = (struct mat_stream_logger *)matsp;
	va_list args_copy;
	int len;

	if (!matsp || !matsp->op || (mat_stream_logger_vprintf != matsp->op->vprintf))
		return;

	if (!matlogp->write_ptr || (matlogp->write_size <= 0))
		return;

	/*
	 * First attempt - format into available space in buffer
	 */
	va_copy(args_copy, args);
	len = vsnprintf(matlogp->write_ptr, matlogp->write_size, format, args_copy);
	va_end(args_copy);
	if ((len > 0) && ((size_t)len >= matlogp->write_size)) {
		/*
		 * Truncation has occured. No room left in buffer for entire string.
		 * Implicitly flush buffer content to logger and try again
		 */
		*matlogp->write_ptr = '\0';
		mat_syslog(matlogp->level, "%s", matlogp->buf_base);

		matlogp->write_ptr = matlogp->buf_base;
		matlogp->write_size = matlogp->capacity;

		/*
		 * Second attempt - format into an empty buffer
		 */
		len = vsnprintf(matlogp->write_ptr, matlogp->write_size, format, args);
		if ((len > 0) && ((size_t)len >= matlogp->write_size)) {
			/*
			 * Truncation has occured. Formatted string is longer than
			 * the buffer capacity. Log it directly to the logger
			 */
			mat_vsyslog(matlogp->level, format, args);
		} else if (len > 0) {
			matlogp->write_ptr += len;
			matlogp->write_size -= (size_t)len;
			/* Invariant (matlogp->write_size >= 1) */
		}
	} else if (len > 0) {
		matlogp->write_ptr += len;
		matlogp->write_size -= (size_t)len;
		/* Invariant (matlogp->write_size >= 1) */
	}
}


static void mat_stream_logger_printf(struct mat_stream *matsp,
				    const char *format, ...)
{
	va_list args;


	if (!matsp || !matsp->op || (mat_stream_logger_printf != matsp->op->printf))
		return;

	va_start(args, format);
	mat_stream_logger_vprintf(matsp, format, args);
	va_end(args);
}


static void mat_stream_logger_delete(struct mat_stream *matsp)
{
	struct mat_stream_logger *matlogp = (struct mat_stream_logger *)matsp;


	if (!matsp || !matsp->op || (mat_stream_logger_delete != matsp->op->delete))
		return;

	mat_stream_logger_flush(matsp);

	free(matlogp->buf_base);
	free(matlogp);
}


static const struct mat_stream_operations mat_stream_logger_ops = {
	.delete = mat_stream_logger_delete,
	.open = mat_stream_logger_open,
	.close = mat_stream_logger_close,
	.get_fp = mat_stream_logger_get_fp,
	.printf = mat_stream_logger_printf,
	.vprintf = mat_stream_logger_vprintf,
	.flush = mat_stream_logger_flush
};

static struct mat_stream_logger *mat_stream_logger_new(size_t logger_bufsize, int level)
{
	struct mat_stream_logger *matlogp;

	matlogp = calloc(1, sizeof(*matlogp));
	if (!matlogp)
		return NULL;

	matlogp->buf_base = calloc(logger_bufsize, sizeof(*matlogp->buf_base));
	if (!matlogp->buf_base) {
		free(matlogp);
		return NULL;
	}

	mat_stream_construct(&matlogp->base, &mat_stream_logger_ops, NULL);

	matlogp->level = level;
	matlogp->capacity = logger_bufsize;
	matlogp->write_ptr = matlogp->buf_base;
	matlogp->write_size = matlogp->capacity;

	return matlogp;
}


static struct mat_stream *mat_stream_create(FILE *fp, int verbose,
					    size_t logger_bufsize,
					    struct mat_stream_operations *op __unused,
					    void *ctx __unused)
{
	if (fp) {
		struct mat_stream_stdio *matstdp;

		matstdp = mat_stream_stdio_new(fp, verbose);
		if (matstdp)
			return &matstdp->base;
	} else if (logger_bufsize > 0) {
		struct mat_stream_logger *matlogp;

		matlogp = mat_stream_logger_new(logger_bufsize, MAT_LOG_INFO);
		if (matlogp)
			return &matlogp->base;
	}

	return NULL;
}


struct mat_stream *mat_stream_stdout(void)
{
	if (!_matstream_stdout) {
		_matstream_stdout = mat_stream_create(stdout, true, 0, NULL, NULL);
	}

	return _matstream_stdout;
}

struct mat_stream *mat_stream_stderr(void)
{
	if (!_matstream_stderr)
		_matstream_stderr = mat_stream_create(stderr, true, 0, NULL, NULL);

	return _matstream_stderr;
}

struct mat_stream *mat_stream_logger(void)
{
	if (!_matstream_logger)
		_matstream_logger = mat_stream_create(NULL, 0, LINE_MAX, NULL, NULL);

	return _matstream_logger;
}


void mat_stream_vprintf(struct mat_stream *matsp, const char *format, va_list args)
{
	if (!matsp || !matsp->op || !matsp->op->vprintf)
		return;

	matsp->op->vprintf(matsp, format, args);
}


void mat_stream_printf(struct mat_stream *matsp, const char *format, ...)
{
	va_list args;


	va_start(args, format);
	mat_stream_vprintf(matsp, format, args);
	va_end(args);
}


FILE *mat_stream_get_fp(struct mat_stream *matsp)
{
	if (!matsp || !matsp->op || !matsp->op->get_fp)
		return NULL;

	return matsp->op->get_fp(matsp);
}


void mat_stream_flush(struct mat_stream *matsp)
{
	if (!matsp || !matsp->op || !matsp->op->flush)
		return;

	matsp->op->flush(matsp);
}
