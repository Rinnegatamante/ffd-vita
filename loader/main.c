/* main.c -- Final Fantasy Dimensions .so loader
 *
 * Copyright (C) 2021 Andy Nguyen
 * Copyright (C) 2024 Rinnegatamante
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.	See the LICENSE file for details.
 */

#include <vitasdk.h>
#include <kubridge.h>
#include <vitashark.h>
#include <vitaGL.h>
#include <zlib.h>

#define AL_ALEXT_PROTOTYPES
#include <AL/alext.h>
#include <AL/efx.h>

#include <malloc.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <wchar.h>
#include <wctype.h>

#include <math.h>
#include <math_neon.h>
#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>

#include <errno.h>
#include <ctype.h>
#include <setjmp.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "main.h"
#include "config.h"
#include "dialog.h"
#include "so_util.h"
#include "sha1.h"

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#include "stb_image.h"

#define STB_TRUETYPE_IMPLEMENTATION
#include "stb_truetype.h"

//#define ENABLE_DEBUG

void *__wrap_calloc(uint32_t nmember, uint32_t size) { return vglCalloc(nmember, size); }
void __wrap_free(void *addr) { vglFree(addr); };
void *__wrap_malloc(uint32_t size) { return vglMalloc(size); };
void *__wrap_memalign(uint32_t alignment, uint32_t size) { return vglMemalign(alignment, size); };
void *__wrap_realloc(void *ptr, uint32_t size) { return vglRealloc(ptr, size); };
void *__wrap_memcpy (void *dst, const void *src, size_t num) { return sceClibMemcpy(dst, src, num); };
void *__wrap_memset (void *ptr, int value, size_t num) { return sceClibMemset(ptr, value, num); };

int _opensles_user_freq = 44100;

static char fake_vm[0x1000];
static char fake_env[0x1000];

int _newlib_heap_size_user = MEMORY_NEWLIB_MB * 1024 * 1024;

unsigned int _pthread_stack_default_user = 1 * 1024 * 1024;

so_module main_mod;

void *__wrap_memmove(void *dest, const void *src, size_t n) {
	return sceClibMemmove(dest, src, n);
}

int debugPrintf(char *fmt, ...) {
#ifdef ENABLE_DEBUG
	va_list list;
	static char string[0x8000];

	va_start(list, fmt);
	vsprintf(string, fmt, list);
	va_end(list);

	printf("[DBG] %s\n", string);
#endif
	return 0;
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
#ifdef ENABLE_DEBUG
	va_list list;
	static char string[0x8000];

	va_start(list, fmt);
	vsprintf(string, fmt, list);
	va_end(list);

	printf("[LOG] %s: %s\n", tag, string);
#endif
	return 0;
}

int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list list) {
#ifdef ENABLE_DEBUG
	static char string[0x8000];

	vsprintf(string, fmt, list);
	va_end(list);

	printf("[LOGV] %s: %s\n", tag, string);
#endif
	return 0;
}

int ret0(void) {
	return 0;
}

int ret1(void) {
	return 1;
}

int clock_gettime(int clk_ik, struct timespec *t) {
	struct timeval now;
	int rv = gettimeofday(&now, NULL);
	if (rv)
		return rv;
	t->tv_sec = now.tv_sec;
	t->tv_nsec = now.tv_usec * 1000;
	return 0;
}

int pthread_mutex_init_fake(pthread_mutex_t **uid,
														const pthread_mutexattr_t *mutexattr) {
	pthread_mutex_t *m = calloc(1, sizeof(pthread_mutex_t));
	if (!m)
		return -1;

	const int recursive = (mutexattr && *(const int *)mutexattr == 1);
	*m = recursive ? PTHREAD_RECURSIVE_MUTEX_INITIALIZER
								 : PTHREAD_MUTEX_INITIALIZER;

	int ret = pthread_mutex_init(m, mutexattr);
	if (ret < 0) {
		free(m);
		return -1;
	}

	*uid = m;

	return 0;
}

int pthread_mutex_destroy_fake(pthread_mutex_t **uid) {
	if (uid && *uid && (uintptr_t)*uid > 0x8000) {
		pthread_mutex_destroy(*uid);
		free(*uid);
		*uid = NULL;
	}
	return 0;
}

int pthread_mutex_lock_fake(pthread_mutex_t **uid) {
	int ret = 0;
	if (!*uid) {
		ret = pthread_mutex_init_fake(uid, NULL);
	} else if ((uintptr_t)*uid == 0x4000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	} else if ((uintptr_t)*uid == 0x8000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	if (ret < 0)
		return ret;
	return pthread_mutex_lock(*uid);
}

int pthread_mutex_unlock_fake(pthread_mutex_t **uid) {
	int ret = 0;
	if (!*uid) {
		ret = pthread_mutex_init_fake(uid, NULL);
	} else if ((uintptr_t)*uid == 0x4000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	} else if ((uintptr_t)*uid == 0x8000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	if (ret < 0)
		return ret;
	return pthread_mutex_unlock(*uid);
}

int pthread_cond_init_fake(pthread_cond_t **cnd, const int *condattr) {
	pthread_cond_t *c = calloc(1, sizeof(pthread_cond_t));
	if (!c)
		return -1;

	*c = PTHREAD_COND_INITIALIZER;

	int ret = pthread_cond_init(c, NULL);
	if (ret < 0) {
		free(c);
		return -1;
	}

	*cnd = c;

	return 0;
}

int pthread_cond_broadcast_fake(pthread_cond_t **cnd) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_broadcast(*cnd);
}

int pthread_cond_signal_fake(pthread_cond_t **cnd) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_signal(*cnd);
}

int pthread_cond_destroy_fake(pthread_cond_t **cnd) {
	if (cnd && *cnd) {
		pthread_cond_destroy(*cnd);
		free(*cnd);
		*cnd = NULL;
	}
	return 0;
}

int pthread_cond_wait_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_wait(*cnd, *mtx);
}

int pthread_cond_timedwait_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx,
																const struct timespec *t) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_timedwait(*cnd, *mtx, t);
}

int pthread_create_fake(pthread_t *thread, const void *unused, void *entry,
												void *arg) {
	return pthread_create(thread, NULL, entry, arg);
}

int pthread_once_fake(volatile int *once_control, void (*init_routine)(void)) {
	if (!once_control || !init_routine)
		return -1;
	if (__sync_lock_test_and_set(once_control, 1) == 0)
		(*init_routine)();
	return 0;
}

int GetCurrentThreadId(void) {
	return sceKernelGetThreadId();
}

extern void *__aeabi_ldiv0;

int GetEnv(void *vm, void **env, int r2) {
	*env = fake_env;
	return 0;
}

void *GetJNIEnv(void *this) {
	return fake_env;
}

void patch_game(void) {
	
}

extern void *__aeabi_atexit;
extern void *__aeabi_idiv;
extern void *__aeabi_idivmod;
extern void *__aeabi_ldivmod;
extern void *__aeabi_uidiv;
extern void *__aeabi_uidivmod;
extern void *__aeabi_uldivmod;
extern void *__cxa_atexit;
extern void *__cxa_finalize;
extern void *__gnu_unwind_frame;
extern void *__stack_chk_fail;
int open(const char *pathname, int flags);

static int __stack_chk_guard_fake = 0x42424242;

static char *__ctype_ = (char *)&_ctype_;

static FILE __sF_fake[0x100][3];

int stat_hook(const char *pathname, void *statbuf) {
	sceClibPrintf("stat %s\n", pathname);
	char real_fname[128];
	sprintf(real_fname, "%s.mp3", pathname);
	
	struct stat st;
	int res = stat(real_fname, &st);
	if (res == 0)
		*(uint64_t *)(statbuf + 0x30) = st.st_size;
	return res;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
					 off_t offset) {
	return malloc(length);
}

int munmap(void *addr, size_t length) {
	free(addr);
	return 0;
}

FILE *fopen_hook(char *fname, char *mode) {
	//sceClibPrintf("opening %s %s\n", fname, mode);
	char full_path[256];
	sprintf(full_path, "ux0:data/ffd%s", fname);
	return fopen(full_path, mode);
}

int open_hook(const char *fname, int flags) {
	return open(fname, flags);
}

int fstat_hook(int fd, void *statbuf) {
	struct stat st;
	int res = fstat(fd, &st);
	if (res == 0)
		*(uint64_t *)(statbuf + 0x30) = st.st_size;
	return res;
}

void *sceClibMemclr(void *dst, SceSize len) {
  return sceClibMemset(dst, 0, len);
}

void *sceClibMemset2(void *dst, SceSize len, int ch) {
  return sceClibMemset(dst, ch, len);
}

pid_t gettid() {
	return sceKernelGetThreadId();
}

int nanosleep_hook(const struct timespec *req, struct timespec *rem) {
	const uint32_t usec = req->tv_sec * 1000 * 1000 + req->tv_nsec / 1000;
	return sceKernelDelayThreadCB(usec);
}

FILE *AAssetManager_open(void *mgr, const char *fname, int mode) {
	char full_fname[256];
	sprintf(full_fname, "ux0:data/ffd/assets/%s", fname);
	//printf("AAssetManager_open %s\n", full_fname);
	return fopen(full_fname, "rb");
}

FILE *saved_fp = NULL;
int AAsset_openFileDescriptor64(FILE *f, int64_t *start, int64_t *len) {
	fseek(f, *start, SEEK_SET);
	saved_fp = f;
	return 1;
}

FILE *fdopen_hook(int fd, const char *mode) {
	if (fd == 1) {
		FILE *r = saved_fp;
		saved_fp = NULL;
		return r;
	}
	return fdopen(fd, mode);
}

int AAsset_close(FILE *f) {
	if (saved_fp) {
		return 0;
	}
	return fclose(f);
}

size_t AAsset_getLength(FILE *f) {
	size_t p = ftell(f);
	fseek(f, 0, SEEK_END);
	size_t res = ftell(f);
	fseek(f, p, SEEK_SET);
	return res;
}

uint64_t AAsset_getLength64(FILE *f) {
	size_t p = ftell(f);
	fseek(f, 0, SEEK_END);
	uint64_t res = ftell(f);
	fseek(f, p, SEEK_SET);
	return res;
}

size_t AAsset_read(FILE *f, void *buf, size_t count) {
	return fread(buf, 1, count, f);
}

size_t AAsset_seek(FILE *f, size_t offs, int whence) {
	fseek(f, offs, whence);
	return ftell(f);
}

size_t __strlen_chk(const char *s, size_t s_len) {
	return strlen(s);
}

int __vsprintf_chk(char* dest, int flags, size_t dest_len_from_compiler, const char *format, va_list va) {
	return vsprintf(dest, format, va);
}

void *__memmove_chk(void *dest, const void *src, size_t len, size_t dstlen) {
	return memmove(dest, src, len);
}

void *__memset_chk(void *dest, int val, size_t len, size_t dstlen) {
	return memset(dest, val, len);
}

size_t __strlcat_chk (char *dest, char *src, size_t len, size_t dstlen) {
	return strlcat(dest, src, len);
}

size_t __strlcpy_chk (char *dest, char *src, size_t len, size_t dstlen) {
	return strlcpy(dest, src, len);
}

char* __strchr_chk(const char* p, int ch, size_t s_len) {
	return strchr(p, ch);
}

char *__strcat_chk(char *dest, const char *src, size_t destlen) {
	return strcat(dest, src);
}

char *__strrchr_chk(const char *p, int ch, size_t s_len) {
	return strrchr(p, ch);
}

char *__strcpy_chk(char *dest, const char *src, size_t destlen) {
	return strcpy(dest, src);
}

char *__strncat_chk(char *s1, const char *s2, size_t n, size_t s1len) {
	return strncat(s1, s2, n);
}

void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) {
	return memcpy(dest, src, len);
}

int __vsnprintf_chk(char *s, size_t maxlen, int flag, size_t slen, const char *format, va_list args) {
	return vsnprintf(s, maxlen, format, args);
}

extern void *_Znaj;
extern void *_ZdaPv;
extern void *_Znwj;
extern void *_ZdlPv;

static so_default_dynlib default_dynlib[] = {
	{ "_Znaj", (uintptr_t)&_Znaj },
	{ "_ZdaPv", (uintptr_t)&_ZdaPv },
	{ "_Znwj", (uintptr_t)&_Znwj },
	{ "_ZdlPv", (uintptr_t)&_ZdlPv },
	{ "__strcat_chk", (uintptr_t)&__strcat_chk },
	{ "__strchr_chk", (uintptr_t)&__strchr_chk },
	{ "__strcpy_chk", (uintptr_t)&__strcpy_chk },
	{ "__strlcat_chk", (uintptr_t)&__strlcat_chk },
	{ "__strlcpy_chk", (uintptr_t)&__strlcpy_chk },
	{ "__strlen_chk", (uintptr_t)&__strlen_chk },
	{ "__strncat_chk", (uintptr_t)&__strncat_chk },
	{ "__strrchr_chk", (uintptr_t)&__strrchr_chk },
	{ "__vsprintf_chk", (uintptr_t)&__vsprintf_chk },
	{ "__vsnprintf_chk", (uintptr_t)&__vsnprintf_chk },
	{ "__memcpy_chk", (uintptr_t)&__memcpy_chk },
	{ "setpriority", (uintptr_t)&ret0 },
	{ "nanosleep", (uintptr_t)&nanosleep_hook },
	{ "SL_IID_ANDROIDSIMPLEBUFFERQUEUE", (uintptr_t)&SL_IID_ANDROIDSIMPLEBUFFERQUEUE},
	{ "SL_IID_AUDIOIODEVICECAPABILITIES", (uintptr_t)&SL_IID_AUDIOIODEVICECAPABILITIES},
	{ "SL_IID_BUFFERQUEUE", (uintptr_t)&SL_IID_BUFFERQUEUE},
	{ "SL_IID_DYNAMICSOURCE", (uintptr_t)&SL_IID_DYNAMICSOURCE},
	{ "SL_IID_ENGINE", (uintptr_t)&SL_IID_ENGINE},
	{ "SL_IID_LED", (uintptr_t)&SL_IID_LED},
	{ "SL_IID_NULL", (uintptr_t)&SL_IID_NULL},
	{ "SL_IID_METADATAEXTRACTION", (uintptr_t)&SL_IID_METADATAEXTRACTION},
	{ "SL_IID_METADATATRAVERSAL", (uintptr_t)&SL_IID_METADATATRAVERSAL},
	{ "SL_IID_OBJECT", (uintptr_t)&SL_IID_OBJECT},
	{ "SL_IID_OUTPUTMIX", (uintptr_t)&SL_IID_OUTPUTMIX},
	{ "SL_IID_PLAY", (uintptr_t)&SL_IID_PLAY},
	{ "SL_IID_VIBRA", (uintptr_t)&SL_IID_VIBRA},
	{ "SL_IID_VOLUME", (uintptr_t)&SL_IID_VOLUME},
	{ "SL_IID_PREFETCHSTATUS", (uintptr_t)&SL_IID_PREFETCHSTATUS},
	{ "SL_IID_PLAYBACKRATE", (uintptr_t)&SL_IID_PLAYBACKRATE},
	{ "SL_IID_SEEK", (uintptr_t)&SL_IID_SEEK},
	{ "SL_IID_RECORD", (uintptr_t)&SL_IID_RECORD},
	{ "SL_IID_EQUALIZER", (uintptr_t)&SL_IID_EQUALIZER},
	{ "SL_IID_DEVICEVOLUME", (uintptr_t)&SL_IID_DEVICEVOLUME},
	{ "SL_IID_PRESETREVERB", (uintptr_t)&SL_IID_PRESETREVERB},
	{ "SL_IID_ENVIRONMENTALREVERB", (uintptr_t)&SL_IID_ENVIRONMENTALREVERB},
	{ "SL_IID_EFFECTSEND", (uintptr_t)&SL_IID_EFFECTSEND},
	{ "SL_IID_3DGROUPING", (uintptr_t)&SL_IID_3DGROUPING},
	{ "SL_IID_3DCOMMIT", (uintptr_t)&SL_IID_3DCOMMIT},
	{ "SL_IID_3DLOCATION", (uintptr_t)&SL_IID_3DLOCATION},
	{ "SL_IID_3DDOPPLER", (uintptr_t)&SL_IID_3DDOPPLER},
	{ "SL_IID_3DSOURCE", (uintptr_t)&SL_IID_3DSOURCE},
	{ "SL_IID_3DMACROSCOPIC", (uintptr_t)&SL_IID_3DMACROSCOPIC},
	{ "SL_IID_MUTESOLO", (uintptr_t)&SL_IID_MUTESOLO},
	{ "SL_IID_DYNAMICINTERFACEMANAGEMENT", (uintptr_t)&SL_IID_DYNAMICINTERFACEMANAGEMENT},
	{ "SL_IID_MIDIMESSAGE", (uintptr_t)&SL_IID_MIDIMESSAGE},
	{ "SL_IID_MIDIMUTESOLO", (uintptr_t)&SL_IID_MIDIMUTESOLO},
	{ "SL_IID_MIDITEMPO", (uintptr_t)&SL_IID_MIDITEMPO},
	{ "SL_IID_MIDITIME", (uintptr_t)&SL_IID_MIDITIME},
	{ "SL_IID_AUDIODECODERCAPABILITIES", (uintptr_t)&SL_IID_AUDIODECODERCAPABILITIES},
	{ "SL_IID_AUDIOENCODERCAPABILITIES", (uintptr_t)&SL_IID_AUDIOENCODERCAPABILITIES},
	{ "SL_IID_AUDIOENCODER", (uintptr_t)&SL_IID_AUDIOENCODER},
	{ "SL_IID_BASSBOOST", (uintptr_t)&SL_IID_BASSBOOST},
	{ "SL_IID_PITCH", (uintptr_t)&SL_IID_PITCH},
	{ "SL_IID_RATEPITCH", (uintptr_t)&SL_IID_RATEPITCH},
	{ "SL_IID_VIRTUALIZER", (uintptr_t)&SL_IID_VIRTUALIZER},
	{ "SL_IID_VISUALIZATION", (uintptr_t)&SL_IID_VISUALIZATION},
	{ "SL_IID_ENGINECAPABILITIES", (uintptr_t)&SL_IID_ENGINECAPABILITIES},
	{ "SL_IID_THREADSYNC", (uintptr_t)&SL_IID_THREADSYNC},
	{ "SL_IID_ANDROIDEFFECT", (uintptr_t)&SL_IID_ANDROIDEFFECT},
	{ "SL_IID_ANDROIDEFFECTSEND", (uintptr_t)&SL_IID_ANDROIDEFFECTSEND},
	{ "SL_IID_ANDROIDEFFECTCAPABILITIES", (uintptr_t)&SL_IID_ANDROIDEFFECTCAPABILITIES},
	{ "SL_IID_ANDROIDCONFIGURATION", (uintptr_t)&SL_IID_ANDROIDCONFIGURATION},
	{ "slCreateEngine", (uintptr_t)&slCreateEngine },
	{ "AAssetManager_fromJava", (uintptr_t)&ret1 },
	{ "AAssetManager_open", (uintptr_t)&AAssetManager_open },
	{ "AAsset_close", (uintptr_t)&AAsset_close },
	{ "AAsset_read", (uintptr_t)&AAsset_read },
	{ "AAsset_getLength", (uintptr_t)&AAsset_getLength },
	{ "AAsset_getLength64", (uintptr_t)&AAsset_getLength64 },
	{ "AAsset_seek", (uintptr_t)&AAsset_seek },
	{ "AAsset_openFileDescriptor64", (uintptr_t)&AAsset_openFileDescriptor64 },
	{ "__aeabi_memclr", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memclr4", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memclr8", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memcpy", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memcpy4", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memcpy8", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memmove", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memmove4", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memmove8", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memset", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_memset4", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_memset8", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_atexit", (uintptr_t)&__aeabi_atexit },
	{ "__aeabi_uidiv", (uintptr_t)&__aeabi_uidiv },
	{ "__aeabi_uidivmod", (uintptr_t)&__aeabi_uidivmod },
	{ "__aeabi_idiv", (uintptr_t)&__aeabi_idiv },
	{ "__aeabi_idivmod", (uintptr_t)&__aeabi_idivmod },
	{ "__android_log_print", (uintptr_t)&__android_log_print },
	{ "__android_log_vprint", (uintptr_t)&__android_log_vprint },
	{ "__cxa_atexit", (uintptr_t)&__cxa_atexit },
	{ "__cxa_finalize", (uintptr_t)&__cxa_finalize },
	{ "__errno", (uintptr_t)&__errno },
	{ "__gnu_unwind_frame", (uintptr_t)&__gnu_unwind_frame },
	// { "__google_potentially_blocking_region_begin", (uintptr_t)&__google_potentially_blocking_region_begin },
	// { "__google_potentially_blocking_region_end", (uintptr_t)&__google_potentially_blocking_region_end },
	{ "__sF", (uintptr_t)&__sF_fake },
	{ "__stack_chk_fail", (uintptr_t)&__stack_chk_fail },
	{ "__stack_chk_guard", (uintptr_t)&__stack_chk_guard_fake },
	{ "_ctype_", (uintptr_t)&__ctype_ },
	{ "abort", (uintptr_t)&abort },
	// { "accept", (uintptr_t)&accept },
	{ "acos", (uintptr_t)&acos },
	{ "acosf", (uintptr_t)&acosf },
	{ "asin", (uintptr_t)&asin },
	{ "asinf", (uintptr_t)&asinf },
	{ "atan", (uintptr_t)&atan },
	{ "atan2", (uintptr_t)&atan2 },
	{ "atan2f", (uintptr_t)&atan2f },
	{ "atanf", (uintptr_t)&atanf },
	{ "atoi", (uintptr_t)&atoi },
	{ "atoll", (uintptr_t)&atoll },
	// { "bind", (uintptr_t)&bind },
	{ "bsearch", (uintptr_t)&bsearch },
	{ "btowc", (uintptr_t)&btowc },
	{ "calloc", (uintptr_t)&calloc },
	{ "ceil", (uintptr_t)&ceil },
	{ "ceilf", (uintptr_t)&ceilf },
	{ "clearerr", (uintptr_t)&clearerr },
	{ "clock", (uintptr_t)&clock },
	{ "clock_gettime", (uintptr_t)&clock_gettime },
	{ "close", (uintptr_t)&close },
	{ "cos", (uintptr_t)&cos },
	{ "cosf", (uintptr_t)&cosf },
	{ "cosh", (uintptr_t)&cosh },
	{ "crc32", (uintptr_t)&crc32 },
	{ "difftime", (uintptr_t)&difftime },
	{ "div", (uintptr_t)&div },
	{ "dlopen", (uintptr_t)&ret0 },
	{ "exit", (uintptr_t)&exit },
	{ "exp", (uintptr_t)&exp },
	{ "exp2f", (uintptr_t)&exp2f },
	{ "expf", (uintptr_t)&expf },
	{ "fclose", (uintptr_t)&fclose },
	{ "fcntl", (uintptr_t)&ret0 },
	{ "fdopen", (uintptr_t)&fdopen_hook },
	{ "ferror", (uintptr_t)&ferror },
	{ "fflush", (uintptr_t)&fflush },
	{ "fgets", (uintptr_t)&fgets },
	{ "floor", (uintptr_t)&floor },
	{ "floorf", (uintptr_t)&floorf },
	{ "fmod", (uintptr_t)&fmod },
	{ "fmodf", (uintptr_t)&fmodf },
	{ "fopen", (uintptr_t)&fopen_hook },
	{ "fprintf", (uintptr_t)&fprintf },
	{ "fputc", (uintptr_t)&fputc },
	{ "fputs", (uintptr_t)&fputs },
	{ "fread", (uintptr_t)&fread },
	{ "free", (uintptr_t)&free },
	{ "frexp", (uintptr_t)&frexp },
	{ "frexpf", (uintptr_t)&frexpf },
	{ "fscanf", (uintptr_t)&fscanf },
	{ "fseek", (uintptr_t)&fseek },
	{ "fstat", (uintptr_t)&fstat_hook },
	{ "fgetpos", (uintptr_t)&fgetpos },
	{ "ftell", (uintptr_t)&ftell },
	{ "fwrite", (uintptr_t)&fwrite },
	{ "getc", (uintptr_t)&getc },
	{ "gettid", (uintptr_t)&gettid },
	{ "getenv", (uintptr_t)&ret0 },
	{ "getwc", (uintptr_t)&getwc },
	{ "gettimeofday", (uintptr_t)&gettimeofday },
	{ "glVertexAttribPointer", (uintptr_t)&glVertexAttribPointer },
	{ "glEnableVertexAttribArray", (uintptr_t)&glEnableVertexAttribArray },
	{ "glAlphaFunc", (uintptr_t)&glAlphaFunc },
	{ "glBindBuffer", (uintptr_t)&glBindBuffer },
	{ "glBindTexture", (uintptr_t)&glBindTexture },
	{ "glBlendFunc", (uintptr_t)&glBlendFunc },
	{ "glBufferData", (uintptr_t)&glBufferData },
	{ "glClear", (uintptr_t)&glClear },
	{ "glClearColor", (uintptr_t)&glClearColor },
	{ "glClearDepthf", (uintptr_t)&glClearDepthf },
	{ "glColorPointer", (uintptr_t)&glColorPointer },
	{ "glCompressedTexImage2D", (uintptr_t)&glCompressedTexImage2D },
	{ "glDeleteBuffers", (uintptr_t)&glDeleteBuffers },
	{ "glDeleteTextures", (uintptr_t)&glDeleteTextures },
	{ "glDepthFunc", (uintptr_t)&glDepthFunc },
	{ "glDepthMask", (uintptr_t)&glDepthMask },
	{ "glDisable", (uintptr_t)&glDisable },
	{ "glDrawElements", (uintptr_t)&glDrawElements },
	{ "glEnable", (uintptr_t)&glEnable },
	{ "glEnableClientState", (uintptr_t)&glEnableClientState },
	{ "glGenBuffers", (uintptr_t)&glGenBuffers },
	{ "glGenTextures", (uintptr_t)&glGenTextures },
	{ "glGetError", (uintptr_t)&ret0 },
	{ "glLoadIdentity", (uintptr_t)&glLoadIdentity },
	{ "glMatrixMode", (uintptr_t)&glMatrixMode },
	{ "glMultMatrixx", (uintptr_t)&glMultMatrixx },
	{ "glOrthof", (uintptr_t)&glOrthof },
	{ "glPixelStorei", (uintptr_t)&ret0 },
	{ "glPopMatrix", (uintptr_t)&glPopMatrix },
	{ "glScissor", (uintptr_t)&glScissor },
	{ "glPushMatrix", (uintptr_t)&glPushMatrix },
	{ "glTexCoordPointer", (uintptr_t)&glTexCoordPointer },
	{ "glTexImage2D", (uintptr_t)&glTexImage2D },
	{ "glTexParameteri", (uintptr_t)&glTexParameteri },
	{ "glTexSubImage2D", (uintptr_t)&glTexSubImage2D },
	{ "glTranslatex", (uintptr_t)&glTranslatex },
	{ "glVertexPointer", (uintptr_t)&glVertexPointer },
	{ "glViewport", (uintptr_t)&glViewport },
	{ "gmtime", (uintptr_t)&gmtime },
	{ "gzopen", (uintptr_t)&ret0 },
	{ "inflate", (uintptr_t)&inflate },
	{ "inflateEnd", (uintptr_t)&inflateEnd },
	{ "inflateInit_", (uintptr_t)&inflateInit_ },
	{ "inflateReset", (uintptr_t)&inflateReset },
	{ "isalnum", (uintptr_t)&isalnum },
	{ "isalpha", (uintptr_t)&isalpha },
	{ "iscntrl", (uintptr_t)&iscntrl },
	{ "islower", (uintptr_t)&islower },
	{ "ispunct", (uintptr_t)&ispunct },
	{ "isprint", (uintptr_t)&isprint },
	{ "isspace", (uintptr_t)&isspace },
	{ "isupper", (uintptr_t)&isupper },
	{ "iswalpha", (uintptr_t)&iswalpha },
	{ "iswcntrl", (uintptr_t)&iswcntrl },
	{ "iswctype", (uintptr_t)&iswctype },
	{ "iswdigit", (uintptr_t)&iswdigit },
	{ "iswdigit", (uintptr_t)&iswdigit },
	{ "iswlower", (uintptr_t)&iswlower },
	{ "iswprint", (uintptr_t)&iswprint },
	{ "iswpunct", (uintptr_t)&iswpunct },
	{ "iswspace", (uintptr_t)&iswspace },
	{ "iswupper", (uintptr_t)&iswupper },
	{ "iswxdigit", (uintptr_t)&iswxdigit },
	{ "isxdigit", (uintptr_t)&isxdigit },
	{ "ldexp", (uintptr_t)&ldexp },
	// { "listen", (uintptr_t)&listen },
	{ "localtime", (uintptr_t)&localtime },
	{ "localtime_r", (uintptr_t)&localtime_r },
	{ "log", (uintptr_t)&log },
	{ "log10", (uintptr_t)&log10 },
	{ "logf", (uintptr_t)&logf },
	{ "log10f", (uintptr_t)&log10f },
	{ "longjmp", (uintptr_t)&longjmp },
	{ "lrand48", (uintptr_t)&lrand48 },
	{ "lrint", (uintptr_t)&lrint },
	{ "lrintf", (uintptr_t)&lrintf },
	{ "lseek", (uintptr_t)&lseek },
	{ "malloc", (uintptr_t)&malloc },
	{ "mbrtowc", (uintptr_t)&mbrtowc },
	{ "memalign", (uintptr_t)&memalign },
	{ "memchr", (uintptr_t)&sceClibMemchr },
	{ "memcmp", (uintptr_t)&memcmp },
	{ "memcpy", (uintptr_t)&sceClibMemcpy },
	{ "memmove", (uintptr_t)&sceClibMemmove },
	{ "memset", (uintptr_t)&sceClibMemset },
	{ "mkdir", (uintptr_t)&mkdir },
	{ "mktime", (uintptr_t)&mktime },
	{ "mmap", (uintptr_t)&mmap},
	{ "munmap", (uintptr_t)&munmap},
	{ "modf", (uintptr_t)&modf },
	// { "poll", (uintptr_t)&poll },
	{ "open", (uintptr_t)&open_hook },
	{ "pow", (uintptr_t)&pow },
	{ "powf", (uintptr_t)&powf },
	{ "printf", (uintptr_t)&printf },
	{ "puts", (uintptr_t)&puts },
	{ "pthread_attr_destroy", (uintptr_t)&ret0 },
	{ "pthread_attr_init", (uintptr_t)&ret0 },
	{ "pthread_attr_setdetachstate", (uintptr_t)&ret0 },
	{ "pthread_attr_setschedpolicy", (uintptr_t)&ret0 },
	{ "pthread_attr_setschedparam", (uintptr_t)&ret0 },
	{ "pthread_cond_init", (uintptr_t)&pthread_cond_init_fake},
	{ "pthread_cond_signal", (uintptr_t)&pthread_cond_signal_fake},
	{ "pthread_cond_broadcast", (uintptr_t)&pthread_cond_broadcast_fake},
	{ "pthread_cond_wait", (uintptr_t)&pthread_cond_wait_fake},
	{ "pthread_create", (uintptr_t)&pthread_create_fake },
	{ "pthread_getschedparam", (uintptr_t)&pthread_getschedparam },
	{ "pthread_getspecific", (uintptr_t)&pthread_getspecific },
	{ "pthread_key_create", (uintptr_t)&pthread_key_create },
	{ "pthread_key_delete", (uintptr_t)&pthread_key_delete },
	{ "pthread_mutex_destroy", (uintptr_t)&pthread_mutex_destroy_fake },
	{ "pthread_mutex_init", (uintptr_t)&pthread_mutex_init_fake },
	{ "pthread_mutex_lock", (uintptr_t)&pthread_mutex_lock_fake },
	{ "pthread_mutex_unlock", (uintptr_t)&pthread_mutex_unlock_fake },
	{ "pthread_once", (uintptr_t)&pthread_once_fake },
	{ "pthread_self", (uintptr_t)&pthread_self },
	{ "pthread_setschedparam", (uintptr_t)&pthread_setschedparam },
	{ "pthread_setspecific", (uintptr_t)&pthread_setspecific },
	{ "pthread_setname_np", (uintptr_t)&ret0 },
	{ "putc", (uintptr_t)&putc },
	{ "putwc", (uintptr_t)&putwc },
	{ "qsort", (uintptr_t)&qsort },
	{ "read", (uintptr_t)&read },
	{ "realloc", (uintptr_t)&realloc },
	{ "remove", (uintptr_t)&remove },
	{ "roundf", (uintptr_t)&roundf },
	// { "recv", (uintptr_t)&recv },
	{ "rint", (uintptr_t)&rint },
	// { "send", (uintptr_t)&send },
	// { "sendto", (uintptr_t)&sendto },
	{ "setenv", (uintptr_t)&ret0 },
	{ "setjmp", (uintptr_t)&setjmp },
	// { "setlocale", (uintptr_t)&setlocale },
	// { "setsockopt", (uintptr_t)&setsockopt },
	{ "setvbuf", (uintptr_t)&setvbuf },
	{ "sin", (uintptr_t)&sin },
	{ "sincosf", (uintptr_t)&sincosf },
	{ "sinf", (uintptr_t)&sinf },
	{ "sinh", (uintptr_t)&sinh },
	{ "snprintf", (uintptr_t)&snprintf },
	// { "socket", (uintptr_t)&socket },
	{ "sprintf", (uintptr_t)&sprintf },
	{ "sqrt", (uintptr_t)&sqrt },
	{ "sqrtf", (uintptr_t)&sqrtf },
	{ "srand48", (uintptr_t)&srand48 },
	{ "sscanf", (uintptr_t)&sscanf },
	{ "stat", (uintptr_t)&stat_hook },
	{ "strcasecmp", (uintptr_t)&strcasecmp },
	{ "strcat", (uintptr_t)&strcat },
	{ "strchr", (uintptr_t)&strchr },
	{ "strcmp", (uintptr_t)&sceClibStrcmp },
	{ "strcoll", (uintptr_t)&strcoll },
	{ "strcpy", (uintptr_t)&strcpy },
	{ "strcspn", (uintptr_t)&strcspn },
	{ "strerror", (uintptr_t)&strerror },
	{ "strftime", (uintptr_t)&strftime },
	{ "strlen", (uintptr_t)&strlen },
	{ "strncasecmp", (uintptr_t)&sceClibStrncasecmp },
	{ "strncat", (uintptr_t)&sceClibStrncat },
	{ "strncmp", (uintptr_t)&sceClibStrncmp },
	{ "strncpy", (uintptr_t)&sceClibStrncpy },
	{ "strpbrk", (uintptr_t)&strpbrk },
	{ "strrchr", (uintptr_t)&sceClibStrrchr },
	{ "strdup", (uintptr_t)&strdup },
	{ "strstr", (uintptr_t)&sceClibStrstr },
	{ "strtod", (uintptr_t)&strtod },
	{ "strtol", (uintptr_t)&strtol },
	{ "strtok", (uintptr_t)&strtok },
	{ "strtoul", (uintptr_t)&strtoul },
	{ "strxfrm", (uintptr_t)&strxfrm },
	{ "sysconf", (uintptr_t)&ret0 },
	{ "tan", (uintptr_t)&tan },
	{ "tanf", (uintptr_t)&tanf },
	{ "tanh", (uintptr_t)&tanh },
	{ "time", (uintptr_t)&time },
	{ "tolower", (uintptr_t)&tolower },
	{ "toupper", (uintptr_t)&toupper },
	{ "towlower", (uintptr_t)&towlower },
	{ "towupper", (uintptr_t)&towupper },
	{ "ungetc", (uintptr_t)&ungetc },
	{ "ungetwc", (uintptr_t)&ungetwc },
	{ "usleep", (uintptr_t)&usleep },
	{ "vfprintf", (uintptr_t)&vfprintf },
	{ "vprintf", (uintptr_t)&vprintf },
	{ "vsnprintf", (uintptr_t)&vsnprintf },
	{ "vsprintf", (uintptr_t)&vsprintf },
	{ "vswprintf", (uintptr_t)&vswprintf },
	{ "wcrtomb", (uintptr_t)&wcrtomb },
	{ "wcscoll", (uintptr_t)&wcscoll },
	{ "wcscmp", (uintptr_t)&wcscmp },
	{ "wcsncpy", (uintptr_t)&wcsncpy },
	{ "wcsftime", (uintptr_t)&wcsftime },
	{ "wcslen", (uintptr_t)&wcslen },
	{ "wcsxfrm", (uintptr_t)&wcsxfrm },
	{ "wctob", (uintptr_t)&wctob },
	{ "wctype", (uintptr_t)&wctype },
	{ "wmemchr", (uintptr_t)&wmemchr },
	{ "wmemcmp", (uintptr_t)&wmemcmp },
	{ "wmemcpy", (uintptr_t)&wmemcpy },
	{ "wmemmove", (uintptr_t)&wmemmove },
	{ "wmemset", (uintptr_t)&wmemset },
	{ "write", (uintptr_t)&write },
	// { "writev", (uintptr_t)&writev },
};

int check_kubridge(void) {
	int search_unk[2];
	return _vshKernelSearchModuleByName("kubridge", search_unk);
}

int file_exists(const char *path) {
	SceIoStat stat;
	return sceIoGetstat(path, &stat) >= 0;
}

enum MethodIDs {
	UNKNOWN = 0,
	INIT,
	GET_TOTAL_MEMORY,
	GET_FREE_MEMORY,
	GET_DATAPATH_BYTES,
	GET_STORAGEPATH_BYTES,
	GET_FONT_HEIGHT,
	ASSIGN_BACK_BUTTON,
	GET_KEY_EVENT,
	GET_LANGUAGE,
	LOAD_RAW_RESOURCE_BUFFER,
	LOAD_TEXTURE,
	IS_RESOURCE_DL_EXEC,
	IS_FILE_CHECK_EXEC,
	IS_RESOURCE_DL_SUCCESS,
	GET_FILE_CODE,
	GET_PACK_FILE_NAME,
	DRAW_FONT,
	CREATE_EDIT_TEXT,
	GET_EDIT_TEXT,
	IS_EDIT_TEXT_EXEC
} MethodIDs;

typedef struct {
	char *name;
	enum MethodIDs id;
} NameToMethodID;

typedef struct {
	unsigned char *elements;
	int size;
} jni_bytearray;

typedef struct {
	int *elements;
	int size;
} jni_intarray;

jni_bytearray *getSaveFileName() {
	char *buffer = "ux0:data/ffd";
	jni_bytearray *result = malloc(sizeof(jni_bytearray));
	result->elements = malloc(strlen(buffer) + 1);
	strcpy((char *)result->elements, buffer);
	result->size = strlen(buffer) + 1;

	return result;
}

int editText = -1;
char *editTextResult = NULL;

void create_edit_text(char *str) {
	editTextResult = NULL;
	editText = init_ime_dialog("", str);
}

char *get_edit_text() { return editTextResult; }

int is_edit_text_exec() {
	if (!editTextResult && editText != -1) {
		editTextResult = get_ime_dialog_result();
	}
	if (editTextResult) {
		editText = -1;
	}
	return editText != -1;
}

static NameToMethodID name_to_method_ids[] = {
	{ "<init>", INIT },
	{ "getTotalMemory", GET_TOTAL_MEMORY },
	{ "getFreeMemory", GET_FREE_MEMORY },
	{ "getDataPathBytes", GET_DATAPATH_BYTES },
	{ "getStoragePathBytes", GET_STORAGEPATH_BYTES },
	{ "getFontHeight", GET_FONT_HEIGHT },
	{ "assignBackButton", ASSIGN_BACK_BUTTON },
	{ "getKeyEvent", GET_KEY_EVENT },
	{ "getLanguage", GET_LANGUAGE },
	{ "loadRawResourceBuffer", LOAD_RAW_RESOURCE_BUFFER },
	{ "loadTexture", LOAD_TEXTURE},
	{ "IsResourceDLExec", IS_RESOURCE_DL_EXEC},
	{ "IsFileCheckExec", IS_FILE_CHECK_EXEC},
	{ "IsResourceDLSuccess", IS_RESOURCE_DL_SUCCESS},
	{ "GetFileCode", 	GET_FILE_CODE},
	{ "getPackFileName", GET_PACK_FILE_NAME},
	{ "drawFont", DRAW_FONT},
	{ "createEditText", CREATE_EDIT_TEXT},
	{ "getEditText", GET_EDIT_TEXT},
	{ "isEditTextExec", IS_EDIT_TEXT_EXEC},
};

int GetMethodID(void *env, void *class, const char *name, const char *sig) {
	for (int i = 0; i < sizeof(name_to_method_ids) / sizeof(NameToMethodID); i++) {
		if (strcmp(name, name_to_method_ids[i].name) == 0) {
			return name_to_method_ids[i].id;
		}
	}

	//sceClibPrintf("%s\n", name);
	return UNKNOWN;
}

int GetStaticMethodID(void *env, void *class, const char *name, const char *sig) {
	for (int i = 0; i < sizeof(name_to_method_ids) / sizeof(NameToMethodID); i++) {
		if (strcmp(name, name_to_method_ids[i].name) == 0)
			return name_to_method_ids[i].id;
	}
	
	//sceClibPrintf("Static: %s\n", name);
	return UNKNOWN;
}

void CallStaticVoidMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	case CREATE_EDIT_TEXT:
		create_edit_text((char *)args[0]);
		break;
	default:
		break;
	}
}

int CallStaticBooleanMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	case IS_RESOURCE_DL_EXEC:
	case IS_FILE_CHECK_EXEC:
	case IS_RESOURCE_DL_SUCCESS:
		return 1;
	case IS_EDIT_TEXT_EXEC:
		return is_edit_text_exec();
	}
	return 0;
}

char raw_tag[8];
int get_language() {
	int lang = -1;
	sceAppUtilSystemParamGetInt(SCE_SYSTEM_PARAM_ID_LANG, &lang);
	switch (lang) {
	case SCE_SYSTEM_PARAM_LANG_JAPANESE:
		sceClibPrintf("Japanese\n");
		strcpy(raw_tag, "-ja");
		return 0;
	case SCE_SYSTEM_PARAM_LANG_FRENCH:
		sceClibPrintf("French\n");
		strcpy(raw_tag, "-fr");
		return 2;
	case SCE_SYSTEM_PARAM_LANG_GERMAN:
		sceClibPrintf("German\n");
		strcpy(raw_tag, "-de");
		return 3;
	case SCE_SYSTEM_PARAM_LANG_ITALIAN:
		sceClibPrintf("Italian\n");
		strcpy(raw_tag, "-it");
		return 4;
	case SCE_SYSTEM_PARAM_LANG_SPANISH:
		sceClibPrintf("Spanish\n");
		strcpy(raw_tag, "-es");
		return 5;
	case SCE_SYSTEM_PARAM_LANG_CHINESE_S:
		sceClibPrintf("Simplified Chinese\n");
		strcpy(raw_tag, "-zh-rCN");
		return 6;
	case SCE_SYSTEM_PARAM_LANG_CHINESE_T:
		sceClibPrintf("Traditional Chinese\n");
		strcpy(raw_tag, "-zh-rTW");
		return 7;
	case SCE_SYSTEM_PARAM_LANG_KOREAN:
		sceClibPrintf("Korean\n");
		strcpy(raw_tag, "-ko");
		return 8;
	default:
		sceClibPrintf("English\n");
		strcpy(raw_tag, "");
		return 1;
	}
}

uint8_t get_filecode() {
	uint8_t res = 0;
	char *res_key = "8162547865";
	while (*res_key) {
		res += *res_key;
		res_key++;
	}
	return res;
}

int CallStaticIntMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	case GET_FONT_HEIGHT:
		return 48;
	case GET_LANGUAGE:
		return get_language();
	case GET_FILE_CODE:
		return get_filecode();
	default:
		return 0;
	}
}

jni_bytearray *load_raw_resource_buffer(int id) {
	//sceClibPrintf("load resource %d\n", id);
	char fname[256];
	switch (id) {
	case 0:
		sprintf(fname, "ux0:data/ffd/res/raw%s/person.anmb2", raw_tag);
		break;
	case 1:
		sprintf(fname, "ux0:data/ffd/res/raw%s/r_chocobo.png", raw_tag);
		break;
	case 2:
		sprintf(fname, "ux0:data/ffd/res/raw%s/moogle.png", raw_tag);
		break;
	default:
		return NULL;
	}
	FILE *f = fopen(fname, "rb");
	if (f) {
		fseek(f, 0, SEEK_END);
		size_t sz = ftell(f);
		fseek(f, 0, SEEK_SET);
		jni_bytearray *result = malloc(sizeof(jni_bytearray));
		result->elements = malloc(sz);
		result->size = sz;
		fread(result->elements, 1, sz, f);
		return result;
		fclose(f);
	}
	return NULL;
}

#define RGBA8(r, g, b, a) \
  ((((a)&0xFF) << 24) | (((b)&0xFF) << 16) | (((g)&0xFF) << 8) | \
   (((r)&0xFF) << 0))

jni_intarray *load_texture(jni_bytearray *bArr) {
	jni_intarray *texture = malloc(sizeof(jni_intarray));

	int x, y, channels_in_file;
	unsigned char *temp = stbi_load_from_memory(bArr->elements, bArr->size, &x, &y, &channels_in_file, 4);

	texture->size = x * y + 2;
	texture->elements = malloc(texture->size * sizeof(int));
	texture->elements[0] = x;
	texture->elements[1] = y;

	for (int n = 0; n < y; n++) {
		for (int m = 0; m < x; m++) {
			unsigned char *color = (unsigned char *)&(((uint32_t *)temp)[n * x + m]);
			texture->elements[2 + n * x + m] = RGBA8(color[2], color[1], color[0], color[3]);
		}
	}

	free(temp);

	return texture;
}

stbtt_fontinfo *info = NULL;
unsigned char *fontBuffer = NULL;

void init_font() {
	long size;

	if (info != NULL)
		return;

	char font_path[256];
	switch (get_language()) {
	case 6:
	case 7:
		strcpy(font_path, "app0:/NotoSansSC-Regular.ttf");
		break;
	case 8:
		strcpy(font_path, "app0:/NotoSansKR-Regular.ttf");
		break;
	default:
		strcpy(font_path, "app0:/NotoSansJP-Regular.ttf");
		break;
	}
	FILE *fontFile = fopen(font_path, "rb");
	fseek(fontFile, 0, SEEK_END);
	size = ftell(fontFile);			 /* how long is the file ? */
	fseek(fontFile, 0, SEEK_SET); /* reset */

	fontBuffer = malloc(size);

	fread(fontBuffer, size, 1, fontFile);
	fclose(fontFile);

	info = malloc(sizeof(stbtt_fontinfo));

	/* prepare font */
	if (!stbtt_InitFont(info, fontBuffer, 0)) {
		printf("failed\n");
	}
}

static inline uint32_t utf8_decode_unsafe_2(const char *data) {
	uint32_t codepoint;
	codepoint = ((data[0] & 0x1F) << 6);
	codepoint |= (data[1] & 0x3F);
	return codepoint;
}

static inline uint32_t utf8_decode_unsafe_3(const char *data) {
	uint32_t codepoint;
	codepoint = ((data[0] & 0x0F) << 12);
	codepoint |= (data[1] & 0x3F) << 6;
	codepoint |= (data[2] & 0x3F);
	return codepoint;
}

static inline uint32_t utf8_decode_unsafe_4(const char *data) {
	uint32_t codepoint;
	codepoint = ((data[0] & 0x07) << 18);
	codepoint |= (data[1] & 0x3F) << 12;
	codepoint |= (data[2] & 0x3F) << 6;
	codepoint |= (data[3] & 0x3F);
	return codepoint;
}

jni_intarray *draw_font(char *word, int size, float fontSize, int y2) {
	init_font();

	jni_intarray *texture = malloc(sizeof(jni_intarray));
	texture->size = size * size + 2;
	texture->elements = calloc(1, texture->size * sizeof(int));

	int b_w = size; /* bitmap width */
	int b_h = size; /* bitmap height */

	/* calculate font scaling */
	float scale = stbtt_ScaleForPixelHeight(info, roundf(1.5f * fontSize));

	int ascent, descent, lineGap;
	stbtt_GetFontVMetrics(info, &ascent, &descent, &lineGap);

	int i = 0;
	while (word[i]) {
		i++;
		if (i == 4)
			break;
	}

	int codepoint;
	switch (i) {
	case 0: // This should never happen
		codepoint = 32;
		break;
	case 2:
		codepoint = utf8_decode_unsafe_2(word);
		break;
	case 3:
		codepoint = utf8_decode_unsafe_3(word);
		break;
	case 4:
		codepoint = utf8_decode_unsafe_4(word);
		break;
	default:
		codepoint = word[0];
		break;
	}

	int ax;
	int lsb;
	stbtt_GetCodepointHMetrics(info, codepoint, &ax, &lsb);

	if (codepoint == 32) {
		texture->elements[0] = roundf(ax * scale);
		return texture;
	}

	/* create a bitmap for the phrase */
	unsigned char *bitmap = calloc(b_w * b_h, sizeof(unsigned char));

	/* get bounding box for character (may be offset to account for chars that dip
	 * above or below the line) */
	int c_x1, c_y1, c_x2, c_y2;
	stbtt_GetCodepointBitmapBox(info, codepoint, scale, scale, &c_x1, &c_y1,
															&c_x2, &c_y2);

	/* compute y (different characters have different heights) */
	int y = roundf(ascent * scale) + c_y1;

	/* render character (stride and offset is important here) */
	int byteOffset = roundf(lsb * scale) + (y * b_w);

	stbtt_MakeCodepointBitmap(info, bitmap + byteOffset, c_x2 - c_x1, c_y2 - c_y1,
														b_w, scale, scale, codepoint);

	texture->elements[0] = roundf(ax * scale);
	texture->elements[1] = size;

	for (int n = 0; n < size * size; n++) {
		texture->elements[2 + n] = RGBA8(bitmap[n], bitmap[n], bitmap[n], bitmap[n]);
	}

	free(bitmap);
	return texture;
}

jni_bytearray *get_pack_filename() {
	char *buffer = "main.obb";
	jni_bytearray *result = malloc(sizeof(jni_bytearray));
	result->elements = malloc(strlen(buffer) + 1);
	strcpy((char *)result->elements, buffer);
	result->size = strlen(buffer) + 1;

	return result;
}

void *CallStaticObjectMethodV(void *env, void *obj, int methodID, va_list args) {
	switch (methodID) {
	case LOAD_RAW_RESOURCE_BUFFER:
		return load_raw_resource_buffer(va_arg(args, int));
	case LOAD_TEXTURE:
		return load_texture((jni_bytearray *)va_arg(args, char *));
	case DRAW_FONT:
		return draw_font(va_arg(args, char *), va_arg(args, int), va_arg(args, double), va_arg(args, int));
	case GET_EDIT_TEXT:
		return get_edit_text();
	case GET_PACK_FILE_NAME:
		return get_pack_filename();
	default:
		break;
	}
	return NULL;
}

uint64_t CallLongMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	return 0;
}

uint64_t CallStaticLongMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	case GET_TOTAL_MEMORY:
		return 128 * 1024 * 1024;
	case GET_FREE_MEMORY:
		return 128 * 1024 * 1024;
	default:
		break;
	}
	return 0;
}

int32_t CallIntMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		break;
	}
	return 0;
}

void *FindClass(void) {
	return (void *)0x41414141;
}

void *NewGlobalRef(void *env, char *str) {
	return (void *)0x42424242;
}

void DeleteGlobalRef(void *env, char *str) {
}

void *NewObjectV(void *env, void *clazz, int methodID, uintptr_t args) {
	return (void *)0x43434343;
}

void *GetObjectClass(void *env, void *obj) {
	return (void *)0x44444444;
}

char *NewStringUTF(void *env, char *bytes) {
	return bytes;
}

char *GetStringUTFChars(void *env, char *string, int *isCopy) {
	return string;
}

int GetJavaVM(void *env, void **vm) {
	*vm = fake_vm;
	return 0;
}

int GetFieldID(void *env, void *clazz, const char *name, const char *sig) {
	return 0;
}

int GetBooleanField(void *env, void *obj, int fieldID) {
	return 0;
}

void *CallObjectMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		return NULL;
	}
}

int CallBooleanMethodV(void *env, void *obj, int methodID, va_list args) {
	return 0;
}

void CallVoidMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		break;
	}
}

uint8_t *NewByteArray(void *env, size_t length) {
	jni_bytearray *result = malloc(sizeof(jni_bytearray));
	result->elements = malloc(length);
	result->size = length;
	return result;
}

uint8_t *SetByteArrayRegion(void *env, jni_bytearray *array, size_t start, size_t len, uint8_t *buf) {
	memcpy(array->elements, &buf[start], len);
	return array;
}

void ReleaseByteArrayElements(void *env, jni_bytearray *obj, void *elems, int mode) {
	free(obj->elements);
	free(obj);
}

void ReleaseIntArrayElements(void *env, jni_intarray *obj, void *elems, int mode) {
	free(obj->elements);
	free(obj);
}

int GetIntField(void *env, void *obj, int fieldID) { return 0; }

int *GetIntArrayElements(void *env, jni_intarray *obj, int *isCopy) {
	if (isCopy) {
		*isCopy = 0;
	}
	return obj->elements;
}

int GetArrayLength(void *env, jni_bytearray *obj) {
	return obj->size;
}

void *GetByteArrayElements(void *env, jni_bytearray *obj) {
	return obj->elements;
}

void DeleteLocalRef(void *env, void *ref) {
}

/*int crasher(unsigned int argc, void *argv) {
	uint32_t *nullptr = NULL;
	for (;;) {
		SceCtrlData pad;
		sceCtrlPeekBufferPositive(0, &pad, 1);
		if (pad.buttons & SCE_CTRL_SELECT) *nullptr = 0;
		sceKernelDelayThread(100);
	}
}*/

enum {
	TOUCH_BEGAN,
	TOUCH_MOVED,
	TOUCH_ENDED
};


void setup_2d_draw(float *bg_attributes, float x, float y, float x2, float y2) {
	glUseProgram(0);
	glDisable(GL_DEPTH_TEST);
	glDisable(GL_CULL_FACE);
	glEnable(GL_BLEND);
	glDisable(GL_ALPHA_TEST);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_TEXTURE_2D);
	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_TEXTURE_COORD_ARRAY);
	glDisableClientState(GL_COLOR_ARRAY);
	glColor4f(1, 1, 1, 1);
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrthof(0, 960, 544, 0, -1, 1);
	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
				
	bg_attributes[0] = x;
	bg_attributes[1] = y;
	bg_attributes[2] = 0.0f;
	bg_attributes[3] = x2;
	bg_attributes[4] = y;
	bg_attributes[5] = 0.0f;
	bg_attributes[6] = x;
	bg_attributes[7] = y2;
	bg_attributes[8] = 0.0f;
	bg_attributes[9] = x2;
	bg_attributes[10] = y2;
	bg_attributes[11] = 0.0f;
	vglVertexPointerMapped(3, bg_attributes);
	
	bg_attributes[12] = 0.0f;
	bg_attributes[13] = 0.0f;
	bg_attributes[14] = 1.0f;
	bg_attributes[15] = 0.0f;
	bg_attributes[16] = 0.0f;
	bg_attributes[17] = 1.0f;
	bg_attributes[18] = 1.0f;
	bg_attributes[19] = 1.0f;
	vglTexCoordPointerMapped(&bg_attributes[12]);
	
	uint16_t *bg_indices = (uint16_t*)&bg_attributes[20];
	bg_indices[0] = 0;
	bg_indices[1] = 1;
	bg_indices[2] = 2;
	bg_indices[3] = 3;
	vglIndexPointerMapped(bg_indices);
}

void *real_main(void *argv) {
	//SceUID crasher_thread = sceKernelCreateThread("crasher", crasher, 0x40, 0x1000, 0, 0, NULL);
	//sceKernelStartThread(crasher_thread, 0, NULL);	
	
	//sceSysmoduleLoadModule(SCE_SYSMODULE_RAZOR_CAPTURE);
	SceAppUtilInitParam init_param;
	SceAppUtilBootParam boot_param;
	memset(&init_param, 0, sizeof(SceAppUtilInitParam));
	memset(&boot_param, 0, sizeof(SceAppUtilBootParam));
	sceAppUtilInit(&init_param, &boot_param);
	
	sceTouchSetSamplingState(SCE_TOUCH_PORT_FRONT, SCE_TOUCH_SAMPLING_STATE_START);

	scePowerSetArmClockFrequency(444);
	scePowerSetBusClockFrequency(222);
	scePowerSetGpuClockFrequency(222);
	scePowerSetGpuXbarClockFrequency(166);

	if (check_kubridge() < 0)
		fatal_error("Error kubridge.skprx is not installed.");

	if (!file_exists("ur0:/data/libshacccg.suprx") && !file_exists("ur0:/data/external/libshacccg.suprx"))
		fatal_error("Error libshacccg.suprx is not installed.");

	if (so_file_load(&main_mod, SO_PATH, LOAD_ADDRESS) < 0)
		fatal_error("Error could not load %s.", SO_PATH);

	so_relocate(&main_mod);
	so_resolve(&main_mod, default_dynlib, sizeof(default_dynlib), 0);

	patch_game();
	so_flush_caches(&main_mod);

	so_initialize(&main_mod);
	
	vglInitExtended(0, SCREEN_W, SCREEN_H, 16 * 1024 * 1024, SCE_GXM_MULTISAMPLE_NONE);
	
	memset(fake_vm, 'A', sizeof(fake_vm));
	*(uintptr_t *)(fake_vm + 0x00) = (uintptr_t)fake_vm; // just point to itself...
	*(uintptr_t *)(fake_vm + 0x10) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_vm + 0x14) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_vm + 0x18) = (uintptr_t)GetEnv;

	memset(fake_env, 'A', sizeof(fake_env));
	*(uintptr_t *)(fake_env + 0x00) = (uintptr_t)fake_env; // just point to itself...
	*(uintptr_t *)(fake_env + 0x18) = (uintptr_t)FindClass;
	*(uintptr_t *)(fake_env + 0x54) = (uintptr_t)NewGlobalRef;
	*(uintptr_t *)(fake_env + 0x58) = (uintptr_t)DeleteGlobalRef;
	*(uintptr_t *)(fake_env + 0x5C) = (uintptr_t)DeleteLocalRef;
	*(uintptr_t *)(fake_env + 0x74) = (uintptr_t)NewObjectV;
	*(uintptr_t *)(fake_env + 0x7C) = (uintptr_t)GetObjectClass;
	*(uintptr_t *)(fake_env + 0x84) = (uintptr_t)GetMethodID;
	*(uintptr_t *)(fake_env + 0x8C) = (uintptr_t)CallObjectMethodV;
	*(uintptr_t *)(fake_env + 0x98) = (uintptr_t)CallBooleanMethodV;
	*(uintptr_t *)(fake_env + 0xC8) = (uintptr_t)CallIntMethodV;
	*(uintptr_t *)(fake_env + 0xD4) = (uintptr_t)CallLongMethodV;
	*(uintptr_t *)(fake_env + 0xF8) = (uintptr_t)CallVoidMethodV;
	*(uintptr_t *)(fake_env + 0x178) = (uintptr_t)GetFieldID;
	*(uintptr_t *)(fake_env + 0x17C) = (uintptr_t)GetBooleanField;
	*(uintptr_t *)(fake_env + 0x190) = (uintptr_t)GetIntField;
	*(uintptr_t *)(fake_env + 0x1C4) = (uintptr_t)GetStaticMethodID;
	*(uintptr_t *)(fake_env + 0x1CC) = (uintptr_t)CallStaticObjectMethodV;
	*(uintptr_t *)(fake_env + 0x1D8) = (uintptr_t)CallStaticBooleanMethodV;
	*(uintptr_t *)(fake_env + 0x208) = (uintptr_t)CallStaticIntMethodV;
	*(uintptr_t *)(fake_env + 0x214) = (uintptr_t)CallStaticLongMethodV;
	*(uintptr_t *)(fake_env + 0x238) = (uintptr_t)CallStaticVoidMethodV;
	*(uintptr_t *)(fake_env + 0x29C) = (uintptr_t)NewStringUTF;
	*(uintptr_t *)(fake_env + 0x2A4) = (uintptr_t)GetStringUTFChars;
	*(uintptr_t *)(fake_env + 0x2A8) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_env + 0x2AC) = (uintptr_t)GetArrayLength;
	*(uintptr_t *)(fake_env + 0x2C0) = (uintptr_t)NewByteArray;
	*(uintptr_t *)(fake_env + 0x2E0) = (uintptr_t)GetByteArrayElements;
	*(uintptr_t *)(fake_env + 0x2EC) = (uintptr_t)GetIntArrayElements;
	*(uintptr_t *)(fake_env + 0x300) = (uintptr_t)ReleaseByteArrayElements;
	*(uintptr_t *)(fake_env + 0x30C) = (uintptr_t)ReleaseIntArrayElements;
	*(uintptr_t *)(fake_env + 0x340) = (uintptr_t)SetByteArrayRegion;
	*(uintptr_t *)(fake_env + 0x36C) = (uintptr_t)GetJavaVM;
	
	GLuint borders_tex;
	int w, h;
	uint8_t *borders_data = stbi_load("app0:borders.png", &w, &h, NULL, 4);
	glGenTextures(1, &borders_tex);
	glBindTexture(GL_TEXTURE_2D, borders_tex);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, borders_data);
	free(borders_data);
	float *bg_attributes = (float*)malloc(sizeof(float) * 44);
	
	void (* MainActivity_init)(void *env, void *obj) = (void *)so_symbol(&main_mod, "Java_com_square_1enix_android_1googleplay_ffl_1gp_MainActivity_init");
	void (* MainActivity_sizeChange)(void *env, void *obj, int w, int h) = (void *)so_symbol(&main_mod, "Java_com_square_1enix_android_1googleplay_ffl_1gp_MainActivity_sizeChange");
	void (* MainActivity_render)(void *env, void *obj) = (void *)so_symbol(&main_mod, "Java_com_square_1enix_android_1googleplay_ffl_1gp_MainActivity_render");
	void (* MainActivity_touch)(void *env, void *obj, int action, int id, float x, float y) = (void *)so_symbol(&main_mod, "Java_com_square_1enix_android_1googleplay_ffl_1gp_MainActivity_touch");
	
	MainActivity_init(fake_env, NULL);
	MainActivity_sizeChange(fake_env, NULL, SCREEN_W, SCREEN_H);
	
	SceTouchData old_touch;
	memset(&old_touch, 0, sizeof(old_touch));
	sceClibPrintf("Entering loop\n");
	uint32_t oldpad = 0;
	for (;;) {
		SceTouchData touch;
		int n, m, action = 0, i = 0;
		sceTouchPeek(SCE_TOUCH_PORT_FRONT, &touch, 1);
		
		#define fakeInput(btn, xval, yval, i) \
			if ((pad.buttons & btn) == btn) { \
				touch.report[touch.reportNum].id = i; \
				touch.report[touch.reportNum].x = xval * 2.0f; \
				touch.report[touch.reportNum].y = yval * 2.0f; \
				touch.reportNum++; \
			}
		
		SceCtrlData pad;
		sceCtrlPeekBufferPositive(0, &pad, 1);
		fakeInput(SCE_CTRL_LEFT, 78.0f, 389.0f, 5);
		fakeInput(SCE_CTRL_RIGHT, 285.0f, 389.0f, 6);
		fakeInput(SCE_CTRL_UP, 175.0f, 281.0f, 7);
		fakeInput(SCE_CTRL_DOWN, 175.0f, 490.0f, 8);
		fakeInput(SCE_CTRL_TRIANGLE, 846.0f, 37.0f, 9);
		fakeInput(SCE_CTRL_CROSS, 1.0f, 1.0f, 10);
		oldpad = pad.buttons;
		
		int report_num = touch.reportNum > 2 ? 2 : touch.reportNum;
		int old_report_num = old_touch.reportNum > 2 ? 2 : old_touch.reportNum;
		for (n = 0; n < report_num; n++) {
			action = TOUCH_BEGAN;
			for (m = 0; m < old_report_num; m++) {
				if (touch.report[n].id == old_touch.report[m].id) {
					action = TOUCH_MOVED;
					old_touch.report[m].id = 0;
					break;
				}
			}
			MainActivity_touch(fake_env, NULL, action, i,
				(float)touch.report[n].x / 1920.0f * SCREEN_W,
				(float)touch.report[n].y / 1088.0f * SCREEN_H);
			i++;
		}

		for (n = 0; n < old_report_num && i < 2; n++) {
			if (old_touch.report[n].id != 0) {
				MainActivity_touch(fake_env, NULL, TOUCH_ENDED, i,
					(float)old_touch.report[n].x / 1920.0f * SCREEN_W,
					(float)old_touch.report[n].y / 1088.0f * SCREEN_H);
				i++;
			}
		}
		
		memcpy(&old_touch, &touch, sizeof(old_touch));
		
		MainActivity_render(fake_env, NULL);
		glViewport(0, 0, SCREEN_W, SCREEN_H);
		glBindTexture(GL_TEXTURE_2D, borders_tex);
		setup_2d_draw(bg_attributes, 0.0f, 0.0f, SCREEN_W, SCREEN_H);
		vglDrawObjects(GL_TRIANGLE_STRIP, 4, GL_TRUE);
		vglSwapBuffers(is_edit_text_exec());
	}

	return NULL;
}

int main(int argc, char *argv[]) {
	pthread_t t;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 0x400000);
	pthread_create(&t, &attr, real_main, NULL);
	
	return sceKernelExitDeleteThread(0);
}
