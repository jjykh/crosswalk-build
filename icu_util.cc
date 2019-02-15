// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/i18n/icu_util.h"

#if defined(OS_WIN)
#include <windows.h>
#endif

#include <string>

#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/files/memory_mapped_file.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/strings/string_util.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/stringprintf.h"
#include "build/build_config.h"
#include "third_party/icu/source/common/unicode/putil.h"
#include "third_party/icu/source/common/unicode/udata.h"
#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
#include "third_party/icu/source/i18n/unicode/timezone.h"
#endif

#if defined(OS_ANDROID)
#include <dirent.h>
#include <dlfcn.h>
#include <android/log.h>
#include "base/android/apk_assets.h"
#endif

#if defined(OS_IOS)
#include "base/ios/ios_util.h"
#endif

#if defined(OS_MACOSX)
#include "base/mac/foundation_util.h"
#endif

namespace base {
namespace i18n {

#if ICU_UTIL_DATA_IMPL == ICU_UTIL_DATA_SHARED
#define ICU_UTIL_DATA_SYMBOL "icudt" U_ICU_VERSION_SHORT "_dat"
#if defined(OS_WIN)
#define ICU_UTIL_DATA_SHARED_MODULE_NAME "icudt.dll"
#endif
#endif

namespace {
#if !defined(OS_NACL)
#if !defined(NDEBUG)
// Assert that we are not called more than once.  Even though calling this
// function isn't harmful (ICU can handle it), being called twice probably
// indicates a programming error.
bool g_check_called_once = true;
bool g_called_once = false;
#endif  // !defined(NDEBUG)

#if ICU_UTIL_DATA_IMPL == ICU_UTIL_DATA_FILE

// To debug http://crbug.com/445616.
int g_debug_icu_last_error;
int g_debug_icu_load;
int g_debug_icu_pf_error_details;
int g_debug_icu_pf_last_error;
#if defined(OS_WIN)
wchar_t g_debug_icu_pf_filename[_MAX_PATH];
#endif  // OS_WIN
// Use an unversioned file name to simplify a icu version update down the road.
// No need to change the filename in multiple places (gyp files, windows
// build pkg configurations, etc). 'l' stands for Little Endian.
// This variable is exported through the header file.
const char kIcuDataFileName[] = "icudtl.dat";

// File handle intentionally never closed. Not using File here because its
// Windows implementation guards against two instances owning the same
// PlatformFile (which we allow since we know it is never freed).
PlatformFile g_icudtl_pf = kInvalidPlatformFile;
MemoryMappedFile* g_icudtl_mapped_file = nullptr;
MemoryMappedFile::Region g_icudtl_region;

#if defined(OS_ANDROID)
namespace {
extern "C" {
// Allowed icu4c version numbers are in the range [44, 999].
// Gingerbread's icu4c 4.4 is the minimum supported ICU version.
static constexpr auto ICUDATA_VERSION_MIN_LENGTH = 2;
static constexpr auto ICUDATA_VERSION_MAX_LENGTH = 3;
static constexpr auto ICUDATA_VERSION_MIN = 44;

static char icudata_version[ICUDATA_VERSION_MAX_LENGTH + 1];
static int  icudt_vernum = 0;
static void* uc_handle = nullptr;
static void* i18n_handle = nullptr;
static void* expat_handle = nullptr;

struct Record {
  void*       addr;
  const char* name;
};
extern Record __icu_funcs_begin[];
extern Record __icu_i18n_funcs[];
extern Record __icu_funcs_end[];

extern Record __expat_funcs[];
extern Record __ssl_funcs[];

static int __icu_dat_file_filter(const dirent* dirp) {
  const char* name = dirp->d_name;
  // Is the name the right length to match 'icudt(\d\d\d)l.dat'?
  const size_t len = strlen(name);
  if (len < 10 + ICUDATA_VERSION_MIN_LENGTH || len > 10 + ICUDATA_VERSION_MAX_LENGTH) return 0;
  return !strncmp(name, "icudt", 5) && !strncmp(&name[len - 5], "l.dat", 5);
}

extern "C" int panic(int a, int b, int c) {
  LOG(ERROR) << "xwalk-panic" << " a:" << a << " b: " << b << " c: " << c;
  __android_log_print(ANDROID_LOG_ERROR, "xwalk-panic", "a: %d, b: %d, c: %d", a, b, c);
  sleep(3);
  __android_log_print(ANDROID_LOG_ERROR, "xwalk-panic", "bye!");
  sleep(1);
  exit(0);
  return 0;
}

extern "C" void* __resolve(void **symptr, void ***PTR, int lit, void *pc) {
__android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "***\n\n %p: <%x>  __resolving... %p, [%p, %p]\n\n***", pc, lit, symptr, symptr[0], symptr[1]);
//sleep(1);
  char full_name[100];
  snprintf(full_name, sizeof(full_name), "%s%s", *(char**)(symptr + 1), icudata_version);
  void* symbol = dlsym(uc_handle, full_name);
  if (symbol == nullptr) {
      symbol = dlsym(i18n_handle, full_name);
      if (symbol == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "couldn't find %s", full_name);
        return NULL;
    }
  }
  __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "resolve %s => %p", full_name, symbol);
  *symptr = symbol;
  return symbol;
}

extern "C" void* __resolve2(const char *name) {
//__android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "***\n\n __resolving... %p\n\n***", name);
//sleep(1);
  char full_name[100];
  snprintf(full_name, sizeof(full_name), "%s%s", name, icudata_version);
  void* symbol = dlsym(uc_handle, full_name);
  if (symbol == nullptr) {
      symbol = dlsym(i18n_handle, full_name);
      if (symbol == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "couldn't find %s", full_name);
        return NULL;
    }
  }
  //__android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "resolve %s => %p", full_name, symbol);
  return symbol;
}

extern char ICU_i18n__begin;

extern "C" void* __resolve3(int id) {
  if (__icu_funcs_begin[id].addr != NULL) return __icu_funcs_begin[id].addr;

  char full_name[100];
  sprintf(full_name, "%s%s", __icu_funcs_begin[id].name, icudata_version);
  void* symbol = dlsym(id < (intptr_t)&ICU_i18n__begin ? uc_handle : i18n_handle, full_name);
  if (symbol == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "couldn't find %s", full_name);
    return NULL;
  }
  //__android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "resolve %s => %p", full_name, symbol);
  __icu_funcs_begin[id].addr = symbol;
  return symbol;
}

extern char SSL_crypto__begin;
static void* ssl_handle = nullptr;
static void* crypto_handle = nullptr;

extern "C" void* __resolve_ssl(int id) {
  void* symbol = __ssl_funcs[id].addr;
  if (symbol != NULL) return symbol;

  const char* name = __ssl_funcs[id].name;
  symbol = dlsym(RTLD_DEFAULT/*id < (intptr_t)&SSL_crypto__begin ? ssl_handle : crypto_handle*/, name);
  if (symbol == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-ssl", "couldn't find %s (id=%d)", name, id);
    return NULL;
  }
  __android_log_print(ANDROID_LOG_ERROR, "xwalk-ssl", "resolve %s => %p", name, symbol);
  __ssl_funcs[id].addr = symbol;
  return symbol;
}

extern "C" void* __resolve_expat(int id) {
  void* symbol = __expat_funcs[id].addr;
  if (symbol != NULL) return symbol;

  const char* name = __expat_funcs[id].name;
  symbol = dlsym(expat_handle, name);
  if (symbol == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-expat", "couldn't find %s", name);
    return NULL;
  }
  //__android_log_print(ANDROID_LOG_ERROR, "xwalk-expat", "resolve %s => %p", name, symbol);
  __expat_funcs[id].addr = symbol;
  return symbol;
}

#define UNormalizationMode int
extern "C" {
extern int32_t (*Fx_unorm_normalize)(const UChar *src, int32_t srcLength,
                UNormalizationMode mode, int32_t options,
                UChar *dest, int32_t destCapacity,
                UErrorCode *pErrorCode);
int32_t
unorm_normalize__(const UChar *src, int32_t srcLength,
                UNormalizationMode mode, int32_t options,
                UChar *dest, int32_t destCapacity,
                UErrorCode *pErrorCode) {
  __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "***\n\n unorm_normalize hook...\n\n***");
  return Fx_unorm_normalize(src, srcLength, mode, options, dest, destCapacity, pErrorCode);
}
}

static bool __init_android_icu() {
  dirent** namelist = nullptr;
  int n = scandir("/system/usr/icu", &namelist, &__icu_dat_file_filter, alphasort);
  int max_version = -1;
  while (n--) {
    // We prefer the latest version available.
    int version = atoi(&namelist[n]->d_name[strlen("icudt")]);
    if (version != 0 && version > max_version) max_version = version;
    free(namelist[n]);
  }
  free(namelist);

  if (max_version < ICUDATA_VERSION_MIN) {
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "couldn't find an ICU .dat file");
    return false;
  }

  snprintf(icudata_version, sizeof(icudata_version), "_%d", max_version);
  icudt_vernum = max_version;

  uc_handle = dlopen("libicuuc.so", RTLD_LAZY);
  if (uc_handle == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "couldn't open libicuuc.so: %s",
                          dlerror());
    return false;
  }
  i18n_handle = dlopen("libicui18n.so", RTLD_LAZY);
  if (i18n_handle == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "couldn't open libicui18n.so: %s",
                          dlerror());
    return false;
  }

  /*char full_name[100];
  for (Record *r = __icu_funcs_begin; r < __icu_funcs_end; r++) {
    snprintf(full_name, sizeof(full_name), "%s%s", r->name, icudata_version);

    void* symbol = dlsym(r >= __icu_i18n_funcs ? i18n_handle : uc_handle, full_name);
    if (symbol == nullptr) {
      __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "couldn't find %s", full_name);
      //return false;
    }
    r->addr = symbol;
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-icu", "<%d> ...found %s => %p  @[%p]", (int)(r - __icu_funcs_begin), r->name, symbol, &r->addr);
  }*/
#if 0
  for (Record *r = __ssl_funcs; r->name != NULL; r++) {
    int id = (int)(r - __ssl_funcs);
    void* symbol = dlsym(/*id < (intptr_t)&SSL_crypto__begin ? ssl_handle : crypto_handle*/RTLD_DEFAULT, r->name);
    if (symbol == nullptr) {
      __android_log_print(ANDROID_LOG_ERROR, "xwalk-ssl", "couldn't find %s", r->name);
      //return false;
    }
    r->addr = symbol;
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-ssl", "<%d> ...found %s => %p  @[%p]", id, r->name, symbol, &r->addr);
  }
#endif
  return true;
}
}
}
#endif

void LazyInitIcuDataFile() {
  if (g_icudtl_pf != kInvalidPlatformFile) {
    return;
  }
#if !defined(OS_MACOSX)
  FilePath data_path;
#if defined(OS_WIN)
  // The data file will be in the same directory as the current module.
  bool path_ok = PathService::Get(DIR_MODULE, &data_path);
  wchar_t tmp_buffer[_MAX_PATH] = {0};
  wcscpy_s(tmp_buffer, data_path.value().c_str());
  debug::Alias(tmp_buffer);
  CHECK(path_ok);  // TODO(scottmg): http://crbug.com/445616
#elif defined(OS_ANDROID)
  /**/
#else
  // For now, expect the data file to be alongside the executable.
  // This is sufficient while we work on unit tests, but will eventually
  // likely live in a data directory.
  bool path_ok = PathService::Get(DIR_EXE, &data_path);
#endif

#if defined(OS_ANDROID)
  char buf[128];
  sprintf(buf, "/system/usr/icu/icudt%dl.dat", icudt_vernum);
  data_path = data_path.AppendASCII(buf);
#else
  DCHECK(path_ok);
  data_path = data_path.AppendASCII(kIcuDataFileName);
#endif

#if defined(OS_WIN)
  // TODO(scottmg): http://crbug.com/445616
  wchar_t tmp_buffer2[_MAX_PATH] = {0};
  wcscpy_s(tmp_buffer2, data_path.value().c_str());
  debug::Alias(tmp_buffer2);
#endif

#else
  // Assume it is in the framework bundle's Resources directory.
  ScopedCFTypeRef<CFStringRef> data_file_name(
      SysUTF8ToCFStringRef(kIcuDataFileName));
  FilePath data_path = mac::PathForFrameworkBundleResource(data_file_name);
#if defined(OS_IOS)
  FilePath override_data_path = base::ios::FilePathOfEmbeddedICU();
  if (!override_data_path.empty()) {
    data_path = override_data_path;
  }
#endif  // !defined(OS_IOS)
  if (data_path.empty()) {
    LOG(ERROR) << kIcuDataFileName << " not found in bundle";
    return;
  }
#endif  // !defined(OS_MACOSX)
  File file(data_path, File::FLAG_OPEN | File::FLAG_READ);
  if (file.IsValid()) {
    // TODO(scottmg): http://crbug.com/445616.
    g_debug_icu_pf_last_error = 0;
    g_debug_icu_pf_error_details = 0;
#if defined(OS_WIN)
    g_debug_icu_pf_filename[0] = 0;
#endif  // OS_WIN

    g_icudtl_pf = file.TakePlatformFile();
    g_icudtl_region = MemoryMappedFile::Region::kWholeFile;
  }
#if defined(OS_WIN)
  else {
    // TODO(scottmg): http://crbug.com/445616.
    g_debug_icu_pf_last_error = ::GetLastError();
    g_debug_icu_pf_error_details = file.error_details();
    wcscpy_s(g_debug_icu_pf_filename, data_path.value().c_str());
  }
#endif  // OS_WIN
}

typedef void** (*getSingletonF)();

bool InitializeICUWithFileDescriptorInternal(
    PlatformFile data_fd,
    const MemoryMappedFile::Region& data_region) {
  // This can be called multiple times in tests.
  if (g_icudtl_mapped_file) {
    g_debug_icu_load = 0;  // To debug http://crbug.com/445616.
    return true;
  }
  if (data_fd == kInvalidPlatformFile) {
    g_debug_icu_load = 1;  // To debug http://crbug.com/445616.
    LOG(ERROR) << "Invalid file descriptor to ICU data received.";
    return false;
  }

  std::unique_ptr<MemoryMappedFile> icudtl_mapped_file(new MemoryMappedFile());
  if (!icudtl_mapped_file->Initialize(File(data_fd), data_region)) {
    g_debug_icu_load = 2;  // To debug http://crbug.com/445616.
    LOG(ERROR) << "Couldn't mmap icu data file";
    return false;
  }
  g_icudtl_mapped_file = icudtl_mapped_file.release();

  UErrorCode err = U_ZERO_ERROR;
  udata_setCommonData(const_cast<uint8_t*>(g_icudtl_mapped_file->data()), &err);
  
  if (err != U_ZERO_ERROR) {
    g_debug_icu_load = 3;  // To debug http://crbug.com/445616.
    g_debug_icu_last_error = err;
  }
  return err == U_ZERO_ERROR;
}
#endif  // ICU_UTIL_DATA_IMPL == ICU_UTIL_DATA_FILE
#endif  // !defined(OS_NACL)

}  // namespace

#if !defined(OS_NACL)
#if ICU_UTIL_DATA_IMPL == ICU_UTIL_DATA_FILE
#if defined(OS_ANDROID)
bool InitializeICUWithFileDescriptor(
    PlatformFile data_fd,
    const MemoryMappedFile::Region& data_region) {
#if !defined(NDEBUG)
  DCHECK(!g_check_called_once || !g_called_once);
  g_called_once = true;
#endif
  return InitializeICUWithFileDescriptorInternal(data_fd, data_region);
}

PlatformFile GetIcuDataFileHandle(MemoryMappedFile::Region* out_region) {
  CHECK_NE(g_icudtl_pf, kInvalidPlatformFile);
  *out_region = g_icudtl_region;
  return g_icudtl_pf;
}
#endif

const uint8_t* GetRawIcuMemory() {
  CHECK(g_icudtl_mapped_file);
  return g_icudtl_mapped_file->data();
}

bool InitializeICUFromRawMemory(const uint8_t* raw_memory) {
#if !defined(COMPONENT_BUILD)
#if !defined(NDEBUG)
  DCHECK(!g_check_called_once || !g_called_once);
  g_called_once = true;
#endif

  UErrorCode err = U_ZERO_ERROR;
  udata_setCommonData(const_cast<uint8_t*>(raw_memory), &err);
  return err == U_ZERO_ERROR;
#else
  return true;
#endif
}

#endif  // ICU_UTIL_DATA_IMPL == ICU_UTIL_DATA_FILE

#define ANDROID_DLEXT_USE_NAMESPACE 0x200
#define ANDROID_NAMESPACE_TYPE_ISOLATED 1
#define ANDROID_NAMESPACE_TYPE_SHARED 2

typedef struct {
  uint64_t flags;
  void*   reserved_addr;
  size_t  reserved_size;
  int     relro_fd;
  int     library_fd;
  off64_t library_fd_offset;
  struct android_namespace_t* library_namespace;
} android_dlextinfo;

typedef void* (*android_dlopen_extF)(const char* filename, int flag, const android_dlextinfo* extinfo);
typedef struct android_namespace_t* (*android_create_namespaceF)(const char* name,
                                                            const char* ld_library_path,
                                                            const char* default_library_path,
                                                            uint64_t type,
                                                            const char* permitted_when_isolated_path,
                                                            struct android_namespace_t* parent);

static void *libdl = nullptr;
static android_dlopen_extF android_dlopen_ext = nullptr;
static android_create_namespaceF android_create_namespace = nullptr;
static struct android_namespace_t *ns = nullptr;

void *my_dlopen(const char *path, int flags) {
  if (!libdl) {
    libdl = dlopen("libdl.so", RTLD_NOW);
    android_dlopen_ext = (android_dlopen_extF) dlsym(libdl, "android_dlopen_ext");
    android_create_namespace = (android_create_namespaceF) dlsym(libdl, "android_create_namespace");
    if (android_create_namespace) {
      const char *lib_path = "/system/lib/";
      ns = android_create_namespace(
        "trustme",
        lib_path,
        lib_path,
        ANDROID_NAMESPACE_TYPE_SHARED |
        ANDROID_NAMESPACE_TYPE_ISOLATED,
        "/system/:/data/:/vendor/",
        NULL);
    }
  }
  if (ns) {
    const android_dlextinfo dlext = {
      ANDROID_DLEXT_USE_NAMESPACE,
      nullptr, 0, 0, 0, 0,
      ns,
    };
    return android_dlopen_ext(path, RTLD_NOW | RTLD_LOCAL, &dlext);
  }
  else {
    return dlopen(path, flags);
  }
}

extern "C" {
void* g_libsqlite = nullptr; 
}

bool InitializeICU() {
#if !defined(NDEBUG)
  DCHECK(!g_check_called_once || !g_called_once);
  g_called_once = true;
#endif

#if defined(OS_ANDROID)
  expat_handle = my_dlopen("libexpat.so", RTLD_LAZY);

  crypto_handle = my_dlopen("libcrypto.so", RTLD_LAZY);
  ssl_handle = my_dlopen("libssl.so", RTLD_LAZY);

  g_libsqlite = my_dlopen("libsqlite.so", RTLD_LAZY);
  if (!g_libsqlite) {
    __android_log_print(ANDROID_LOG_ERROR, "xwalk-sqlite", "couldn't open libsqlite.so: %s", dlerror());
    exit(-1);
  }

  if (!__init_android_icu()) {
    LOG(ERROR) << "android icu not found.";
    return false;
  }
#endif

  bool result;
#if (ICU_UTIL_DATA_IMPL == ICU_UTIL_DATA_SHARED)
  // We expect to find the ICU data module alongside the current module.
  FilePath data_path;
  PathService::Get(DIR_MODULE, &data_path);
  data_path = data_path.AppendASCII(ICU_UTIL_DATA_SHARED_MODULE_NAME);

  HMODULE module = LoadLibrary(data_path.value().c_str());
  if (!module) {
    LOG(ERROR) << "Failed to load " << ICU_UTIL_DATA_SHARED_MODULE_NAME;
    return false;
  }

  FARPROC addr = GetProcAddress(module, ICU_UTIL_DATA_SYMBOL);
  if (!addr) {
    LOG(ERROR) << ICU_UTIL_DATA_SYMBOL << ": not found in "
               << ICU_UTIL_DATA_SHARED_MODULE_NAME;
    return false;
  }

  UErrorCode err = U_ZERO_ERROR;
  udata_setCommonData(reinterpret_cast<void*>(addr), &err);
  result = (err == U_ZERO_ERROR);
#elif (ICU_UTIL_DATA_IMPL == ICU_UTIL_DATA_STATIC)
  // The ICU data is statically linked.
  result = true;
#elif (ICU_UTIL_DATA_IMPL == ICU_UTIL_DATA_FILE)
  // If the ICU data directory is set, ICU won't actually load the data until
  // it is needed.  This can fail if the process is sandboxed at that time.
  // Instead, we map the file in and hand off the data so the sandbox won't
  // cause any problems.
  LazyInitIcuDataFile();
  result =
      InitializeICUWithFileDescriptorInternal(g_icudtl_pf, g_icudtl_region);
#if defined(OS_WIN)
  int debug_icu_load = g_debug_icu_load;
  debug::Alias(&debug_icu_load);
  int debug_icu_last_error = g_debug_icu_last_error;
  debug::Alias(&debug_icu_last_error);
  int debug_icu_pf_last_error = g_debug_icu_pf_last_error;
  debug::Alias(&debug_icu_pf_last_error);
  int debug_icu_pf_error_details = g_debug_icu_pf_error_details;
  debug::Alias(&debug_icu_pf_error_details);
  wchar_t debug_icu_pf_filename[_MAX_PATH] = {0};
  wcscpy_s(debug_icu_pf_filename, g_debug_icu_pf_filename);
  debug::Alias(&debug_icu_pf_filename);
  CHECK(result);  // TODO(scottmg): http://crbug.com/445616
#endif
#endif

// To respond to the timezone change properly, the default timezone
// cache in ICU has to be populated on starting up.
// TODO(jungshik): Some callers do not care about tz at all. If necessary,
// add a boolean argument to this function to init'd the default tz only
// when requested.
#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
  if (result)
    std::unique_ptr<icu::TimeZone> zone(icu::TimeZone::createDefault());
#endif

  return result;
}
#endif  // !defined(OS_NACL)

void AllowMultipleInitializeCallsForTesting() {
#if !defined(NDEBUG) && !defined(OS_NACL)
  g_check_called_once = false;
#endif
}

}  // namespace i18n
}  // namespace base
