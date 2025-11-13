#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

/// Opaque C handle
struct VerdantServiceHandle {
  VerdantService *inner;
};

/// A simple FFI-safe event result. `payload` is a JSON string whose ownership is transferred
/// to the caller. The caller must call `verdant_free_cstring(payload)` when done.
struct VerdantEventFFI {
  uint32_t tag;
  char *payload;
};

struct RuntimeHandle {
  void *ptr;
};

extern "C" {

/// Create a new VerdantService.
/// - `start_discovery`: if non-zero, discovery is enabled
/// - `rt_ptr`: optional pointer to a tokio::runtime::Runtime (if you have one).
///      If null, a new Runtime will be created internally.
/// Returns a pointer to `VerdantServiceHandle` (null on failure).
VerdantServiceHandle *verdant_service_new(int start_discovery, Runtime *rt_ptr);

/// Free the service and all associated resources. Safe to call with null.
void verdant_service_free(VerdantServiceHandle *h);

/// Send a login command. Returns 0 on success, non-zero on failure (e.g., bad args or send error).
int verdant_service_login(VerdantServiceHandle *h,
                          const char *url,
                          const char *username,
                          const char *password);

/// Try to receive an UI event without blocking. Returns a VerdantEventFFIby value.
/// If no event is available, returns an event with tag = None and payload = NULL.
/// Caller is responsible for freeing `payload` if non-null by calling `verdant_free_cstring`.
VerdantEventFFI verdant_service_try_recv(VerdantServiceHandle *h);

/// Free a C string returned by the above APIs (or any CString you create via `into_raw()`).
void verdant_free_cstring(char *s);

/// Create a new Tokio runtime and return a raw pointer to it.
/// Returns NULL on failure. Caller must later call `verdant_runtime_free()`.
RuntimeHandle verdant_runtime_new();

/// Free a Tokio runtime created with `verdant_runtime_new()`.
/// Safe to call with NULL.
void verdant_runtime_free(RuntimeHandle *rt);

}  // extern "C"
