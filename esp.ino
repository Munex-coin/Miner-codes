// ======= Config for user =======
#define WIFI_SSID              "NOKIA-5D71"
#define WIFI_PASSWORD          "zkDAej8QuW"

#define MCX_NODE_HOST          "192.168.88.4"
#define MCX_NODE_PORT          8080
#define MCX_PRIVKEY_HEX        ""
#define MCX_WALLET_OVERRIDE    ""
#define MCX_MINER_ID_OVERRIDE  ""
#define MCX_CHAIN_ID           6620

#define WDT_TIMEOUT_S                 30
#define WIFI_CONNECT_TIMEOUT_MS       20000
#define WIFI_MAX_BACKOFF_MS           60000
#define WS_RECONNECT_MIN_MS           3000
#define WS_RECONNECT_MAX_MS           60000
#define WS_SILENCE_TIMEOUT_MS         120000
#define REGISTER_TIMEOUT_MS           35000
#define MOVE_ACK_TIMEOUT_MS           12000
#define MAZE_STATE_TIMEOUT_MS         10000
#define POW_ACK_TIMEOUT_MS            12000
#define POW_MAX_SOLVE_MS              45000
#define MAZE_WAIT_TIMEOUT_MS          90000
#define UPTIME_PING_INTERVAL_MS       10000
#define NTP_MAX_WAIT_MS               180000
#define MIN_FREE_HEAP                 40000
#define MAX_MEM_CHALLENGE_BYTES       (64u * 1024u * 1024u)
#define MAX_CONSECUTIVE_FAILS         5

#define MOVE_PACING_MS                150
#define MAX_MAZE_DIM                  24
#define NO_PATH_RESYNC_LIMIT          3
#define AI_EPS_START                  0.20f
#define AI_EPS_MIN                    0.05f
#define AI_EPS_DECAY                  0.999f
#define AI_LEARNING_RATE              0.08f
#define AI_GAMMA                      0.90f
#define AI_R_REWARD_STEP              1.0f
#define AI_R_GOAL                     10.0f
#define AI_R_WALL                     (-2.0f)
#define AI_R_REJECT                   (-1.0f)
#define AI_R_GHOST                    (-5.0f)

#define AI_USE_LLM                    1
#define AI_LLM_INT8                   1
#define AI_MODEL_FS_PATH              "/mcx_model.bin"
#define AI_TOKENIZER_FS_PATH          "/mcx_tok.bin"
#define AI_LLM_PROMPT                 "Munex maze. Choose one direction east west north south up down. Next move:"
// ======= End user config =======

// Forward declarations needed by Arduino's automatic prototype generation
// after consolidating helper headers into this single sketch file.
#include <stdint.h>
#include <stddef.h>
struct Mj;
struct MjKV;
struct Arena;
struct MjParser;
struct OutBuf;
enum MjType : uint8_t;
struct Cfg;
struct QT;
struct Model;
struct Scratch;
struct BpeTokenizer;

#if !defined(ARDUINO_ARCH_ESP32)
#error "esp_miner.ino targets ESP32 / ESP32-S3 boards."
#endif

#include <Arduino.h>
#include <stdarg.h>
#include <stdlib.h>
#include <Preferences.h>
#include <WiFi.h>
// ArduinoJson v6/v7 compatibility is handled at document construction: v6
// uses DynamicJsonDocument(capacity), v7 uses JsonDocument.
// Application-side JSON cap. This does NOT override the receive limit in the
// separately compiled Links2004 WebSockets library. Its common ESP32 release
// defines WEBSOCKETS_MAX_DATA_SIZE as 15 KiB in WebSockets.h and enforces it in
// WebSockets.cpp. A MAX_MAZE_DIM=24 dense maze can exceed that limit. For 24^3
// frames, increase the limit in the installed library source and rebuild the
// library; a sketch-local #define cannot safely change its compiled .cpp.
#define MCX_MAX_JSON_BYTES (96u * 1024u)
#include <WebSocketsClient.h>
#if defined(WEBSOCKETS_MAX_DATA_SIZE) && WEBSOCKETS_MAX_DATA_SIZE < (24u * 24u * 24u * 2u + 4096u)
#warning "Installed WebSockets library may reject MAX_MAZE_DIM=24 frames; see RX-cap comment above."
#endif
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <time.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/version.h>
#include <uECC.h>
#include <esp_heap_caps.h>
// The task-watchdog API exists in both Arduino-ESP32 2.x and 3.x. Include its
// header for both; only the configuration/reconfigure API is version-gated.
#include <esp_task_wdt.h>
#if defined(ESP_ARDUINO_VERSION) && ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
#include <esp_system.h>
#endif
#if __has_include(<esp_random.h>)
#include <esp_random.h>
#else
#include <esp_system.h>
#endif

// MiniJSON structures are required by the block-signing parser even when the optional
// local-language model is disabled. Keep these definitions unconditional.
enum MjType : uint8_t { MJ_NULL = 0, MJ_BOOL = 1, MJ_NUM = 2, MJ_STR = 3, MJ_ARR = 4, MJ_OBJ = 5 };

struct Mj;
struct MjKV { const char* k; uint32_t kl; Mj* v; };

struct Mj {
  uint8_t t;
  union {
    bool b;
    struct { const char* s; uint32_t len; } num;   // slice of input
    struct { char* s; uint32_t len; } str;         // decoded, arena-owned
    struct { Mj** it; uint32_t n; } arr;
    struct { MjKV* kv; uint32_t n; } obj;
  };
};

struct Arena { uint8_t* base; size_t cap; size_t used; };

struct MjParser {
  const char* p, * end;
  Arena* a;
  bool fail;
};

struct OutBuf { char* p; size_t cap; size_t len; bool fail; };


#if AI_USE_LLM
#define MCX_HAVE_LLM 1
#if AI_LLM_INT8
#define LLM_INT8_ACT 1
#endif
// --- Embedded project-local header: llm.h ---
#ifndef LLM_H
#define LLM_H
#include <stdint.h>
#include <math.h>
#include <string.h>

#define LLM_MAGIC 0x00454C50u        /* "PLE\0" */
#define LLM_FORMAT_VERSION 1u
#define LLM_FLAG_TIED_HEAD 1u        /* head is the token embedding */
#define LLM_FLAGS_KNOWN LLM_FLAG_TIED_HEAD
#define LLM_HEADER_BYTES 56u         /* version 1 */
#define LLM_HEADER_MAX 4096u         /* sanity bound on a future header */
#define LLM_MAX_LAYERS 32            /* fixed per-layer arrays below */
#define RMS_EPS 1e-6f
#define LLM_Q8_MAX_INPUT 4096


typedef struct Cfg {
  int vocab, dim, n_layers, n_heads, ffn, ple_dim, seq_len, group;
  float rope_theta;
} Cfg;

// A group-wise int4 tensor viewed in place: ragged packed nibbles (row-aligned
// to a byte) + fp16 group scales. Per-tensor group. No padding.
typedef struct QT {
  const uint8_t  *codes;   // rows*row_bytes, nibble = value+8, row_bytes=ceil(cols/2)
  const uint8_t *scales;   // rows*n_groups fp16, byte-addressed (asset is tightly packed)
  int rows, cols, group, n_groups, row_bytes;
  /* Optional int8 staging: nibbles unpacked and group scales converted once, so
   * each matvec skips both. Numerics are unchanged - same codes, same scales,
   * same group sums. NULL selects the int4 path. */
  const int8_t *w8;        // rows*cols, values -7..7
  const float  *scale8;    // rows*n_groups, half2float'd once
} QT;

// IEEE half -> float.
static inline float half2float(uint16_t h) {
  uint32_t sign = (uint32_t)(h & 0x8000) << 16;
  uint32_t exp = (h >> 10) & 0x1F, man = h & 0x3FF, f;
  if (exp == 0) {
    if (man == 0) f = sign;
    else {
      exp = 127 - 15 + 1;
      while (!(man & 0x400)) { man <<= 1; exp--; }
      man &= 0x3FF; f = sign | (exp << 23) | (man << 13);
    }
  } else if (exp == 0x1F) {
    f = sign | 0x7F800000u | (man << 13);
  } else {
    f = sign | ((exp - 15 + 127) << 23) | (man << 13);
  }
  float out; memcpy(&out, &f, 4); return out;
}

typedef struct Model {
  Cfg c;
  QT tok_emb;             // [V, D]  input embedding
  QT out_head;            // [Vout, D]; first Vout rows of tok_emb when tied
  int out_vocab;          // logits produced per step
  QT ple_model_proj;      // [L*P, D]
  const float *ple_proj_norm; // [P]
  QT ple_table;           // [V, L*P]
  const float *attn_norm[LLM_MAX_LAYERS]; // [D]
  QT qkv[LLM_MAX_LAYERS];             // [3D, D]
  QT attn_proj[LLM_MAX_LAYERS];       // [D, D]
  const float *ffn_norm[LLM_MAX_LAYERS];  // [D]
  QT gate[LLM_MAX_LAYERS], up[LLM_MAX_LAYERS], down[LLM_MAX_LAYERS];
  QT ple_gate[LLM_MAX_LAYERS];        // [P, D]
  QT ple_proj[LLM_MAX_LAYERS];        // [D, P]
  const float *ple_norm[LLM_MAX_LAYERS];  // [D]
  const float *out_norm;      // [D]
  size_t image_bytes;     // bytes consumed by the image, which is smaller than
                          // the flash partition holding it

  // Optional platform overrides; NULL uses MATVEC. Separate hooks because a
  // tied 32,768-row head and a 66-row FFN matrix have different cost profiles.
  void (*head_matvec)(const QT *, const float *, float *);
  void (*layer_matvec)(const QT *, const float *, float *);
} Model;

// Size-checked little-endian readers. Model files can be truncated or corrupt;
// never trust a tensor's dimensions or group size before checking the image end.
static uint32_t llm_rd_u32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int32_t llm_rd_i32(const uint8_t *p) { return (int32_t)llm_rd_u32(p); }
static bool llm_has_bytes(const uint8_t *p, const uint8_t *end, size_t n) {
  return p && end && p <= end && n <= (size_t)(end - p);
}
static bool llm_mul_size(size_t a, size_t b, size_t *out) {
  if (!out || (a != 0 && b > SIZE_MAX / a)) return false;
  *out = a * b;
  return true;
}
static const uint8_t *bind_q(const uint8_t *p, const uint8_t *end,
                             QT *t, int rows, int cols) {
  if (!t || rows <= 0 || cols <= 0 || !llm_has_bytes(p, end, 4)) return NULL;
  int32_t group = llm_rd_i32(p);
  p += 4;
  if (group <= 0 || group > 4096) return NULL;
  size_t n_groups = ((size_t)cols + (size_t)group - 1u) / (size_t)group;
  size_t row_bytes = ((size_t)cols + 1u) / 2u;
  size_t codes_bytes, scale_count, scales_bytes, total;
  if (!llm_mul_size((size_t)rows, row_bytes, &codes_bytes) ||
      !llm_mul_size((size_t)rows, n_groups, &scale_count) ||
      !llm_mul_size(scale_count, sizeof(uint16_t), &scales_bytes) ||
      codes_bytes > SIZE_MAX - scales_bytes) return NULL;
  total = codes_bytes + scales_bytes;
  if (!llm_has_bytes(p, end, total)) return NULL;
  t->rows = rows; t->cols = cols; t->group = group;
  t->n_groups = (int)n_groups; t->row_bytes = (int)row_bytes;
  t->codes = p; p += codes_bytes;
  t->scales = p; p += scales_bytes;
  t->w8 = NULL; t->scale8 = NULL;
  return p;
}
static const uint8_t *bind_f(const uint8_t *p, const uint8_t *end,
                             const float **t, int n) {
  size_t bytes;
  if (!t || n <= 0 || !llm_mul_size((size_t)n, sizeof(float), &bytes) ||
      !llm_has_bytes(p, end, bytes)) return NULL;
  *t = (const float *)p;
  return p + bytes;
}


// The packed model format adds no alignment padding before FP16 scale arrays.
// Read scale words via memcpy so odd-offset assets remain defined on Xtensa and
// other targets that do not permit unaligned uint16_t loads.
static inline uint16_t qt_scale_bits(const QT *t, size_t index) {
  uint16_t h = 0;
  memcpy(&h, t->scales + index * sizeof(h), sizeof(h));
  return h;
}
static inline float qt_scale_value(const QT *t, size_t index) {
  return half2float(qt_scale_bits(t, index));
}

// Dequantize row r of a quant tensor into out[cols].
static inline void deq_row(const QT *t, int r, float *out) {
  const uint8_t *row = t->codes + (size_t)r * t->row_bytes;
  for (int gi = 0; gi < t->n_groups; gi++) {
    int begin = gi * t->group;
    int end = begin + t->group;
    if (end > t->cols) end = t->cols;
    float scale = qt_scale_value(t, (size_t)r * (size_t)t->n_groups + (size_t)gi);
    int j = begin;
    if ((j & 1) && j < end) {
      out[j] = (float)((row[j >> 1] >> 4) - 8) * scale;
      j++;
    }
    for (; j + 1 < end; j += 2) {
      uint8_t byte = row[j >> 1];
      out[j] = (float)((byte & 0xF) - 8) * scale;
      out[j + 1] = (float)((byte >> 4) - 8) * scale;
    }
    if (j < end) {
      uint8_t byte = row[j >> 1];
      int code = (j & 1) ? (byte >> 4) : (byte & 0xF);
      out[j] = (float)(code - 8) * scale;
    }
  }
}

// y[row_begin:row_end] = W * x for a quant tensor W. Keeping the row range
// explicit lets platforms parallelize the large output head without changing
// any individual dot product.
static inline void matvec_q_range(const QT *t, const float *x, float *y,
                                  int row_begin, int row_end) {
  for (int r = row_begin; r < row_end; r++) {
    const uint8_t *row = t->codes + (size_t)r * t->row_bytes;
    float acc = 0.f;
    for (int gi = 0; gi < t->n_groups; gi++) {
      int begin = gi * t->group;
      int end = begin + t->group;
      if (end > t->cols) end = t->cols;
      float scale = qt_scale_value(t, (size_t)r * (size_t)t->n_groups + (size_t)gi);
      float group_acc = 0.f;
      int j = begin;
      if ((j & 1) && j < end) {
        group_acc += (float)((row[j >> 1] >> 4) - 8) * x[j];
        j++;
      }
      for (; j + 1 < end; j += 2) {
        uint8_t byte = row[j >> 1];
        group_acc += (float)((byte & 0xF) - 8) * x[j];
        group_acc += (float)((byte >> 4) - 8) * x[j + 1];
      }
      if (j < end) {
        uint8_t byte = row[j >> 1];
        int code = (j & 1) ? (byte >> 4) : (byte & 0xF);
        group_acc += (float)(code - 8) * x[j];
      }
      acc += group_acc * scale;
    }
    y[r] = acc;
  }
}

// y[rows] = W * x[cols], W a quant tensor [rows, cols].
static inline void matvec_q(const QT *t, const float *x, float *y) {
  matvec_q_range(t, x, y, 0, t->rows);
}

// ---- int8-activation path ---------------------------------------------------
// Quantize x to int8 once per call, then per output row do int8*int8 -> int32
// group dot products, scaled by (x_scale * group_scale). The only approximation
// against matvec_q is the int8 activations. Split into quantize + ranged-dot so
// a parallel caller can quantize once and let both cores read the result.
static inline void quantize_act(const float *x, int n, int8_t *xq, float *x_scale) {
  float xmax = 1e-8f;
  for (int j = 0; j < n; j++) { float a = fabsf(x[j]); if (a > xmax) xmax = a; }
  float inv = 127.f / xmax;
  for (int j = 0; j < n; j++) {
    int q = (int)lrintf(x[j] * inv);
    xq[j] = (int8_t)(q > 127 ? 127 : (q < -127 ? -127 : q));
  }
  *x_scale = xmax / 127.f;
}

static inline void matvec_q8_range(const QT *t, const int8_t *xq, float x_scale,
                            float *y, int row_begin, int row_end) {
  for (int r = row_begin; r < row_end; r++) {
    const uint8_t *row = t->codes + (size_t)r * t->row_bytes;
    float acc = 0.f;
    for (int gi = 0; gi < t->n_groups; gi++) {
      int begin = gi * t->group, end = begin + t->group;
      if (end > t->cols) end = t->cols;
      int32_t g = 0;                       // group accumulator
      for (int j = begin; j < end; j++) {
        uint8_t byte = row[j >> 1];
        int code = (j & 1) ? (byte >> 4) : (byte & 0xF);
        g += (code - 8) * (int)xq[j];
      }
      acc += (float)g * qt_scale_value(t, (size_t)r * (size_t)t->n_groups + (size_t)gi);
    }
    y[r] = acc * x_scale;
  }
}

/* Scalar int8 dot product. */
static inline int32_t llm_dot_i8(const int8_t *a, const int8_t *b, int n) {
  int32_t acc = 0;
  for (int i = 0; i < n; i++) acc += (int32_t)a[i] * (int32_t)b[i];
  return acc;
}

/* Same arithmetic as matvec_q8_range, reading pre-unpacked int8 weights.
 *
 * Keep out of line on ESP32-S3: with Arduino ESP32 3.3.10 at -O3, inlining
 * regressed inference from 95.0 to 155.2 ms/token. */
#if defined(__GNUC__)
__attribute__((noinline))
#endif
static void matvec_i8_range(const QT *t, const int8_t *xq, float x_scale,
                            float *y, int row_begin, int row_end) {
  int g = t->group, ng = t->n_groups, cols = t->cols;
  for (int r = row_begin; r < row_end; r++) {
    const int8_t *w = t->w8 + (size_t)r * cols;
    const float *sc = t->scale8 + (size_t)r * ng;
    float acc = 0.f;
    for (int gi = 0; gi < ng; gi++) {
      int begin = gi * g, end = begin + g;
      if (end > cols) end = cols;
      acc += (float)llm_dot_i8(w + begin, xq + begin, end - begin) * sc[gi];
    }
    y[r] = acc * x_scale;
  }
}

static inline void matvec_q8(const QT *t, const float *x, float *y) {
  static int8_t xq[LLM_Q8_MAX_INPUT];
  float xs;
  quantize_act(x, t->cols, xq, &xs);
  if (t->w8 != NULL) { matvec_i8_range(t, xq, xs, y, 0, t->rows); return; }
  matvec_q8_range(t, xq, xs, y, 0, t->rows);
}

// llm_forward dispatches through MATVEC so one flag flips the whole model.
#ifdef LLM_INT8_ACT
#define MATVEC matvec_q8
#else
#define MATVEC matvec_q
#endif
static inline void rmsnorm(const float *x, const float *w, int n, float *out) {
  float ss = 0.f;
  for (int i = 0; i < n; i++) ss += x[i] * x[i];
  float inv = 1.f / sqrtf(ss / n + RMS_EPS);
  if (((uintptr_t)w & (sizeof(float) - 1)) == 0) {
    for (int i = 0; i < n; i++) out[i] = w[i] * x[i] * inv;
    return;
  }
  const uint8_t *wb = (const uint8_t *)w;
  for (int i = 0; i < n; i++) {
    float wi;
    memcpy(&wi, wb + (size_t)i * sizeof(float), sizeof wi);
    out[i] = wi * x[i] * inv;
  }
}
static inline float gelu(float x) { return 0.5f * x * (1.f + erff(x * 0.70710678f)); }
static inline float silu(float x) { return x / (1.f + expf(-x)); }

// Parse header + bind every tensor only after validating its full extent.
// Returns 0 on success, negative on malformed/incompatible model data.
static int llm_load(const uint8_t *base, size_t image_len, Model *m) {
  if (!base || !m || image_len < LLM_HEADER_BYTES || sizeof(float) != 4) return -2;
  const uint8_t *end = base + image_len;
  uint32_t magic = llm_rd_u32(base + 0);
  uint32_t version = llm_rd_u32(base + 4);
  uint32_t header_bytes = llm_rd_u32(base + 8);
  uint32_t flags = llm_rd_u32(base + 12);
  if (magic != LLM_MAGIC) return -1;
  if (version == 0 || version > LLM_FORMAT_VERSION) return -3;
  if (header_bytes < LLM_HEADER_BYTES || header_bytes > LLM_HEADER_MAX ||
      header_bytes > image_len) return -2;
  if (flags & ~(uint32_t)LLM_FLAGS_KNOWN) return -3;

  const uint8_t *h = base + 16;
  uint32_t in_vocab = llm_rd_u32(h); h += 4;
  uint32_t out_vocab = llm_rd_u32(h); h += 4;
  int32_t hv[7];
  for (int i = 0; i < 7; ++i, h += 4) hv[i] = llm_rd_i32(h);
  uint32_t rope_bits = llm_rd_u32(h);
  memcpy(&m->c.rope_theta, &rope_bits, sizeof(rope_bits));

  if (in_vocab < 256 || in_vocab > 65536 || out_vocab < 1 || out_vocab > 65536)
    return -2;
  m->c.vocab = (int)in_vocab; m->out_vocab = (int)out_vocab;
  m->c.dim = hv[0]; m->c.n_layers = hv[1]; m->c.n_heads = hv[2];
  m->c.ffn = hv[3]; m->c.ple_dim = hv[4]; m->c.seq_len = hv[5]; m->c.group = hv[6];
  // Bound every dimension before it contributes to an allocation or pointer walk.
  if (m->c.dim < 1 || m->c.dim > 4096 ||
      m->c.ffn < 1 || m->c.ffn > 4096 ||
      m->c.ple_dim < 1 || m->c.ple_dim > 4096 ||
      m->c.seq_len < 2 || m->c.seq_len > 2048 ||
      m->c.group < 1 || m->c.group > 4096 ||
      m->c.n_layers < 1 || m->c.n_layers > LLM_MAX_LAYERS ||
      m->c.n_heads < 1 || m->c.n_heads > 128 ||
      m->c.dim % m->c.n_heads != 0 ||
      (m->c.dim / m->c.n_heads) % 2 != 0 ||
      !isfinite(m->c.rope_theta) || m->c.rope_theta <= 0.0f) return -2;
  if ((flags & LLM_FLAG_TIED_HEAD) && m->out_vocab > m->c.vocab) return -2;
#ifdef LLM_INT8_ACT
  if (m->c.dim > LLM_Q8_MAX_INPUT || m->c.ffn > LLM_Q8_MAX_INPUT ||
      m->c.ple_dim > LLM_Q8_MAX_INPUT) return -2;
#endif

  m->head_matvec = NULL; m->layer_matvec = NULL;
  int D = m->c.dim, L = m->c.n_layers, P = m->c.ple_dim, F = m->c.ffn, V = m->c.vocab;
  const uint8_t *p = base + header_bytes;
#define LLM_BIND_Q(dst, rows, cols) do { p = bind_q(p, end, &(dst), (rows), (cols)); if (!p) return -4; } while (0)
#define LLM_BIND_F(dst, n) do { p = bind_f(p, end, &(dst), (n)); if (!p) return -4; } while (0)
  LLM_BIND_Q(m->tok_emb, V, D);
  LLM_BIND_Q(m->ple_model_proj, L * P, D);
  LLM_BIND_F(m->ple_proj_norm, P);
  LLM_BIND_Q(m->ple_table, V, L * P);
  for (int i = 0; i < L; i++) {
    LLM_BIND_F(m->attn_norm[i], D);
    LLM_BIND_Q(m->qkv[i], 3 * D, D);
    LLM_BIND_Q(m->attn_proj[i], D, D);
    LLM_BIND_F(m->ffn_norm[i], D);
    LLM_BIND_Q(m->gate[i], F, D);
    LLM_BIND_Q(m->up[i], F, D);
    LLM_BIND_Q(m->down[i], D, F);
    LLM_BIND_Q(m->ple_gate[i], P, D);
    LLM_BIND_Q(m->ple_proj[i], D, P);
    LLM_BIND_F(m->ple_norm[i], D);
  }
  LLM_BIND_F(m->out_norm, D);
  if (flags & LLM_FLAG_TIED_HEAD) {
    m->out_head = m->tok_emb;
    m->out_head.rows = m->out_vocab;
  } else {
    LLM_BIND_Q(m->out_head, m->out_vocab, D);
  }
#undef LLM_BIND_Q
#undef LLM_BIND_F
  m->image_bytes = (size_t)(p - base);
  return 0;
}

/* ---- int8 staging -------------------------------------------------------
 * Costs 2x the bytes of the int4 form. The caller supplies the buffer, so
 * placement is the platform's choice. */
/* Byte offset of the float scale array in a staged buffer. rows*cols need not
 * be a multiple of 4, so the offset is rounded up to keep the float* aligned. */
static inline size_t llm_stage_scale_offset(const QT *t) {
  size_t w_bytes = (size_t)t->rows * t->cols * sizeof(int8_t);
  return (w_bytes + sizeof(float) - 1) & ~(size_t)(sizeof(float) - 1);
}

static inline size_t llm_stage_int8_bytes(const QT *t) {
  return llm_stage_scale_offset(t)
       + (size_t)t->rows * t->n_groups * sizeof(float);
}

static inline void llm_stage_int8(QT *t, void *buffer) {
  int8_t *w = (int8_t *)buffer;
  float *sc = (float *)((uint8_t *)buffer + llm_stage_scale_offset(t));
  for (int r = 0; r < t->rows; r++) {
#if defined(ARDUINO_ARCH_ESP32)
    // Int8 staging can visit millions of parameters on first boot. Feed the
    // loop-task watchdog periodically so optional model setup cannot reboot
    // the miner before it reaches the network loop.
    if ((r & 31) == 0) esp_task_wdt_reset();
#endif
    const uint8_t *row = t->codes + (size_t)r * t->row_bytes;
    int8_t *dst = w + (size_t)r * t->cols;
    for (int j = 0; j < t->cols; j++) {
      uint8_t byte = row[j >> 1];
      int code = (j & 1) ? (byte >> 4) : (byte & 0xF);
      dst[j] = (int8_t)(code - 8);
    }
    for (int gi = 0; gi < t->n_groups; gi++)
      sc[(size_t)r * t->n_groups + gi] =
          qt_scale_value(t, (size_t)r * (size_t)t->n_groups + (size_t)gi);
  }
  t->w8 = w;
  t->scale8 = sc;
}

/* Stage every per-position tensor, one allocation per tensor: a multi-megabyte
 * contiguous request fails on a fragmented heap even when total free is larger.
 * Returns the number staged; a tensor whose allocation fails keeps the int4
 * path. Callers requiring a guaranteed placement compare this against
 * llm_core_stage_count(). */
static inline int llm_stage_core_int8_alloc(Model *m, void *(*alloc)(size_t)) {
  int staged = 0;
  QT *tensors[7];
  void *buf = alloc(llm_stage_int8_bytes(&m->ple_model_proj));
  if (buf) { llm_stage_int8(&m->ple_model_proj, buf); ++staged; }
  for (int l = 0; l < m->c.n_layers; l++) {
    tensors[0] = &m->qkv[l];       tensors[1] = &m->attn_proj[l];
    tensors[2] = &m->gate[l];      tensors[3] = &m->up[l];
    tensors[4] = &m->down[l];      tensors[5] = &m->ple_gate[l];
    tensors[6] = &m->ple_proj[l];
    for (int i = 0; i < 7; i++) {
      void *b = alloc(llm_stage_int8_bytes(tensors[i]));
      if (b) { llm_stage_int8(tensors[i], b); ++staged; }
    }
  }
  return staged;
}

/* Number of tensors llm_stage_core_int8_alloc attempts. */
static inline int llm_core_stage_count(const Model *m) {
  return 1 + 7 * m->c.n_layers;
}

// Scratch buffers, caller-allocated (host: malloc; device: PSRAM).
typedef struct Scratch {
  float *x, *h, *qkv, *att, *g1, *g2, *ple, *tmpP, *trow, *logits;
  float *scores; // [seq_len], reused by each attention head
  float *kcache, *vcache; // [L * seq_len * D]
#ifdef LLM_PROFILE
  struct {
    uint64_t input_us, attn_us, ffn_us, ple_us, head_us;
    uint32_t calls;
  } profile;
#endif
} Scratch;

#ifdef LLM_PROFILE
static void llm_profile_reset(Scratch *s) {
  memset(&s->profile, 0, sizeof(s->profile));
}
#endif

// One decode step: token at position pos -> logits[V]. KV cache persists across calls.
/* Per-layer matvec dispatch: platform hook if set, otherwise MATVEC. */
#define LLM_LMV(m, t, x, y) \
  do { if ((m)->layer_matvec) (m)->layer_matvec((t), (x), (y)); \
       else MATVEC((t), (x), (y)); } while (0)

static void llm_forward(Model *m, int token, int pos, Scratch *s) {
  int D = m->c.dim, L = m->c.n_layers, P = m->c.ple_dim, F = m->c.ffn;
  int H = m->c.n_heads, Dh = D / H, S = m->c.seq_len;
#ifdef LLM_PROFILE
  uint64_t profile_t0 = (uint64_t)LLM_PROFILE_NOW();
#endif

  deq_row(&m->tok_emb, token, s->x);           // embedding

  // ---- per-layer input: (RMSNorm(proj(x)/sqrt(D)) + table[tok]*sqrt(P)) / sqrt(2)
  LLM_LMV(m, &m->ple_model_proj, s->x, s->tmpP); // [L*P]
  float dscale = 1.f / sqrtf((float)D);
  for (int i = 0; i < L * P; i++) s->tmpP[i] *= dscale;
  for (int l = 0; l < L; l++)
    rmsnorm(s->tmpP + l * P, m->ple_proj_norm, P, s->tmpP + l * P);
  deq_row(&m->ple_table, token, s->trow);      // [L*P]
  float sp = sqrtf((float)P), inv2 = 0.70710678f;
  for (int i = 0; i < L * P; i++)
    s->ple[i] = (s->tmpP[i] + s->trow[i] * sp) * inv2;

  // RoPE frequencies are identical across every head and layer at a position.
  // Reuse trow (dead after constructing s->ple) instead of recomputing the same
  // pow/cos/sin values L*H times.
  float *rope_c = s->trow, *rope_s = s->trow + Dh / 2;
  for (int i = 0; i < Dh / 2; i++) {
    float freq = powf(m->c.rope_theta, -2.f * i / Dh);
    rope_c[i] = cosf(pos * freq);
    rope_s[i] = sinf(pos * freq);
  }
#ifdef LLM_PROFILE
  uint64_t profile_t1 = (uint64_t)LLM_PROFILE_NOW();
  s->profile.input_us += profile_t1 - profile_t0;
#endif

  for (int l = 0; l < L; l++) {
    // ---- attention
    rmsnorm(s->x, m->attn_norm[l], D, s->h);
    LLM_LMV(m, &m->qkv[l], s->h, s->qkv);        // [3D]
    float *q = s->qkv, *k = s->qkv + D, *v = s->qkv + 2 * D;
    // split-half RoPE at position pos, per head
    for (int hh = 0; hh < H; hh++) {
      float *qh = q + hh * Dh, *kh = k + hh * Dh;
      for (int i = 0; i < Dh / 2; i++) {
        float c = rope_c[i], sn = rope_s[i];
        float q1 = qh[i], q2 = qh[i + Dh / 2];
        qh[i] = q1 * c - q2 * sn; qh[i + Dh / 2] = q2 * c + q1 * sn;
        float k1 = kh[i], k2 = kh[i + Dh / 2];
        kh[i] = k1 * c - k2 * sn; kh[i + Dh / 2] = k2 * c + k1 * sn;
      }
    }
    float *kc = s->kcache + (size_t)l * S * D, *vc = s->vcache + (size_t)l * S * D;
    memcpy(kc + (size_t)pos * D, k, D * sizeof(float));
    memcpy(vc + (size_t)pos * D, v, D * sizeof(float));
    // causal attention over 0..pos
    float scale = 1.f / sqrtf((float)Dh);
    for (int hh = 0; hh < H; hh++) {
      float *qh = q + hh * Dh;
      float *ao = s->att + hh * Dh;
      for (int i = 0; i < Dh; i++) ao[i] = 0.f;
      float maxs = -1e30f;
      // pass 1: max for stable softmax
      for (int t = 0; t <= pos; t++) {
        float *kt = kc + (size_t)t * D + hh * Dh, dot = 0.f;
        for (int i = 0; i < Dh; i++) dot += qh[i] * kt[i];
        dot *= scale;
        s->scores[t] = dot;
        if (dot > maxs) maxs = dot;
      }
      float denom = 0.f;
      for (int t = 0; t <= pos; t++) {
        float w = expf(s->scores[t] - maxs); denom += w;
        float *vt = vc + (size_t)t * D + hh * Dh;
        for (int i = 0; i < Dh; i++) ao[i] += w * vt[i];
      }
      for (int i = 0; i < Dh; i++) ao[i] /= denom;
    }
    LLM_LMV(m, &m->attn_proj[l], s->att, s->h);
    for (int i = 0; i < D; i++) s->x[i] += s->h[i];
#ifdef LLM_PROFILE
    uint64_t profile_t2 = (uint64_t)LLM_PROFILE_NOW();
    s->profile.attn_us += profile_t2 - profile_t1;
#endif

    // ---- SwiGLU FFN
    rmsnorm(s->x, m->ffn_norm[l], D, s->h);
    LLM_LMV(m, &m->gate[l], s->h, s->g1);
    LLM_LMV(m, &m->up[l], s->h, s->g2);
    for (int i = 0; i < F; i++) s->g1[i] = silu(s->g1[i]) * s->g2[i];
    LLM_LMV(m, &m->down[l], s->g1, s->h);
    for (int i = 0; i < D; i++) s->x[i] += s->h[i];
#ifdef LLM_PROFILE
    uint64_t profile_t3 = (uint64_t)LLM_PROFILE_NOW();
    s->profile.ffn_us += profile_t3 - profile_t2;
#endif

    // ---- PLE gate: x += RMSNorm(ple_proj(gelu(ple_gate(x)) * ple_l))
    LLM_LMV(m, &m->ple_gate[l], s->x, s->g2);    // [P]
    for (int i = 0; i < P; i++) s->g2[i] = gelu(s->g2[i]) * s->ple[l * P + i];
    LLM_LMV(m, &m->ple_proj[l], s->g2, s->h);    // [D]
    rmsnorm(s->h, m->ple_norm[l], D, s->h);
    for (int i = 0; i < D; i++) s->x[i] += s->h[i];
#ifdef LLM_PROFILE
    profile_t1 = (uint64_t)LLM_PROFILE_NOW();
    s->profile.ple_us += profile_t1 - profile_t3;
#endif
  }

  rmsnorm(s->x, m->out_norm, D, s->x);
  // output head: logits[v] = dot(out_head_row[v], x). out_head is tok_emb when
  // the model ties them, and a separate tensor when it does not.
  if (m->head_matvec) m->head_matvec(&m->out_head, s->x, s->logits);
  else MATVEC(&m->out_head, s->x, s->logits);
#ifdef LLM_PROFILE
  s->profile.head_us += (uint64_t)LLM_PROFILE_NOW() - profile_t1;
  s->profile.calls++;
#endif
}

#endif  // LLM_H

// --- Embedded project-local header: bpe_tokenizer.h ---
#ifndef BPE_TOKENIZER_H
#define BPE_TOKENIZER_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define BTK_FORMAT_VERSION 2
#define BTK_HEADER_BYTES 52
#define BTK_BYTE_TABLE_BYTES 512
#define BTK_MERGE_ENTRY_BYTES 6
#define BTK_MAX_INPUT_BYTES 512

/* Token ids and merge ranks are uint16 in the asset, so neither count can
 * exceed this. A corrupt header would otherwise send the binary search walking
 * past the end of the image. */
#define BTK_MAX_TABLE_ENTRIES 0x10000

/* bpe_encode_ascii failures. Negative so a caller can test for < 0 in bulk. */
#define BTK_ERR_TOO_LONG (-2)
#define BTK_ERR_NOT_ASCII (-3)
#define BTK_ERR_CAPACITY (-4)

typedef struct BpeTokenizer {
  const uint8_t *asset;
  uint32_t active_vocab;
  uint32_t merge_count;
  uint32_t merge_base;
  const uint8_t *byte_ids;
  const uint8_t *merges;
} BpeTokenizer;

static uint16_t btk_u16(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t btk_u32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Returns 0 on success, -1 on an asset this encoder cannot read.
//
// asset_size is required, not advisory: the merge count is a field of the asset
// itself, so without a length there is nothing to check it against and a
// truncated table sends btk_merge_rank reading past the end of the image.
// The generated header supplies TOKENIZER_ENCODER_ASSET_SIZE for this argument.
//
// Nothing is written to tok until every check has passed, so a rejected asset
// cannot leave a half-populated tokenizer behind.
static int bpe_tokenizer_load(
    const uint8_t *asset, size_t asset_size, BpeTokenizer *tok) {
  if (asset == NULL || tok == NULL) return -1;
  /* Enough bytes to read the header and byte table before trusting any field. */
  if (asset_size < BTK_HEADER_BYTES + BTK_BYTE_TABLE_BYTES) return -1;
  if (memcmp(asset, "BTK1", 4) != 0) return -1;
  if (btk_u32(asset + 4) != BTK_FORMAT_VERSION) return -1;

  uint32_t active_vocab = btk_u32(asset + 8);
  uint32_t merge_count = btk_u32(asset + 12);
  /* asset + 16 is reserved and deliberately not read. */
  uint32_t merge_base = btk_u32(asset + 20);

  /* The 256 single-byte symbols are always present, so the vocabulary cannot be
   * smaller than that. The upper bound is what a uint16 token id can address. */
  if (active_vocab < 256 || active_vocab > BTK_MAX_TABLE_ENTRIES) return -1;
  if (merge_count == 0 || merge_count > BTK_MAX_TABLE_ENTRIES) return -1;
  /* Rank 0 must name a real token, and rank merge_count-1 must too. Both bounds
   * matter: btk_encode_piece emits merge_base + rank as a uint16, so an id at or
   * past active_vocab is either outside the vocabulary or a wrapped value.
   * active_vocab is already capped above, so this also keeps the largest emitted
   * id, merge_base + merge_count - 1, inside uint16. */
  if (merge_base == 0 || merge_base >= active_vocab) return -1;
  if (merge_base + merge_count > active_vocab) return -1;

  /* Only now is merge_count trustworthy enough to size the table with. */
  size_t required = (size_t)BTK_HEADER_BYTES + BTK_BYTE_TABLE_BYTES +
                    (size_t)merge_count * BTK_MERGE_ENTRY_BYTES;
  if (asset_size < required) return -1;

  const uint8_t *byte_ids = asset + BTK_HEADER_BYTES;
  const uint8_t *merges = byte_ids + BTK_BYTE_TABLE_BYTES;
  for (uint32_t i = 0; i < 256; ++i)
    if (btk_u16(byte_ids + (size_t)i * 2) >= active_vocab) return -1;
  uint32_t previous_key = 0;
  for (uint32_t i = 0; i < merge_count; ++i) {
    const uint8_t *e = merges + (size_t)i * BTK_MERGE_ENTRY_BYTES;
    uint32_t key = btk_u32(e);
    uint32_t left = key >> 16, right = key & 0xFFFFu;
    uint32_t rank = btk_u16(e + 4);
    if (left >= active_vocab || right >= active_vocab || rank >= merge_count ||
        merge_base + rank >= active_vocab || (i > 0 && key <= previous_key)) return -1;
    previous_key = key;
  }
  tok->asset = asset;
  tok->active_vocab = active_vocab;
  tok->merge_count = merge_count;
  tok->merge_base = merge_base;
  tok->byte_ids = byte_ids;
  tok->merges = merges;
  return 0;
}

static uint16_t btk_byte_id(const BpeTokenizer *tok, uint8_t byte) {
  return btk_u16(tok->byte_ids + (size_t)byte * 2);
}

// Rank of the pair, or -1 if it is not a merge. Binary search: the table is
// sorted by key, and at 7000-odd entries a linear scan per adjacent pair per
// round would dominate encoding.
static int btk_merge_rank(
    const BpeTokenizer *tok, uint16_t left, uint16_t right) {
  uint32_t key = ((uint32_t)left << 16) | right;
  uint32_t lo = 0, hi = tok->merge_count;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    const uint8_t *entry = tok->merges + (size_t)mid * BTK_MERGE_ENTRY_BYTES;
    uint32_t candidate = btk_u32(entry);
    if (candidate < key) lo = mid + 1;
    else hi = mid;
  }
  if (lo == tok->merge_count) return -1;
  const uint8_t *entry = tok->merges + (size_t)lo * BTK_MERGE_ENTRY_BYTES;
  return btk_u32(entry) == key ? (int)btk_u16(entry + 4) : -1;
}

// Ranked BPE over one pre-token: repeatedly apply the lowest-ranked adjacent
// merge until none applies.
static int btk_encode_piece(
    const BpeTokenizer *tok,
    const uint8_t *piece,
    int piece_len,
    uint16_t *out,
    int out_cap) {
  if (!tok || !tok->byte_ids || !tok->merges || !piece || !out ||
      piece_len < 0 || out_cap < 0) return BTK_ERR_CAPACITY;
  if (piece_len > BTK_MAX_INPUT_BYTES || piece_len > out_cap)
    return BTK_ERR_TOO_LONG;
  int n = piece_len;
  for (int i = 0; i < n; i++) out[i] = btk_byte_id(tok, piece[i]);

  for (;;) {
    int best_rank = -1;
    uint16_t best_left = 0, best_right = 0;
    for (int i = 0; i + 1 < n; i++) {
      int rank = btk_merge_rank(tok, out[i], out[i + 1]);
      if (rank >= 0 && (best_rank < 0 || rank < best_rank)) {
        best_rank = rank;
        best_left = out[i];
        best_right = out[i + 1];
      }
    }
    if (best_rank < 0) break;

    int write = 0;
    for (int read = 0; read < n;) {
      if (read + 1 < n && out[read] == best_left &&
          out[read + 1] == best_right) {
        out[write++] = (uint16_t)(tok->merge_base + best_rank);
        read += 2;
      } else {
        out[write++] = out[read++];
      }
    }
    n = write;
  }
  return n;
}

static int btk_ascii_letter(uint8_t c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int btk_ascii_digit(uint8_t c) {
  return c >= '0' && c <= '9';
}

static int btk_ascii_space(uint8_t c) {
  return c == ' ' || c == '\t' || c == '\n' ||
         c == '\r' || c == '\f' || c == '\v';
}

static int btk_contraction_len(const uint8_t *s, int n) {
  static const char *suffixes[] = {"'s", "'t", "'re", "'ve", "'m", "'ll", "'d"};
  if (n < 2 || s[0] != '\'') return 0;
  for (unsigned i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
    int len = (int)strlen(suffixes[i]);
    if (len <= n && memcmp(s, suffixes[i], (size_t)len) == 0) return len;
  }
  return 0;
}

// Mirrors the Hugging Face ByteLevel pre-tokenizer over the supported ASCII
// domain, then applies ranked BPE independently to each pre-token. Returns the
// number of ids written, or one of the BTK_ERR_* codes.
static int bpe_encode_ascii(
    const BpeTokenizer *tok,
    const char *text,
    uint16_t *out,
    int out_cap) {
  if (!tok || !tok->byte_ids || !tok->merges || !text || !out || out_cap < 0)
    return BTK_ERR_CAPACITY;
  int len = (int)strlen(text);
  if (len > BTK_MAX_INPUT_BYTES) return BTK_ERR_TOO_LONG;
  for (int i = 0; i < len; i++)
    if ((uint8_t)text[i] >= 0x80) return BTK_ERR_NOT_ASCII;

  uint16_t piece_ids[BTK_MAX_INPUT_BYTES];
  int pos = 0, written = 0;
  while (pos < len) {
    const uint8_t *s = (const uint8_t *)text;
    int start = pos, contraction = btk_contraction_len(s + pos, len - pos);
    if (contraction) {
      pos += contraction;
    } else if (
        s[pos] == ' ' && pos + 1 < len && btk_ascii_letter(s[pos + 1])) {
      pos += 2;
      while (pos < len && btk_ascii_letter(s[pos])) pos++;
    } else if (btk_ascii_letter(s[pos])) {
      while (pos < len && btk_ascii_letter(s[pos])) pos++;
    } else if (
        s[pos] == ' ' && pos + 1 < len && btk_ascii_digit(s[pos + 1])) {
      pos += 2;
      while (pos < len && btk_ascii_digit(s[pos])) pos++;
    } else if (btk_ascii_digit(s[pos])) {
      while (pos < len && btk_ascii_digit(s[pos])) pos++;
    } else if (
        s[pos] == ' ' && pos + 1 < len && !btk_ascii_space(s[pos + 1]) &&
        !btk_ascii_letter(s[pos + 1]) && !btk_ascii_digit(s[pos + 1])) {
      pos += 2;
      while (pos < len && !btk_ascii_space(s[pos]) &&
             !btk_ascii_letter(s[pos]) && !btk_ascii_digit(s[pos])) pos++;
    } else if (!btk_ascii_space(s[pos]) && !btk_ascii_letter(s[pos]) &&
               !btk_ascii_digit(s[pos])) {
      while (pos < len && !btk_ascii_space(s[pos]) &&
             !btk_ascii_letter(s[pos]) && !btk_ascii_digit(s[pos])) pos++;
    } else {
      while (pos < len && btk_ascii_space(s[pos])) pos++;
      // Before non-whitespace, the regex leaves the last whitespace byte to be
      // consumed as the optional prefix of the next token class.
      if (pos < len && pos - start > 1) pos--;
    }

    int n = btk_encode_piece(tok, s + start, pos - start, piece_ids,
                             BTK_MAX_INPUT_BYTES);
    if (n < 0 || written + n > out_cap) return BTK_ERR_CAPACITY;
    memcpy(out + written, piece_ids, (size_t)n * sizeof(uint16_t));
    written += n;
  }
  return written;
}
#endif  // BPE_TOKENIZER_H
#endif  // AI_USE_LLM
// ======= PROTOCOL CONSTANTS =======
static const char* const kDirName[6] = { "east", "west", "north", "south", "up", "down" };
static const int8_t kDirDx[6] = {  1, -1,  0,  0,  0,  0 };
static const int8_t kDirDy[6] = {  0,  0,  1, -1,  0,  0 };
static const int8_t kDirDz[6] = {  0,  0,  0,  0,  1, -1 };

#define AWAIT_NONE        0
#define AWAIT_MOVE        1
#define AWAIT_POW         2
#define AWAIT_MAZE_STATE  3

#define PH_WIFI           0
#define PH_NTP            1
#define PH_WS             2
#define PH_REGISTER       3
#define PH_CHALLENGE      4
#define PH_WAIT_MAZE      5
#define PH_MINE           6

#define WIFI_ATTEMPT      0
#define WIFI_BACKOFF      1
#define WIFI_UP           2

#define AI_NF             22   // learner feature count
// ======= HELPERS =======
#define DUE(ts)   ((int32_t)((uint32_t)millis() - (uint32_t)(ts)) >= 0)

static void logf_(const char* tag, const char* fmt, ...) {
  char buf[384];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  Serial.printf("[%8lu][MCX-%s] %s\r\n", (unsigned long)millis(), tag, buf);
}

// ── SHA256 (mbedtls 2.x / 3.x compatible) ───────────────────────────────────
static void mcxSha256(const uint8_t* in, size_t n, uint8_t out[32]) {
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, in, n);
  mbedtls_sha256_finish(&c, out);
#else
  mbedtls_sha256_starts_ret(&c, 0);
  mbedtls_sha256_update_ret(&c, in, n);
  mbedtls_sha256_finish_ret(&c, out);
#endif
  mbedtls_sha256_free(&c);
}

static void hexEncode(const uint8_t* in, size_t n, char* out /* 2n+1 */) {
  static const char hd[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[i * 2]     = hd[in[i] >> 4];
    out[i * 2 + 1] = hd[in[i] & 0xF];
  }
  out[n * 2] = 0;
}

static int hexNib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool hexDecode(const char* hex, uint8_t* out, size_t outLen) {
  size_t n = strlen(hex);
  if (n != outLen * 2) return false;
  for (size_t i = 0; i < outLen; i++) {
    int hi = hexNib(hex[i * 2]), lo = hexNib(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

// ── keccak256 (Ethereum flavour, 0x01 padding) ──────────────────────────────
static const uint64_t kKeccakRC[24] = {
  0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
  0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
  0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
  0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
  0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
  0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
static const int kKeccakRot[24] = {
  1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
  27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};
static const int kKeccakPil[24] = {
  10, 7,  11, 17, 18, 3,  5,  16, 8,  21, 24, 4,
  15, 23, 19, 13, 12, 2,  20, 14, 22, 9,  6,  1
};

static inline uint64_t rol64(uint64_t x, int s) { return (x << s) | (x >> (64 - s)); }

static void keccakf(uint64_t st[25]) {
  for (int round = 0; round < 24; round++) {
    uint64_t bc[5];
    for (int i = 0; i < 5; i++)
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (int i = 0; i < 5; i++) {
      uint64_t t = bc[(i + 4) % 5] ^ rol64(bc[(i + 1) % 5], 1);
      for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
    }
    uint64_t t = st[1];
    for (int i = 0; i < 24; i++) {
      int j = kKeccakPil[i];
      uint64_t tmp = st[j];
      st[j] = rol64(t, kKeccakRot[i]);
      t = tmp;
    }
    for (int j = 0; j < 25; j += 5) {
      uint64_t row[5];
      for (int i = 0; i < 5; i++) row[i] = st[j + i];
      for (int i = 0; i < 5; i++)
        st[j + i] ^= (~row[(i + 1) % 5]) & row[(i + 2) % 5];
    }
    st[0] ^= kKeccakRC[round];
  }
}

static void keccak256(const uint8_t* in, size_t n, uint8_t out[32]) {
  uint64_t st[25];
  memset(st, 0, sizeof(st));
  const size_t rate = 136;
  uint8_t tmp[136];
  size_t off = 0;
  while (n - off >= rate) {
    for (size_t i = 0; i < rate; i++)
      ((uint8_t*)st)[i] ^= in[off + i];
    keccakf(st);
    off += rate;
  }
  size_t rem = n - off;
  memset(tmp, 0, rate);
  memcpy(tmp, in + off, rem);
  tmp[rem] ^= 0x01;
  tmp[rate - 1] ^= 0x80;
  for (size_t i = 0; i < rate; i++)
    ((uint8_t*)st)[i] ^= tmp[i];
  keccakf(st);
  for (size_t i = 0; i < 32; i++)
    out[i] = (uint8_t)((st[i >> 3] >> (8 * (i & 7))) & 0xFF);
}

// ── secp256k1 signing (micro-ecc) ───────────────────────────────────────────
static uint8_t gPriv[32];   // declared early: mcxSign below needs it

static int mcxUeccRng(uint8_t* dest, unsigned size) {
  for (unsigned i = 0; i < size; i++) dest[i] = (uint8_t)(esp_random() & 0xFF);
  return 1;
}

// secp256k1 n/2 (big-endian). s above this must be flipped to n-s (low-s).
static const uint8_t kSecpNHalf[32] = {
  0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
  0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0
};
// secp256k1 n (big-endian)
static const uint8_t kSecpN[32] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
  0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
  0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

static bool isHighS(const uint8_t s[32]) {
  return memcmp(s, kSecpNHalf, 32) > 0;
}

static void negateS(uint8_t s[32]) {
  // s = n - s, 256-bit big-endian borrow arithmetic.
  uint32_t borrow = 0;
  for (int i = 31; i >= 0; i--) {
    uint32_t sub = (uint32_t)kSecpN[i] - s[i] - borrow;
    s[i] = (uint8_t)(sub & 0xFF);
    borrow = (sub >> 8) & 1;
  }
}

// ECDSA(SHA256(msg)) -> 128 lowercase hex (r||s, low-s) — matches sign_bytes().
static bool mcxSign(const uint8_t* msg, size_t len, char outHex[129]) {
  uint8_t h[32], sig[64];
  mcxSha256(msg, len, h);
  if (!uECC_sign(gPriv, h, 32, sig, uECC_secp256k1())) return false;
  if (isHighS(sig + 32)) negateS(sig + 32);
  hexEncode(sig, 64, outHex);
  return true;
}
// ======= MINI JSON (block signing) =======
// Canonical JSON reproducing Python:
//   json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=False)
// Numbers keep their ORIGINAL text (the node emitted Python repr already, so
// byte-preservation is exact). Strings are decoded and re-escaped with
// json.dumps(ensure_ascii=False) rules. Excluded top-level fields (hash,
// signature, pqc_signature, finalized) are dropped only at emit root — the
// server's block_signing_payload() strips only the top-level dict.


// MiniJSON types are embedded unconditionally above so this parser remains
// available even when AI_USE_LLM is disabled.

static void* arenaAlloc(Arena* a, size_t bytes) {
  if (!a || !a->base || a->used > a->cap) return NULL;
  if (bytes > SIZE_MAX - 7u) return NULL;
  bytes = (bytes + 7u) & ~(size_t)7u;
  if (bytes > a->cap - a->used) return NULL;
  void* p = a->base + a->used;
  a->used += bytes;
  return p;
}

// Validate raw UTF-8 before JSON parsing/canonical signing. Invalid UTF-8 can be
// replaced by terminal/logging layers with '?' and, more importantly, different
// decoders may hash different byte sequences. Valid non-ASCII UTF-8 is preserved.
static bool mcxValidUtf8(const uint8_t* s, size_t n) {
  if (!s && n) return false;
  size_t i = 0;
  while (i < n) {
    uint8_t c = s[i++];
    if (c <= 0x7Fu) continue;
    if (c >= 0xC2u && c <= 0xDFu) {
      if (i >= n || (s[i] & 0xC0u) != 0x80u) return false;
      ++i;
      continue;
    }
    if (c >= 0xE0u && c <= 0xEFu) {
      if (i + 1 >= n) return false;
      uint8_t b1 = s[i], b2 = s[i + 1];
      if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u) return false;
      if ((c == 0xE0u && b1 < 0xA0u) || (c == 0xEDu && b1 >= 0xA0u)) return false;
      i += 2;
      continue;
    }
    if (c >= 0xF0u && c <= 0xF4u) {
      if (i + 2 >= n) return false;
      uint8_t b1 = s[i], b2 = s[i + 1], b3 = s[i + 2];
      if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u ||
          (b3 & 0xC0u) != 0x80u) return false;
      if ((c == 0xF0u && b1 < 0x90u) || (c == 0xF4u && b1 >= 0x90u)) return false;
      i += 3;
      continue;
    }
    return false;
  }
  return true;
}

static void mjSkipWs(MjParser* q) {
  while (q->p < q->end && (*q->p == ' ' || *q->p == '\t' || *q->p == '\n' || *q->p == '\r')) q->p++;
}

static bool mjUtf8Append(char* dst, uint32_t* len, uint32_t cap, uint32_t cp) {
  if (cp < 0x80) {
    if (*len + 1 > cap) return false;
    dst[(*len)++] = (char)cp;
  } else if (cp < 0x800) {
    if (*len + 2 > cap) return false;
    dst[(*len)++] = (char)(0xC0 | (cp >> 6));
    dst[(*len)++] = (char)(0x80 | (cp & 0x3F));
  } else if (cp < 0x10000) {
    if (*len + 3 > cap) return false;
    dst[(*len)++] = (char)(0xE0 | (cp >> 12));
    dst[(*len)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
    dst[(*len)++] = (char)(0x80 | (cp & 0x3F));
  } else {
    if (*len + 4 > cap) return false;
    dst[(*len)++] = (char)(0xF0 | (cp >> 18));
    dst[(*len)++] = (char)(0x80 | ((cp >> 12) & 0x3F));
    dst[(*len)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
    dst[(*len)++] = (char)(0x80 | (cp & 0x3F));
  }
  return true;
}

static bool mjHex4(const char* s, const char* end, uint32_t* cp) {
  if (end - s < 4) return false;
  uint32_t v = 0;
  for (int i = 0; i < 4; i++) {
    int h = hexNib(s[i]);
    if (h < 0) return false;
    v = (v << 4) | (uint32_t)h;
  }
  *cp = v;
  return true;
}

// Two-pass sizing: exact decoded length of the string starting at s
// (just after the opening quote). Decoded output is never longer than the
// raw span, but sizing exactly keeps the arena small for many-keyed objects.
static bool mjStringNeed(const char* s, const char* end, size_t* need) {
  size_t n = 0;
  while (s < end) {
    char c = *s;
    if (c == '"') { *need = n; return true; }
    if ((uint8_t)c < 0x20) return false;
    if (c != '\\') { n++; s++; continue; }
    s++;
    if (s >= end) return false;
    char e = *s++;
    if (e == 'u') {
      uint32_t cp;
      if (!mjHex4(s, end, &cp)) return false;
      s += 4;
      if (cp >= 0xD800 && cp <= 0xDBFF) {
        if (end - s >= 6 && s[0] == '\\' && s[1] == 'u') {
          uint32_t lo;
          if (!mjHex4(s + 2, end, &lo) || lo < 0xDC00 || lo > 0xDFFF) return false;
          s += 6;
          n += 4;
        } else return false;
      } else {
        if (cp >= 0xDC00 && cp <= 0xDFFF) return false; // orphan low surrogate
        n += (cp < 0x80) ? 1 : (cp < 0x800) ? 2 : 3;
      }
    } else {
      n += 1;   // \" \\ \/ \b \f \n \r \t or invalid (validated in pass 2)
    }
  }
  return false;
}

// Decode a JSON string (q->p just after the opening quote). Returns arena ptr.
static char* mjParseString(MjParser* q, uint32_t* outLen) {
  size_t need = 0;
  if (!mjStringNeed(q->p, q->end, &need)) { q->fail = true; return NULL; }
  char* dst = (char*)arenaAlloc(q->a, need + 1);
  if (!dst) { q->fail = true; return NULL; }
  uint32_t len = 0;
  const uint32_t cap = (uint32_t)need;
  while (q->p < q->end) {
    char c = *q->p;
    if (c == '"') { q->p++; dst[len] = 0; *outLen = len; return dst; }
    if ((uint8_t)c < 0x20) { q->fail = true; return NULL; }
    if (c != '\\') {
      if (len + 1 > cap) { q->fail = true; return NULL; }
      dst[len++] = c;
      q->p++;
      continue;
    }
    q->p++;
    if (q->p >= q->end) { q->fail = true; return NULL; }
    char e = *q->p++;
    bool ok = true;
    switch (e) {
      case '"':  dst[len++] = '"';  break;
      case '\\': dst[len++] = '\\'; break;
      case '/':  dst[len++] = '/';  break;
      case 'b':  dst[len++] = '\b'; break;
      case 'f':  dst[len++] = '\f'; break;
      case 'n':  dst[len++] = '\n'; break;
      case 'r':  dst[len++] = '\r'; break;
      case 't':  dst[len++] = '\t'; break;
      case 'u': {
        uint32_t cp;
        if (!mjHex4(q->p, q->end, &cp)) { q->fail = true; return NULL; }
        q->p += 4;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
          if (q->end - q->p >= 6 && q->p[0] == '\\' && q->p[1] == 'u') {
            q->p += 2;
            uint32_t lo;
            if (!mjHex4(q->p, q->end, &lo)) { q->fail = true; return NULL; }
            q->p += 4;
            if (lo >= 0xDC00 && lo <= 0xDFFF)
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            else { q->fail = true; return NULL; }
          } else { q->fail = true; return NULL; }
        }
        ok = mjUtf8Append(dst, &len, cap, cp);
        break;
      }
      default: ok = false; break;
    }
    if (!ok) { q->fail = true; return NULL; }
  }
  q->fail = true;
  return NULL;
}

#define MJ_MAX_JSON_DEPTH 64
static Mj* mjParseValue(MjParser* q);
static Mj* mjParseValueDepth(MjParser* q, unsigned depth);

static Mj* mjNew(MjParser* q, MjType t) {
  Mj* v = (Mj*)arenaAlloc(q->a, sizeof(Mj));
  if (!v) { q->fail = true; return NULL; }
  v->t = (uint8_t)t;
  return v;
}

static Mj* mjParseValueDepth(MjParser* q, unsigned depth) {
  if (depth > MJ_MAX_JSON_DEPTH) { q->fail = true; return NULL; }
  mjSkipWs(q);
  if (q->fail || q->p >= q->end) { q->fail = true; return NULL; }
  char c = *q->p;
  if (c == '{') {
    q->p++;
    Mj* v = mjNew(q, MJ_OBJ);
    if (!v) return NULL;
    v->obj.kv = NULL; v->obj.n = 0;
    uint32_t cap = 16, n = 0;
    MjKV* kv = (MjKV*)arenaAlloc(q->a, cap * sizeof(MjKV));
    if (!kv) { q->fail = true; return NULL; }
    mjSkipWs(q);
    if (q->p < q->end && *q->p == '}') { q->p++; v->obj.kv = kv; v->obj.n = 0; return v; }
    for (;;) {
      mjSkipWs(q);
      if (q->p >= q->end || *q->p != '"') { q->fail = true; return NULL; }
      q->p++;
      uint32_t klen = 0;
      char* k = mjParseString(q, &klen);
      if (!k) return NULL;
      for (uint32_t j = 0; j < n; ++j) {
        if (kv[j].kl == klen && memcmp(kv[j].k, k, klen) == 0) {
          q->fail = true; return NULL; // duplicate JSON keys are ambiguous for signatures
        }
      }
      mjSkipWs(q);
      if (q->p >= q->end || *q->p != ':') { q->fail = true; return NULL; }
      q->p++;
      Mj* val = mjParseValueDepth(q, depth + 1);
      if (!val) return NULL;
      if (n == cap) {
        uint32_t ncap = cap * 2;
        MjKV* nkv = (MjKV*)arenaAlloc(q->a, ncap * sizeof(MjKV));
        if (!nkv) { q->fail = true; return NULL; }
        memcpy(nkv, kv, n * sizeof(MjKV));
        kv = nkv; cap = ncap;
      }
      kv[n].k = k; kv[n].kl = klen; kv[n].v = val; n++;
      mjSkipWs(q);
      if (q->p < q->end && *q->p == ',') { q->p++; continue; }
      if (q->p < q->end && *q->p == '}') { q->p++; break; }
      q->fail = true; return NULL;
    }
    v->obj.kv = kv; v->obj.n = n;
    return v;
  }
  if (c == '[') {
    q->p++;
    Mj* v = mjNew(q, MJ_ARR);
    if (!v) return NULL;
    uint32_t cap = 16, n = 0;
    Mj** it = (Mj**)arenaAlloc(q->a, cap * sizeof(Mj*));
    if (!it) { q->fail = true; return NULL; }
    mjSkipWs(q);
    if (q->p < q->end && *q->p == ']') { q->p++; v->arr.it = it; v->arr.n = 0; return v; }
    for (;;) {
      Mj* val = mjParseValueDepth(q, depth + 1);
      if (!val) return NULL;
      if (n == cap) {
        uint32_t ncap = cap * 2;
        Mj** nit = (Mj**)arenaAlloc(q->a, ncap * sizeof(Mj*));
        if (!nit) { q->fail = true; return NULL; }
        memcpy(nit, it, n * sizeof(Mj*));
        it = nit; cap = ncap;
      }
      it[n++] = val;
      mjSkipWs(q);
      if (q->p < q->end && *q->p == ',') { q->p++; continue; }
      if (q->p < q->end && *q->p == ']') { q->p++; break; }
      q->fail = true; return NULL;
    }
    v->arr.it = it; v->arr.n = n;
    return v;
  }
  if (c == '"') {
    q->p++;
    Mj* v = mjNew(q, MJ_STR);
    if (!v) return NULL;
    uint32_t sl = 0;
    char* s = mjParseString(q, &sl);
    if (!s) return NULL;
    v->str.s = s; v->str.len = sl;
    return v;
  }
  if (c == 't' || c == 'f') {
    bool isT = (c == 't');
    const char* lit = isT ? "true" : "false";
    size_t l = isT ? 4 : 5;
    if ((size_t)(q->end - q->p) < l || memcmp(q->p, lit, l) != 0) { q->fail = true; return NULL; }
    q->p += l;
    Mj* v = mjNew(q, MJ_BOOL);
    if (!v) return NULL;
    v->b = isT;
    return v;
  }
  if (c == 'n') {
    if ((size_t)(q->end - q->p) < 4 || memcmp(q->p, "null", 4) != 0) { q->fail = true; return NULL; }
    q->p += 4;
    return mjNew(q, MJ_NULL);
  }
  if (c == '-' || (c >= '0' && c <= '9')) {
    const char* start = q->p;
    if (*q->p == '-') { q->p++; if (q->p >= q->end) { q->fail = true; return NULL; } }
    if (*q->p == '0') {
      q->p++;
      if (q->p < q->end && *q->p >= '0' && *q->p <= '9') { q->fail = true; return NULL; }
    } else if (*q->p >= '1' && *q->p <= '9') {
      do { q->p++; } while (q->p < q->end && *q->p >= '0' && *q->p <= '9');
    } else { q->fail = true; return NULL; }
    if (q->p < q->end && *q->p == '.') {
      q->p++;
      if (q->p >= q->end || *q->p < '0' || *q->p > '9') { q->fail = true; return NULL; }
      while (q->p < q->end && *q->p >= '0' && *q->p <= '9') q->p++;
    }
    if (q->p < q->end && (*q->p == 'e' || *q->p == 'E')) {
      q->p++;
      if (q->p < q->end && (*q->p == '+' || *q->p == '-')) q->p++;
      if (q->p >= q->end || *q->p < '0' || *q->p > '9') { q->fail = true; return NULL; }
      while (q->p < q->end && *q->p >= '0' && *q->p <= '9') q->p++;
    }
    Mj* v = mjNew(q, MJ_NUM);
    if (!v) return NULL;
    v->num.s = start;
    v->num.len = (uint32_t)(q->p - start);
    return v;
  }
  q->fail = true;
  return NULL;
}

static Mj* mjParseValue(MjParser* q) { return mjParseValueDepth(q, 0); }

// Append key/value (used to inject producer_pub / hash / signature).
static bool mjObjAppend(Mj* obj, Arena* a, const char* key, const char* val) {
  if (!obj || obj->t != MJ_OBJ) return false;
  uint32_t n = obj->obj.n;
  size_t kl = strlen(key), vl = strlen(val);
  // never emit duplicate keys: replace an existing value in place
  for (uint32_t i = 0; i < n; i++) {
    MjKV* kv = &obj->obj.kv[i];
    if (kv->kl == kl && memcmp(kv->k, key, kl) == 0) {
      char* vc = (char*)arenaAlloc(a, vl + 1);
      Mj* sv = (Mj*)arenaAlloc(a, sizeof(Mj));
      if (!vc || !sv) return false;
      memcpy(vc, val, vl + 1);
      sv->t = MJ_STR;
      sv->str.s = vc;
      sv->str.len = (uint32_t)vl;
      kv->v = sv;
      return true;
    }
  }
  MjKV* nk = (MjKV*)arenaAlloc(a, ((size_t)n + 1) * sizeof(MjKV));
  if (!nk) return false;
  if (n) memcpy(nk, obj->obj.kv, n * sizeof(MjKV));
  char* kcopy = (char*)arenaAlloc(a, kl + 1);
  char* vcopy = (char*)arenaAlloc(a, vl + 1);
  Mj* sv = (Mj*)arenaAlloc(a, sizeof(Mj));
  if (!kcopy || !vcopy || !sv) return false;
  memcpy(kcopy, key, kl + 1);
  memcpy(vcopy, val, vl + 1);
  sv->t = MJ_STR;
  sv->str.s = vcopy;
  sv->str.len = (uint32_t)vl;
  nk[n].k = kcopy;
  nk[n].kl = (uint32_t)kl;
  nk[n].v = sv;
  obj->obj.kv = nk;
  obj->obj.n = n + 1;
  return true;
}

static bool mjIsExcluded(const MjKV* kv) {
  static const char* ex[4] = { "hash", "signature", "pqc_signature", "finalized" };
  for (int i = 0; i < 4; i++) {
    size_t l = strlen(ex[i]);
    if (kv->kl == l && memcmp(kv->k, ex[i], l) == 0) return true;
  }
  return false;
}

static void outRaw(OutBuf* o, const char* s, size_t n) {
  if (o->fail || o->len + n > o->cap) { o->fail = true; return; }
  memcpy(o->p + o->len, s, n);
  o->len += n;
}
static void outCh(OutBuf* o, char c) { outRaw(o, &c, 1); }

// json.dumps(..., ensure_ascii=False) string escaping.
static void outJsonString(OutBuf* o, const char* s, uint32_t n) {
  outCh(o, '"');
  for (uint32_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '"')       outRaw(o, "\\\"", 2);
    else if (c == '\\') outRaw(o, "\\\\", 2);
    else if (c == '\b') outRaw(o, "\\b", 2);
    else if (c == '\f') outRaw(o, "\\f", 2);
    else if (c == '\n') outRaw(o, "\\n", 2);
    else if (c == '\r') outRaw(o, "\\r", 2);
    else if (c == '\t') outRaw(o, "\\t", 2);
    else if (c < 0x20) {
      char b[8];
      snprintf(b, sizeof(b), "\\u%04x", c);
      outRaw(o, b, 6);
    } else {
      outCh(o, (char)c);
    }
  }
  outCh(o, '"');
}

static int mjKvCmp(const void* a, const void* b) {
  const MjKV* x = *(const MjKV* const*)a;
  const MjKV* y = *(const MjKV* const*)b;
  uint32_t mn = x->kl < y->kl ? x->kl : y->kl;
  int c = memcmp(x->k, y->k, mn);
  if (c != 0) return c;
  return (x->kl > y->kl) - (x->kl < y->kl);
}

static void mjEmit(Mj* v, OutBuf* o, bool sort, bool dropExcludedAtRoot, int depth) {
  if (!v || o->fail) return;
  switch ((MjType)v->t) {
    case MJ_NULL: outRaw(o, "null", 4); break;
    case MJ_BOOL: outRaw(o, v->b ? "true" : "false", v->b ? 4 : 5); break;
    case MJ_NUM:  outRaw(o, v->num.s, v->num.len); break;
    case MJ_STR:  outJsonString(o, v->str.s, v->str.len); break;
    case MJ_ARR: {
      outCh(o, '[');
      for (uint32_t i = 0; i < v->arr.n; i++) {
        if (i) outCh(o, ',');
        mjEmit(v->arr.it[i], o, sort, false, depth + 1);
      }
      outCh(o, ']');
      break;
    }
    case MJ_OBJ: {
      outCh(o, '{');
      uint32_t emitted = 0;
      if (sort && v->obj.n > 0) {
        const MjKV** order = (const MjKV**)malloc(v->obj.n * sizeof(MjKV*));
        if (!order) { o->fail = true; return; }
        uint32_t m = 0;
        for (uint32_t i = 0; i < v->obj.n; i++) {
          if (dropExcludedAtRoot && depth == 0 && mjIsExcluded(&v->obj.kv[i])) continue;
          order[m++] = &v->obj.kv[i];
        }
        qsort(order, m, sizeof(MjKV*), mjKvCmp);
        for (uint32_t i = 0; i < m; i++) {
          if (emitted++) outCh(o, ',');
          outJsonString(o, order[i]->k, order[i]->kl);
          outCh(o, ':');
          mjEmit((Mj*)order[i]->v, o, sort, false, depth + 1);
        }
        free(order);
      } else {
        for (uint32_t i = 0; i < v->obj.n; i++) {
          if (dropExcludedAtRoot && depth == 0 && mjIsExcluded(&v->obj.kv[i])) continue;
          if (emitted++) outCh(o, ',');
          outJsonString(o, v->obj.kv[i].k, v->obj.kv[i].kl);
          outCh(o, ':');
          mjEmit(v->obj.kv[i].v, o, sort, false, depth + 1);
        }
      }
      outCh(o, '}');
      break;
    }
  }
}
// ======= MINING STATE =======
static char gPubHex[131];           // 04 + 128 hex
static char gWallet[48];            // 0x + 40 hex (lowercase)
static char gMinerId[48];           // PC_ + 32 upper hex
static bool gPrivFromConfig = false;
static bool gLlmReady = false;

static WebSocketsClient webSocket;

static bool     gWsUp = false;
static bool     gRegistered = false;
static int      gPhase = PH_WIFI;
static uint32_t gLastFrameMs = 0;
static uint32_t gConnectedMs = 0;
static uint32_t gRegisterSentMs = 0;
static bool     gWsBegun = false;   // begin() called exactly once (see wsEnsureBegun)
static uint8_t  gRegFailStreak = 0;
static bool     gNtpOk = false;
static bool     gNtpDead = false;   // NTP unreachable: proceed without time sync (see ntpWatchdog)
static uint32_t gNtpWaitStartMs = 0;
static bool     gMazeTooBig = false; // latest maze exceeds MAX_MAZE_DIM: wait loudly, do not reconnect-spin
static bool     gMazeAskDone = false;
static uint32_t gLastPingMs = 0;      // last uptime_ping sent

static int      gAwait = AWAIT_NONE;
static uint32_t gAwaitStartMs = 0;
static uint8_t  gAwaitFails = 0;

// maze
static uint8_t* gCells = NULL;
static int      gCellsCap = 0;
static int      gDim = 0;
static int8_t   gCur[3]  = { 0, 0, 0 };
static int8_t   gGoal[3] = { 0, 0, 0 };
static int64_t  gNonce = 0;       // last ACCEPTED move nonce
static int64_t  gGrowth = 0;
static bool     gHasMaze = false;

// BFS scratch
static uint8_t* gVis = NULL;
static int32_t* gPar = NULL;
static int32_t* gQue = NULL;
static int      gBfsCap = 0;

// deferred memory challenge
static bool     gChalPending = false;
static char     gChalSeedB64[64];
static uint8_t  gChalSeed[32];
static uint32_t gChalMemSize = 0;
static uint32_t gChalProduced = 0;
static uint64_t gChalCounter = 0;
static mbedtls_sha256_context gChalOuter;
static bool     gChalOuterInit = false;

// deferred PoW
static bool     gPowPending = false;
static bool     gPowSolved = false;
static char     gPowSeed[160];
static int      gPowDiff = 5;
static uint64_t gPowNonce = 0;
static uint32_t gPowStartMs = 0;

// WiFi watchdog
static int      gWifiState = WIFI_ATTEMPT;
static uint32_t gWifiAttemptMs = 0;
static uint32_t gWifiBackoffMs = 0;
static uint32_t gWifiRetryAtMs = 0;

// AI learner
static float gW[AI_NF];
static float gEps = AI_EPS_START;
static float gWallHeat = 0.0f;
static int   gPrevA = -1;
static float gPrevPhi[AI_NF];
static bool  gHasPrev = false;
static int   gPrevDist = 0;
static int8_t gLlmPref = -1;
static bool  gLlmNeedScore = false;
static uint8_t gNoPathCount = 0;
static uint32_t gNextMoveMs = 0;
static uint32_t gLastHbLogMs = 0;

#if MCX_HAVE_LLM
static Model gModel;
static Scratch gScratch;
static BpeTokenizer gBpe;
static bool gModelLoaded = false, gBpeLoaded = false;
static int gLlmStagedTensors = -1;
// Owned only when loaded from LittleFS / allocated for scratch. Compile-time
// embedded assets are borrowed and must never be freed by this sketch.
static uint8_t* gLlmModelStorage = NULL;
static uint8_t* gLlmTokenizerStorage = NULL;
static uint8_t* gLlmScratchStorage = NULL;
#endif
// ======= CRYPTO IDENTITY =======
static bool deriveIdentity(const char* privHexOverride) {
  const char* hx = privHexOverride;
  if (!hx || !*hx) hx = MCX_PRIVKEY_HEX;
  gPrivFromConfig = (hx && *hx);
  if (gPrivFromConfig) {
    if (!hexDecode(hx, gPriv, 32)) {
      logf_("ID", "ERROR: MCX_PRIVKEY_HEX must be exactly 64 hex chars");
      return false;
    }
  } else {
    // Keep a stable miner identity across reboots. Without this, each boot
    // generated an unprinted throwaway key, changing the wallet and miner ID.
    Preferences prefs;
    if (!prefs.begin("mcx-ident", false)) {
      logf_("ID", "ERROR: NVS unavailable; cannot persist miner identity");
      return false;
    }
    size_t stored = prefs.getBytesLength("priv");
    if (stored == sizeof(gPriv)) {
      if (prefs.getBytes("priv", gPriv, sizeof(gPriv)) != sizeof(gPriv)) {
        prefs.end();
        logf_("ID", "ERROR: stored identity read failed");
        return false;
      }
      logf_("ID", "loaded persistent identity from NVS");
    } else {
      uint8_t pubTmp[64];
      if (!uECC_make_key(pubTmp, gPriv, uECC_secp256k1())) {
        prefs.end();
        logf_("ID", "ERROR: key generation failed");
        return false;
      }
      if (prefs.putBytes("priv", gPriv, sizeof(gPriv)) != sizeof(gPriv)) {
        memset(gPriv, 0, sizeof(gPriv));
        prefs.end();
        logf_("ID", "ERROR: could not persist generated identity; refusing volatile wallet");
        return false;
      }
      logf_("ID", "generated and persisted a stable identity in NVS (private key never printed)");
    }
    prefs.end();
  }

  uint8_t pub64[64];
  if (!uECC_compute_public_key(gPriv, pub64, uECC_secp256k1())) {
    memset(gPriv, 0, sizeof(gPriv));
    logf_("ID", "ERROR: invalid secp256k1 private key");
    return false;
  }
  gPubHex[0] = '0'; gPubHex[1] = '4';
  hexEncode(pub64, 64, gPubHex + 2);

  uint8_t k[32];
  keccak256(pub64, 64, k);
  char addr[41];
  hexEncode(k + 12, 20, addr);
  char derivedWallet[48];
  snprintf(derivedWallet, sizeof(derivedWallet), "0x%s", addr);
  if (MCX_WALLET_OVERRIDE[0]) {
    char overrideLower[48];
    strncpy(overrideLower, MCX_WALLET_OVERRIDE, sizeof(overrideLower) - 1);
    overrideLower[sizeof(overrideLower) - 1] = 0;
    for (char* p = overrideLower; *p; p++) if (*p >= 'A' && *p <= 'F') *p = (char)(*p + 32);
    if (strlen(overrideLower) != 42 || strcmp(overrideLower, derivedWallet) != 0) {
      logf_("ID", "ERROR: MCX_WALLET_OVERRIDE must match the private key's derived address");
      return false;
    }
  }
  strncpy(gWallet, derivedWallet, sizeof(gWallet) - 1);
  gWallet[sizeof(gWallet) - 1] = 0;

  // Server enforces PC_ + SHA256(wallet + "_mcx_miner").hexdigest()[:32].upper()
  char idMsg[96];
  snprintf(idMsg, sizeof(idMsg), "%s_mcx_miner", gWallet);
  uint8_t idDigest[32];
  mcxSha256((const uint8_t*)idMsg, strlen(idMsg), idDigest);
  char idHex[65];
  hexEncode(idDigest, 32, idHex);
  idHex[32] = 0;
  for (int i = 0; i < 32; i++) if (idHex[i] >= 'a' && idHex[i] <= 'f') idHex[i] -= 32;
  char derivedMinerId[48];
  snprintf(derivedMinerId, sizeof(derivedMinerId), "PC_%s", idHex);
  if (MCX_MINER_ID_OVERRIDE[0]) {
    const size_t baseLen = strlen(derivedMinerId);
    if (strncmp(MCX_MINER_ID_OVERRIDE, derivedMinerId, baseLen) != 0 ||
        (MCX_MINER_ID_OVERRIDE[baseLen] != 0 && MCX_MINER_ID_OVERRIDE[baseLen] != '_') ||
        strlen(MCX_MINER_ID_OVERRIDE) >= sizeof(gMinerId)) {
      logf_("ID", "ERROR: MCX_MINER_ID_OVERRIDE must equal the derived ID or add an underscore suffix");
      return false;
    }
    strncpy(gMinerId, MCX_MINER_ID_OVERRIDE, sizeof(gMinerId) - 1);
    gMinerId[sizeof(gMinerId) - 1] = 0;
  } else {
    strncpy(gMinerId, derivedMinerId, sizeof(gMinerId) - 1);
    gMinerId[sizeof(gMinerId) - 1] = 0;
  }

  // self-test: sign + verify round trip
  char sig[129];
  bool okSign = mcxSign((const uint8_t*)"MCXESPSELFTEST", 14, sig);
  bool okVerify = false;
  if (okSign) {
    uint8_t h[32], s[64], pub64b[64];
    hexDecode(sig, s, 64);
    hexDecode(gPubHex + 2, pub64b, 64);
    mcxSha256((const uint8_t*)"MCXESPSELFTEST", 14, h);
    okVerify = uECC_verify(pub64b, h, 32, s, uECC_secp256k1()) != 0;
  }
  logf_("ID", "wallet  = %s", gWallet);
  logf_("ID", "miner_id= %s", gMinerId);
  logf_("ID", "pub     = %.24s...", gPubHex);
  logf_("ID", "sig self-test: %s", (okSign && okVerify) ? "PASS" : "FAIL");
  return okSign && okVerify;
}
// ======= BFS PATH PLANNER =======
static bool ensureMazeCap(int cells) {
  if (cells <= gCellsCap) return true;
  uint8_t* nc = (uint8_t*)realloc(gCells, (size_t)cells);
  if (!nc) return false;
  gCells = nc; gCellsCap = cells;
  return true;
}

static bool ensureBfsCap(int cells) {
  if (cells <= gBfsCap) return true;
  uint8_t* nv = (uint8_t*)realloc(gVis, (size_t)cells);
  if (!nv) return false;
  gVis = nv;
  int32_t* np = (int32_t*)realloc(gPar, (size_t)cells * sizeof(int32_t));
  if (!np) return false;
  gPar = np;
  int32_t* nq = (int32_t*)realloc(gQue, (size_t)cells * sizeof(int32_t));
  if (!nq) return false;
  gQue = nq;
  gBfsCap = cells;
  return true;
}

static inline int cellIdx(int x, int y, int z) { return (z * gDim + y) * gDim + x; }

static inline bool inBounds(int x, int y, int z) {
  return x >= 0 && y >= 0 && z >= 0 && x < gDim && y < gDim && z < gDim;
}

static inline bool isOpen(int x, int y, int z) {
  return inBounds(x, y, z) && gCells[cellIdx(x, y, z)] == 0;
}

// BFS from s to g. Returns: 1 = first step found (out = next cell),
// 0 = s == g, -1 = unreachable.
static int bfsFirstStep(const int8_t s[3], const int8_t g[3], int out[3]) {
  int cells = gDim * gDim * gDim;
  if (s[0] == g[0] && s[1] == g[1] && s[2] == g[2]) return 0;
  if (!isOpen(g[0], g[1], g[2]) || !isOpen(s[0], s[1], s[2])) return -1;
  memset(gVis, 0, (size_t)cells);
  memset(gPar, 0xFF, (size_t)cells * sizeof(int32_t));   // -1
  int head = 0, tail = 0;
  int si = cellIdx(s[0], s[1], s[2]);
  int gi = cellIdx(g[0], g[1], g[2]);
  gQue[tail++] = si;
  gVis[si] = 1;
  gPar[si] = -1;
  bool found = false;
  while (head < tail) {
    int ci = gQue[head++];
    if (ci == gi) { found = true; break; }
    int cz = ci / (gDim * gDim);
    int rem = ci % (gDim * gDim);
    int cy = rem / gDim, cx = rem % gDim;
    for (int d = 0; d < 6; d++) {
      int nx = cx + kDirDx[d], ny = cy + kDirDy[d], nz = cz + kDirDz[d];
      if (!isOpen(nx, ny, nz)) continue;
      int ni = cellIdx(nx, ny, nz);
      if (gVis[ni]) continue;
      gVis[ni] = 1;
      gPar[ni] = ci;
      gQue[tail++] = ni;
    }
  }
  if (!found) return -1;
  // walk back from goal to the cell right after s
  int node = gi;
  while (gPar[node] != si && gPar[node] != -1) node = gPar[node];
  if (gPar[node] != si) return -1;
  out[0] = node % gDim;
  out[1] = (node / gDim) % gDim;
  out[2] = node / (gDim * gDim);
  return 1;
}
// ======= AI =======
static void computeOpen(int open[6]) {
  for (int d = 0; d < 6; d++)
    open[d] = isOpen(gCur[0] + kDirDx[d], gCur[1] + kDirDy[d], gCur[2] + kDirDz[d]) ? 1 : 0;
}

static void aiFeatures(const int open[6], int a, float phi[AI_NF]) {
  memset(phi, 0, sizeof(float) * AI_NF);
  phi[a] = 1.0f;                                   // 0..5   one-hot
  if (open[a]) phi[6 + a] = 1.0f;                  // 6..11  open
  int dx = gGoal[0] - gCur[0];
  int dy = gGoal[1] - gCur[1];
  int dz = gGoal[2] - gCur[2];
  int dot = dx * kDirDx[a] + dy * kDirDy[a] + dz * kDirDz[a];
  phi[12 + a] = dot > 0 ? 1.0f : (dot < 0 ? -0.5f : 0.0f);   // 12..17 toward goal
  phi[18] = gWallHeat;                            // 18     recent wall heat
  int oc = 0;
  for (int i = 0; i < 6; i++) if (open[i]) oc++;
  phi[19] = oc / 6.0f;                            // 19     openness
  phi[20] = 1.0f;                                 // 20     bias
  phi[21] = (gLlmPref >= 0 && a == gLlmPref) ? 1.0f : 0.0f;  // 21 LLM prior
}

static float aiQ(const float phi[AI_NF]) {
  float q = 0;
  for (int i = 0; i < AI_NF; i++) q += gW[i] * phi[i];
  return q;
}

// pick direction: BFS step normally, epsilon-greedy learner override, else
// best open learner action if BFS is blocked.
static int aiChoose(int bfsDir, const int open[6]) {
  bool explore = ((int)(esp_random() % 10000) < (int)(gEps * 10000.0f));
  if (explore) {
    float best = -1e30f; int bestA = -1;
    float phi[AI_NF];
    for (int d = 0; d < 6; d++) {
      if (!open[d]) continue;
      aiFeatures(open, d, phi);
      float q = aiQ(phi);
      if (q > best) { best = q; bestA = d; }
    }
    if (bestA >= 0) return bestA;
  }
  if (bfsDir >= 0 && open[bfsDir]) return bfsDir;
  // BFS blocked: learner picks among open cells (exploration to find paths
  // after maze growth/sealing).
  float best = -1e30f; int bestA = -1;
  float phi[AI_NF];
  for (int d = 0; d < 6; d++) {
    if (!open[d]) continue;
    aiFeatures(open, d, phi);
    float q = aiQ(phi);
    if (q > best) { best = q; bestA = d; }
  }
  return bestA;
}

static void aiLearn(float reward, bool terminal, const int openNext[6]) {
  if (!gHasPrev) return;
  gHasPrev = false;
  float target = reward;
  if (!terminal) {
    float best = -1e30f;
    float phi[AI_NF];
    for (int d = 0; d < 6; d++) {
      if (!openNext[d]) continue;
      aiFeatures(openNext, d, phi);
      float q = aiQ(phi);
      if (q > best) best = q;
    }
    if (best > -1e29f) target += AI_GAMMA * best;
  }
  float err = target - aiQ(gPrevPhi);
  if (err > 4.0f) err = 4.0f;
  if (err < -4.0f) err = -4.0f;
  for (int i = 0; i < AI_NF; i++) {
    gW[i] += AI_LEARNING_RATE * err * gPrevPhi[i];
    if (gW[i] > 4.0f) gW[i] = 4.0f;
    if (gW[i] < -4.0f) gW[i] = -4.0f;
  }
  if (gEps > AI_EPS_MIN) {
    gEps *= AI_EPS_DECAY;
    if (gEps < AI_EPS_MIN) gEps = AI_EPS_MIN;
  }
}

static int manhattan(const int8_t a[3], const int8_t b[3]) {
  int dx = a[0] - b[0]; if (dx < 0) dx = -dx;
  int dy = a[1] - b[1]; if (dy < 0) dy = -dy;
  int dz = a[2] - b[2]; if (dz < 0) dz = -dz;
  return dx + dy + dz;
}

// ── esp32-ai LLM scorer ─────────────────────────────────────────────────────
#if MCX_HAVE_LLM
static void* llmPsramAlloc(size_t n) {
  if (n == 0) return NULL;
  if (psramFound()) {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p) return p;
  }
  // Only tiny buffers may fall back to internal RAM. Large model/scratch
  // allocations can starve networking and trigger the watchdog on no-PSRAM boards.
  if (n <= 64u * 1024u) return heap_caps_malloc(n, MALLOC_CAP_8BIT);
  return NULL;
}

static void llmCleanupFailedInit() {
  if (gLlmScratchStorage) { heap_caps_free(gLlmScratchStorage); gLlmScratchStorage = NULL; }
  if (gLlmTokenizerStorage) { heap_caps_free(gLlmTokenizerStorage); gLlmTokenizerStorage = NULL; }
  if (gLlmModelStorage) { heap_caps_free(gLlmModelStorage); gLlmModelStorage = NULL; }
  memset(&gModel, 0, sizeof(gModel));
  memset(&gScratch, 0, sizeof(gScratch));
  memset(&gBpe, 0, sizeof(gBpe));
  gModelLoaded = false;
  gBpeLoaded = false;
  gLlmStagedTensors = -1;
  gLlmReady = false;
}

static bool llmInit() {
  const uint8_t* modelBase = NULL;
  size_t modelLen = 0;
  const uint8_t* tokBase = NULL;
  size_t tokLen = 0;

#ifdef MCX_MODEL_IMAGE
  modelBase = MCX_MODEL_IMAGE;
  modelLen = MCX_MODEL_IMAGE_LEN;
#endif
#ifdef MCX_TOKENIZER_IMAGE
  tokBase = MCX_TOKENIZER_IMAGE;
  tokLen = MCX_TOKENIZER_IMAGE_LEN;
#endif

  if ((!modelBase || !tokBase) && LittleFS.begin(false)) {
    // Never format LittleFS automatically: that could erase model/tokenizer
    // assets after a transient mount error. Mount failures degrade to learner-only mode.
    if (!modelBase) {
      File f = LittleFS.open(AI_MODEL_FS_PATH, "r");
      if (f) {
        size_t n = f.size();
        if (n == 0 || n > 32u * 1024u * 1024u) {
          logf_("LLM", "model size invalid (%u bytes); LLM disabled", (unsigned)n);
        } else {
          uint8_t* buf = (uint8_t*)llmPsramAlloc(n);
          if (buf && f.read(buf, n) == n) {
            modelBase = buf; modelLen = n; gLlmModelStorage = buf;
          } else {
            if (buf) heap_caps_free(buf);
            logf_("LLM", "model read failed (%s)", AI_MODEL_FS_PATH);
          }
        }
        f.close();
      }
    }
    if (!tokBase) {
      File f = LittleFS.open(AI_TOKENIZER_FS_PATH, "r");
      if (f) {
        size_t n = f.size();
        if (n == 0 || n > 4u * 1024u * 1024u) {
          logf_("LLM", "tokenizer size invalid (%u bytes); LLM disabled", (unsigned)n);
        } else {
          uint8_t* buf = (uint8_t*)llmPsramAlloc(n);
          if (buf && f.read(buf, n) == n) {
            tokBase = buf; tokLen = n; gLlmTokenizerStorage = buf;
          } else {
            if (buf) heap_caps_free(buf);
            logf_("LLM", "tokenizer read failed (%s)", AI_TOKENIZER_FS_PATH);
          }
        }
        f.close();
      }
    }
  }

  (void)modelLen; (void)tokLen;

  if (!modelBase || !tokBase) {
    logf_("LLM", "no model/tokenizer assets - built-in learner only "
                  "(see header: mcx_ai_assets.h or LittleFS)");
    llmCleanupFailedInit(); return false;
  }

  memset(&gModel, 0, sizeof(gModel));
  int rc = llm_load(modelBase, modelLen, &gModel);
  if (rc != 0) {
    logf_("LLM", "llm_load failed rc=%d (magic PLE expected)", rc);
    llmCleanupFailedInit(); return false;
  }
  if (bpe_tokenizer_load(tokBase, tokLen, &gBpe) != 0) {
    logf_("LLM", "BTK1 tokenizer load failed");
    llmCleanupFailedInit(); return false;
  }
  if (gBpe.active_vocab > (uint32_t)gModel.c.vocab ||
      gBpe.active_vocab > (uint32_t)gModel.out_vocab) {
    logf_("LLM", "tokenizer vocab (%u) exceeds model input/output vocab (%d/%d)",
          (unsigned)gBpe.active_vocab, gModel.c.vocab, gModel.out_vocab);
    llmCleanupFailedInit(); return false;
  }

  int D = gModel.c.dim, L = gModel.c.n_layers, P = gModel.c.ple_dim;
  int F = gModel.c.ffn, S = gModel.c.seq_len, V = gModel.out_vocab;
  size_t floats =
      (size_t)D +          /*x*/     (size_t)D +          /*h*/
      (size_t)3 * D +      /*qkv*/   (size_t)D +          /*att*/
      (size_t)F +          /*g1*/    (size_t)(F > P ? F : P) +   /*g2*/
      (size_t)2 * L * P +  /*ple + tmpP*/
      (size_t)(L * P > D ? L * P : D) +                   /*trow*/
      (size_t)V +          /*logits*/(size_t)S +          /*scores*/
      (size_t)2 * L * S * D;                              /*kcache + vcache*/
  if (floats > SIZE_MAX / sizeof(float) || floats * sizeof(float) > 16u * 1024u * 1024u) {
    logf_("LLM", "scratch requirement exceeds ESP safety cap; learner-only mode");
    llmCleanupFailedInit(); return false;
  }
  uint8_t* mem = (uint8_t*)llmPsramAlloc(floats * sizeof(float));
  if (!mem) {
    logf_("LLM", "scratch alloc failed (%u bytes)", (unsigned)(floats * sizeof(float)));
    llmCleanupFailedInit(); return false;
  }
  gLlmScratchStorage = mem;
  float* f = (float*)mem;
  gScratch.x = f; f += D;
  gScratch.h = f; f += D;
  gScratch.qkv = f; f += 3 * D;
  gScratch.att = f; f += D;
  gScratch.g1 = f; f += F;
  gScratch.g2 = f; f += (F > P ? F : P);
  gScratch.ple = f; f += (size_t)L * P;
  gScratch.tmpP = f; f += (size_t)L * P;
  gScratch.trow = f; f += (L * P > D ? L * P : D);
  gScratch.logits = f; f += V;
  gScratch.scores = f; f += S;
  gScratch.kcache = f; f += (size_t)L * S * D;
  gScratch.vcache = f;   /* L*S*D remain */

#if AI_LLM_INT8
  if (psramFound()) {
    gLlmStagedTensors = llm_stage_core_int8_alloc(&gModel, llmPsramAlloc);
    logf_("LLM", "int8 staging: %d/%d tensors", gLlmStagedTensors,
          llm_core_stage_count(&gModel));
  }
#endif

  gModelLoaded = gBpeLoaded = true;
  logf_("LLM", "READY: D=%d L=%d H=%d F=%d P=%d S=%d V=%d scratch=%uKB%s",
        D, L, gModel.c.n_heads, F, P, S, V,
        (unsigned)(floats * sizeof(float) / 1024),
        psramFound() ? " (PSRAM)" : "");
  return true;
}

static float llmTokenLogProb(const float* logits, int vocab, int token) {
  if (!logits || vocab <= 0 || token < 0 || token >= vocab) return -INFINITY;
  float mx = logits[0];
  for (int i = 1; i < vocab; ++i) if (logits[i] > mx) mx = logits[i];
  double sum = 0.0;
  for (int i = 0; i < vocab; ++i) sum += exp((double)logits[i] - (double)mx);
  if (!(sum > 0.0) || !isfinite(sum)) return -INFINITY;
  return (float)((double)logits[token] - (double)mx - log(sum));
}

static int llmScoreDirections() {
  if (!gLlmReady || !gModelLoaded || !gBpeLoaded) return -1;
  const int S = gModel.c.seq_len, V = gModel.out_vocab;
  if (S < 4 || V <= 0) return -1;
  uint16_t ids[256];
  int promptN = bpe_encode_ascii(&gBpe, AI_LLM_PROMPT, ids, 256);
  if (promptN < 1) { logf_("LLM", "prompt tokenize failed rc=%d", promptN); return -1; }
  if (promptN > S - 2) promptN = S - 2;
  if (promptN < 1) return -1;
  for (int p = 0; p < promptN; p++) {
    if ((int)ids[p] >= gModel.c.vocab) return -1;
    llm_forward(&gModel, ids[p], p, &gScratch);
    if ((p & 3) == 0) esp_task_wdt_reset();
  }
  // At this point logits are P(next token | prompt). Score each full direction
  // tokenization by log-probability, not by reading logits AFTER feeding the
  // same candidate token (the previous implementation scored the wrong token).
  float bestScore = -INFINITY;
  int bestDir = -1;
  uint32_t t0 = millis();
  for (int d = 0; d < 6; d++) {
    char cand[16];
    snprintf(cand, sizeof(cand), " %s", kDirName[d]);
    uint16_t cid[8];
    int cn = bpe_encode_ascii(&gBpe, cand, cid, 8);
    if (cn <= 0 || promptN + cn >= S) continue;
    bool idsOk = true;
    for (int i = 0; i < cn; ++i) if ((int)cid[i] >= V || (int)cid[i] >= gModel.c.vocab) idsOk = false;
    if (!idsOk) continue;
    float score = 0.0f;
    for (int i = 0; i < cn; ++i) {
      const float* logits = gScratch.logits;
      score += llmTokenLogProb(logits, V, (int)cid[i]);
      if (i + 1 < cn) llm_forward(&gModel, (int)cid[i], promptN + i, &gScratch);
      esp_task_wdt_reset();
    }
    score /= (float)cn;
    if (isfinite(score) && score > bestScore) { bestScore = score; bestDir = d; }
    // Restore only the prompt KV state on the next candidate by replaying it.
    // Replaying is cheap relative to a decode and prevents candidate contamination.
    for (int p = 0; p < promptN; ++p) llm_forward(&gModel, ids[p], p, &gScratch);
  }
  logf_("LLM", "direction prior -> %s (mean logp %.3f, %lums)",
        bestDir >= 0 ? kDirName[bestDir] : "none", (double)bestScore,
        (unsigned long)(millis() - t0));
  return bestDir;
}
#endif  // MCX_HAVE_LLM
// ======= WS PROTOCOL SENDING =======
static bool wsSend(const char* json, size_t len) {
  if (!json || len == 0 || len > MCX_MAX_JSON_BYTES || !gWsUp) return false;
  if (!mcxValidUtf8((const uint8_t*)json, len)) {
    logf_("TX", "refusing malformed UTF-8 JSON frame (len=%u)", (unsigned)len);
    return false;
  }
#if defined(WEBSOCKETS_MAX_DATA_SIZE)
  if (len > (size_t)WEBSOCKETS_MAX_DATA_SIZE) {
    logf_("TX", "frame %u exceeds installed WebSockets library limit %u; patch library or chunk protocol",
          (unsigned)len, (unsigned)WEBSOCKETS_MAX_DATA_SIZE);
    return false;
  }
#endif
  bool ok = webSocket.sendTXT((uint8_t*)json, len);
  if (!ok) logf_("TX", "sendTXT failed (len=%u)", (unsigned)len);
  return ok;
}

static void sendRegister() {
  char authMsg[128];
  int64_t ts = (int64_t)time(nullptr);
  snprintf(authMsg, sizeof(authMsg), "%s%s%lld", gMinerId, gWallet, (long long)ts);
  char sig[129];
  if (!mcxSign((const uint8_t*)authMsg, strlen(authMsg), sig)) {
    logf_("REG", "sign failed");
    return;
  }
  char out[1024];
  int n = snprintf(out, sizeof(out),
      "{\"type\":\"register\",\"miner_id\":\"%s\",\"wallet\":\"%s\","
      "\"public_key\":\"%s\",\"signature\":\"%s\",\"timestamp\":%lld,"
      "\"miner_type\":\"pc\",\"maze_id\":\"%s\",\"block_signing_pub\":\"%s\"}",
      gMinerId, gWallet, gPubHex, sig, (long long)ts, gPubHex, gPubHex);
  if (n <= 0 || n >= (int)sizeof(out)) {
    logf_("REG", "register JSON construction failed");
    return;
  }
  if (!wsSend(out, (size_t)n)) {
    logf_("REG", "register not queued; will retry after reconnect");
    return;
  }
  gRegisterSentMs = millis();
  gPhase = PH_REGISTER;
  logf_("REG", "register sent (ts=%lld bytes=%d)", (long long)ts, n);
}

// Keepalive while registered: refreshes the node's last_ping (miner
// dropped after 60s idle) and maze updatedat (PoG eligibility). Any
// authenticated message refreshes last_ping server-side, but during
// idle stretches (maze wait, long PoW, resync) nothing else flows.
static void sendUptimePing(uint32_t now) {
  char out[192];
  int n = snprintf(out, sizeof(out),
      "{\"type\":\"uptime_ping\",\"miner_id\":\"%s\",\"uptime_seconds\":%lu}",
      gMinerId, (unsigned long)(now / 1000));
  if (n > 0 && n < (int)sizeof(out) && wsSend(out, (size_t)n)) gLastPingMs = now;
}

static void pingTick(uint32_t now) {
  if (!gWsUp || !gRegistered) return;
  if ((now - gLastPingMs) >= UPTIME_PING_INTERVAL_MS) sendUptimePing(now);
}

// MCXPOGMOVEV1 canonical auth — byte-identical to
// PoGConsensus._move_auth_bytes (json.dumps sort_keys compact ASCII). The
// transmitted direction is always one of six hard-coded ASCII tokens; no LLM
// free-form text is ever copied into a node command.
static bool sendMove(int dirIdx) {
  if (dirIdx < 0 || dirIdx >= 6 || !gWsUp || !gRegistered) return false;
  char auth[512];
  int n = snprintf(auth, sizeof(auth),
      "{\"chainid\":%d,\"direction\":\"%s\",\"domain\":\"MCXPOGMOVEV1\","
      "\"mazeid\":\"%s\",\"mazeversion\":%lld,\"minerid\":\"%s\",\"movenonce\":%lld}",
      MCX_CHAIN_ID, kDirName[dirIdx], gPubHex, (long long)gGrowth,
      gMinerId, (long long)(gNonce + 1));
  if (n <= 0 || n >= (int)sizeof(auth)) return false;
  char sig[129];
  if (!mcxSign((const uint8_t*)auth, (size_t)n, sig)) return false;
  char out[768];
  n = snprintf(out, sizeof(out),
      "{\"type\":\"maze_move\",\"miner_id\":\"%s\",\"maze_id\":\"%s\","
      "\"direction\":\"%s\",\"signature\":\"%s\",\"move_nonce\":%lld}",
      gMinerId, gPubHex, kDirName[dirIdx], sig, (long long)(gNonce + 1));
  if (n <= 0 || n >= (int)sizeof(out)) return false;
  // The node accepts exactly these ASCII directions. Do not let a corrupted
  // enum/index, non-ASCII byte, or format truncation become a strange wire value.
  bool directionKnown = false;
  for (int i = 0; i < 6; ++i) if (strcmp(kDirName[dirIdx], kDirName[i]) == 0) directionKnown = true;
  if (!directionKnown) return false;
  for (int i = 0; i < n; ++i) {
    const unsigned char c = (unsigned char)out[i];
    if (c < 0x20 || c > 0x7E) {
      logf_("TX", "refusing non-ASCII maze_move byte at offset %d (0x%02x)", i, (unsigned)c);
      return false;
    }
  }
  if (!wsSend(out, (size_t)n)) return false;
  // These are deliberately only the protocol's ASCII enum and counter—not the
  // private key or signature. This makes a serial report of "????" traceable
  // without dumping authentication material.
  logf_("TX", "maze_move queued direction=%s nonce=%lld bytes=%d",
        kDirName[dirIdx], (long long)(gNonce + 1), n);
  return true;
}

static void sendGetMazeState() {
  char out[384];
  int n = snprintf(out, sizeof(out),
      "{\"type\":\"get_maze_state\",\"miner_id\":\"%s\",\"maze_id\":\"%s\"}",
      gMinerId, gPubHex);
  if (n <= 0 || n >= (int)sizeof(out) || !wsSend(out, (size_t)n)) return;
  gAwait = AWAIT_MAZE_STATE;
  gAwaitStartMs = millis();
}

static void requestResync(const char* why) {
  if (gAwait == AWAIT_MAZE_STATE) return;
  logf_("SYNC", "resync: %s", why);
  gAwait = AWAIT_NONE;
  sendGetMazeState();
}

static void sendWallSolve() {
  char out[384];
  int n = snprintf(out, sizeof(out),
      "{\"type\":\"wall_hit_solve\",\"miner_id\":\"%s\",\"maze_id\":\"%s\",\"nonce\":%llu}",
      gMinerId, gPubHex, (unsigned long long)gPowNonce);
  if (n <= 0 || n >= (int)sizeof(out) || !wsSend(out, (size_t)n)) {
    requestResync("wall solve send failed");
    return;
  }
  gAwait = AWAIT_POW;
  gAwaitStartMs = millis();
}

// Single reconnect mechanism: ordinary TCP/handshake failures are retried
// by the WebSockets client library itself (setReconnectInterval in setup).
// doReconnect() only resets APPLICATION state and drops the socket via
// disconnect(); the library then redials after its interval. It must NEVER
// call begin(): begin() zeroes the library's _lastConnectionFail timestamp,
// so with a long interval every begin() re-arms the full wait and the client
// never dials TCP (the observed never-CONNECTED stall). begin() runs exactly
// once in wsEnsureBegun().
static void doReconnect(const char* why) {
  logf_("WS", "reconnect (%s): app state reset, library retry owns redial", why);
  gWsUp = false;
  gRegistered = false;
  gHasMaze = false;
  gAwait = AWAIT_NONE;
  gChalPending = false;
  if (gChalOuterInit) { mbedtls_sha256_free(&gChalOuter); gChalOuterInit = false; }
  gPowPending = false;
  gPowSolved = false;
  gHasPrev = false;
  gMazeAskDone = false;
  gPhase = PH_WS;
  webSocket.disconnect();
}

// Called when WiFi is up. Runs begin() at most once for the whole uptime:
// the NTP gate must NOT delay it (NTP only gates REGISTER, not TCP), so a
// dead NTP path can never leave the client permanently uninitialized.
static void wsEnsureBegun() {
  if (gWsBegun) return;
  if (WiFi.status() != WL_CONNECTED) return;
  IPAddress ip;
  if (WiFi.hostByName(MCX_NODE_HOST, ip)) {
    logf_("WS", "begin %s:%d/ws (resolved %s)", MCX_NODE_HOST, (int)MCX_NODE_PORT,
          ip.toString().c_str());
  } else {
    logf_("WS", "begin %s:%d/ws (DNS pending here; library resolves per attempt)",
          MCX_NODE_HOST, (int)MCX_NODE_PORT);
  }
  webSocket.begin(MCX_NODE_HOST, MCX_NODE_PORT, "/ws");
  gWsBegun = true;
  if (gPhase != PH_CHALLENGE) gPhase = PH_REGISTER;
}
// ======= BLOCK SIGNING =======
// Matches _embedded_sign_block(): inject producer_pub FIRST, hash = sha256 of
// canonical JSON minus {hash, signature, pqc_signature, finalized}, then
// signature = sign_bytes(priv, bytes.fromhex(hash)).
static void handleProduceBlock(const char* payload, size_t len) {
  if (!payload || len == 0 || len > MCX_MAX_JSON_BYTES) {
    logf_("BLK", "invalid produce_block frame size=%u", (unsigned)len);
    return;
  }
  if (len > (SIZE_MAX - 32768u) / 6u) {
    logf_("BLK", "produce_block length overflow");
    return;
  }
  size_t arenaCap = len * 6 + 32768;
  Arena arena;
  arena.base = (uint8_t*)malloc(arenaCap);
  if (!arena.base) { logf_("BLK", "arena alloc failed (%u)", (unsigned)arenaCap); return; }
  arena.cap = arenaCap; arena.used = 0;
  MjParser q; q.p = payload; q.end = payload + len; q.a = &arena; q.fail = false;
  Mj* root = mjParseValue(&q);
  mjSkipWs(&q);
  if (q.fail || !root || root->t != MJ_OBJ || q.p != q.end) {
    logf_("BLK", "JSON parse failed");
    free(arena.base);
    return;
  }
  Mj* block = NULL;
  for (uint32_t i = 0; i < root->obj.n; i++)
    if (root->obj.kv[i].kl == 5 && memcmp(root->obj.kv[i].k, "block", 5) == 0)
      block = root->obj.kv[i].v;
  if (!block || block->t != MJ_OBJ) {
    logf_("BLK", "no block field");
    free(arena.base);
    return;
  }

  // 1) inject producer_pub (part of the hashed payload!)
  if (!mjObjAppend(block, &arena, "producer_pub", gPubHex)) {
    logf_("BLK", "inject producer_pub failed");
    free(arena.base);
    return;
  }

  // 2) hash = sha256(canonical(block minus excluded, sorted))
  size_t hcap = len * 2 + 1024;
  char* hbuf = (char*)malloc(hcap);
  if (!hbuf) { free(arena.base); return; }
  OutBuf ho; ho.p = hbuf; ho.cap = hcap; ho.len = 0; ho.fail = false;
  mjEmit(block, &ho, true, true, 0);
  if (ho.fail) { logf_("BLK", "canonical emit failed"); free(hbuf); free(arena.base); return; }
  uint8_t digest[32];
  mcxSha256((const uint8_t*)hbuf, ho.len, digest);
  char hashHex[65];
  hexEncode(digest, 32, hashHex);
  free(hbuf);

  // 3) signature over the raw 32-byte hash
  char sig[129];
  if (!mcxSign(digest, 32, sig)) { logf_("BLK", "sign failed"); free(arena.base); return; }

  // 4) inject hash + signature, emit full block for transport
  if (!mjObjAppend(block, &arena, "hash", hashHex) ||
      !mjObjAppend(block, &arena, "signature", sig)) {
    logf_("BLK", "inject hash/sig failed");
    free(arena.base);
    return;
  }
  size_t mcap = len + 512;
  char* mbuf = (char*)malloc(mcap);
  if (!mbuf) { free(arena.base); return; }
  OutBuf mo; mo.p = mbuf; mo.cap = mcap; mo.len = 0; mo.fail = false;
  char prefix[160];
  int pn = snprintf(prefix, sizeof(prefix),
      "{\"type\":\"block_signed\",\"miner_id\":\"%s\",\"block\":", gMinerId);
  outRaw(&mo, prefix, (size_t)pn);
  mjEmit(block, &mo, true, false, 0);
  if (!mo.fail) outCh(&mo, '}');
  if (!mo.fail) {
    if (wsSend(mbuf, mo.len)) logf_("BLK", "signed block queued hash=%.16s...", hashHex);
    else logf_("BLK", "signed block not queued; transport down or TX buffer full");
  } else {
    logf_("BLK", "emit failed");
  }
  free(mbuf);
  free(arena.base);
}
// ======= MESSAGE HANDLING =======
// MCX81's sparse_to_dense() currently serializes maze cells as JSON booleans
// (false=open, true=wall). Older/node variants may serialize these as integer
// 0/1. Accept both wire representations, but reject strings, floats, null,
// and numeric values outside the binary cell domain.
static bool readMazeCellBit(JsonVariantConst cell, uint8_t* outBit) {
  if (!outBit) return false;
  if (cell.is<bool>()) {
    *outBit = cell.as<bool>() ? 1u : 0u;
    return true;
  }
  if (cell.is<int>()) {
    const int value = cell.as<int>();
    if (value == 0 || value == 1) {
      *outBit = (uint8_t)value;
      return true;
    }
  }
  return false;
}

static bool adoptMazeArr(JsonVariantConst arr, int size) {
  // Validate before multiplying; a malformed peer-supplied size must not cause
  // signed overflow in size*size*size before the bounds check.
  if (size <= 0 || size > MAX_MAZE_DIM) {
    // Oversize (never undersize: node floor is 5): the chain outgrew this
    // firmware's RAM budget. Wait loudly instead of reconnect-spinning —
    // ghost shrink may bring it back into range, else raise MAX_MAZE_DIM
    // (needs PSRAM-class RAM: ~10 bytes/cell) and reflash.
    gMazeTooBig = (size > MAX_MAZE_DIM);
    logf_("MAZE", "bad size %d (max %d)", size, MAX_MAZE_DIM);
    return false;
  }
  const int cells = size * size * size; // size is now bounded by MAX_MAZE_DIM
  if (arr.isNull()) {
    logf_("MAZE", "maze payload is not an array");
    return false;
  }
  // Preflight the complete cube before mutating the active local maze.
  for (int z = 0; z < size; z++) {
    JsonArrayConst zl = arr[z].as<JsonArrayConst>();
    if (zl.isNull() || zl.size() != (size_t)size) {
      logf_("MAZE", "invalid maze layer %d", z);
      return false;
    }
    for (int y = 0; y < size; y++) {
      JsonArrayConst yl = zl[y].as<JsonArrayConst>();
      if (yl.isNull() || yl.size() != (size_t)size) {
        logf_("MAZE", "invalid maze row z=%d y=%d", z, y);
        return false;
      }
      for (int x = 0; x < size; x++) {
        JsonVariantConst cell = yl[x];
        uint8_t bit = 0;
        if (!readMazeCellBit(cell, &bit)) {
          logf_("MAZE", "invalid maze cell type/value at (%d,%d,%d); expected bool or integer 0/1",
                x, y, z);
          return false;
        }
      }
    }
  }
  gMazeTooBig = false;
  if (!ensureMazeCap(cells) || !ensureBfsCap(cells)) {
    logf_("MAZE", "alloc failed for %d cells (heap %u)", cells,
          (unsigned)ESP.getFreeHeap());
    return false;
  }
  gDim = size;
  for (int z = 0; z < size; z++) {
    JsonArrayConst zl = arr[z].as<JsonArrayConst>();
    for (int y = 0; y < size; y++) {
      JsonArrayConst yl = zl[y].as<JsonArrayConst>();
      for (int x = 0; x < size; x++) {
        uint8_t bit = 0; // preflight validated each cell above
        if (!readMazeCellBit(yl[x], &bit)) return false; // defensive against document mutation
        gCells[cellIdx(x, y, z)] = bit;
      }
    }
  }
  return true;
}

// Read a coordinate triple without narrowing or wrapping malformed JSON values
// into int8_t. Maze dimensions are <= MAX_MAZE_DIM, so accepted values fit.
static bool readMazeCoord(JsonArrayConst a, int size, int8_t out[3]) {
  if (a.isNull() || a.size() < 3 || size <= 0 || size > MAX_MAZE_DIM) return false;
  int tmp[3];
  for (int i = 0; i < 3; ++i) {
    JsonVariantConst v = a[i];
    if (!v.is<int>()) return false;
    tmp[i] = v.as<int>();
    if (tmp[i] < 0 || tmp[i] >= size) return false;
  }
  for (int i = 0; i < 3; ++i) out[i] = (int8_t)tmp[i];
  return true;
}

// Stable wait state for an oversized chain maze; reconnecting cannot fix the cap.
static void waitForSupportedMaze(const char* source) {
  gHasMaze = false;
  gAwait = AWAIT_NONE;
  gPhase = PH_WAIT_MAZE;
  gMazeTooBig = true;
  gConnectedMs = millis();
  logf_("MAZE", "%s exceeds firmware MAX_MAZE_DIM=%d; staying registered",
        source ? source : "maze", MAX_MAZE_DIM);
}

// Apply a server wall delta to the local maze copy: sealed cells become
// walls (1), opened cells become open (0). The node seals cells behind
// the miner and opens others as it moves (maze_move_ack top-level
// "sealed_walls" = full current set, state "sealed_walls"/"opened_walls"
// = per-move deltas). Without these the local BFS view diverges from
// the authoritative layout: it routes through sealed cells (wall-hit
// penalties) or reports "no path" through opened ones.
static void applyWallList(JsonVariantConst arr, uint8_t val, const char* what) {
  if (arr.isNull() || gDim <= 0 || !gCells) return;
  JsonArrayConst a = arr.as<JsonArrayConst>();
  if (a.isNull()) return;
  int n = 0;
  for (size_t i = 0; i < a.size(); i++) {
    JsonArrayConst w = a[i].as<JsonArrayConst>();
    if (w.isNull() || w.size() < 3) continue;
    if (!w[0].is<int>() || !w[1].is<int>() || !w[2].is<int>()) continue;
    int x = w[0].as<int>(), y = w[1].as<int>(), z = w[2].as<int>();
    if (!inBounds(x, y, z)) continue;
    gCells[cellIdx(x, y, z)] = val;
    n++;
  }
  if (n) logf_("MAZE", "%s %d cells", what, n);
}

static void resetRoundState(bool newMaze) {
  gHasPrev = false;
  gPrevA = -1;
  gNoPathCount = 0;
  gEps = AI_EPS_START;
  if (newMaze) gLlmNeedScore = true;
}

static void handleMazeInit(JsonDocument& doc) {
  int size = doc["size"] | 0;
  JsonVariantConst arr = doc["maze"];
  if (arr.isNull()) { logf_("MAZE", "maze_init missing maze"); doReconnect("maze_init missing maze"); return; }
  if (!adoptMazeArr(arr, size)) {
    if (gMazeTooBig) waitForSupportedMaze("maze_init");
    else doReconnect("bad maze_init");
    return;
  }
  int8_t nextCur[3], nextGoal[3];
  if (!readMazeCoord(doc["start"].as<JsonArrayConst>(), size, nextCur) ||
      !readMazeCoord(doc["goal"].as<JsonArrayConst>(), size, nextGoal)) {
    logf_("MAZE", "maze_init has invalid start/goal coordinates");
    doReconnect("invalid maze_init coordinates");
    return;
  }
  // The node also bakes sealed walls into the maze array; applying the
  // list again is idempotent belt-and-braces.
  applyWallList(doc["sealed_walls"].as<JsonVariantConst>(), 1, "sealed");
  memcpy(gCur, nextCur, sizeof(gCur));
  memcpy(gGoal, nextGoal, sizeof(gGoal));
  gNonce = doc["movenonce"] | (int64_t)0;
  gGrowth = doc["growthcount"] | (int64_t)0;
  gHasMaze = true;
  gPhase = PH_MINE;
  gAwait = AWAIT_NONE;
  gWallHeat = 0;
  resetRoundState(true);
  gNextMoveMs = millis();
  logf_("MAZE", "maze_init dim=%d start=(%d,%d,%d) goal=(%d,%d,%d) nonce=%lld growth=%lld",
        gDim, gCur[0], gCur[1], gCur[2], gGoal[0], gGoal[1], gGoal[2],
        (long long)gNonce, (long long)gGrowth);
}

static void handleMazeState(JsonDocument& doc) {
  JsonObjectConst st = doc["state"].as<JsonObjectConst>();
  if (st.isNull()) { logf_("SYNC", "maze_state without state"); gAwait = AWAIT_NONE; return; }
  JsonVariantConst arr = st["maze"];
  int size = st["size"] | 0;
  if (arr.isNull() || !adoptMazeArr(arr, size)) {
    gAwait = AWAIT_NONE;
    if (gMazeTooBig) waitForSupportedMaze("maze_state");
    else doReconnect("bad maze_state");
    return;
  }
  int8_t nextCur[3], nextGoal[3];
  if (!readMazeCoord(st["position"].as<JsonArrayConst>(), size, nextCur) ||
      !readMazeCoord(st["goal"].as<JsonArrayConst>(), size, nextGoal)) {
    logf_("SYNC", "maze_state has invalid position/goal coordinates");
    gAwait = AWAIT_NONE;
    doReconnect("invalid maze_state coordinates");
    return;
  }
  memcpy(gCur, nextCur, sizeof(gCur));
  memcpy(gGoal, nextGoal, sizeof(gGoal));
  gNonce = st["movenonce"] | (int64_t)0;
  gGrowth = st["growthcount"] | (int64_t)0;
  gHasMaze = true;
  gPhase = PH_MINE;
  gAwait = AWAIT_NONE;
  gAwaitFails = 0;
  gNoPathCount = 0;
  gHasPrev = false;
  gNextMoveMs = millis();
  logf_("SYNC", "resynced pos=(%d,%d,%d) goal=(%d,%d,%d) nonce=%lld growth=%lld",
        gCur[0], gCur[1], gCur[2], gGoal[0], gGoal[1], gGoal[2],
        (long long)gNonce, (long long)gGrowth);
}

static void handleMoveAck(JsonDocument& doc) {
  // The node echoes authoritative counters on both success and rejection.
  if (!doc["movenonce"].isNull()) gNonce = doc["movenonce"].as<int64_t>();
  if (!doc["growthcount"].isNull()) gGrowth = doc["growthcount"].as<int64_t>();
  gAwait = AWAIT_NONE;
  gAwaitFails = 0;

  const bool success = doc["success"] | false;
  const char* msg = doc["message"] | "";
  JsonObjectConst st = doc["state"].as<JsonObjectConst>();

  if (success) {
    const bool caught = !st.isNull() && (st["caught"] | false);
    const bool goalMoved = !st.isNull() && (st["goal_moved"] | false);
    const bool goalCaught = caught && !st["newsize"].isNull();
    const bool hasNewMaze = !doc["maze"].isNull();

    if (hasNewMaze) {
      // Goal catches and ghost catches both replace the maze. Adopt the NEW
      // maze before validating its coordinates or computing features; the
      // state.position in a caught ack may describe the old maze and must not
      // be validated against the new maze dimensions.
      const int size = doc["size"] | 0;
      if (!adoptMazeArr(doc["maze"].as<JsonVariantConst>(), size)) {
        if (gMazeTooBig) waitForSupportedMaze("maze_move_ack");
        else doReconnect("bad maze in move ack");
        return;
      }

      int8_t nextCur[3], nextGoal[3];
      if (!readMazeCoord(doc["start"].as<JsonArrayConst>(), size, nextCur) ||
          !readMazeCoord(doc["goal"].as<JsonArrayConst>(), size, nextGoal)) {
        logf_("MAZE", "new maze ack has invalid start/goal coordinates");
        doReconnect("invalid new maze ack coordinates");
        return;
      }
      memcpy(gCur, nextCur, sizeof(gCur));
      memcpy(gGoal, nextGoal, sizeof(gGoal));
      if (!doc["movenonce"].isNull()) gNonce = doc["movenonce"].as<int64_t>();
      if (!doc["growthcount"].isNull()) gGrowth = doc["growthcount"].as<int64_t>();
      applyWallList(doc["sealed_walls"].as<JsonVariantConst>(), 1, "sealed");

      // Learn from the previous maze using a terminal transition: never
      // bootstrap Q-values from the newly spawned maze. A goal capture is
      // distinct from a ghost capture (only goal capture includes state.newsize).
      int open[6];
      computeOpen(open);
      const float reward = goalCaught ? AI_R_GOAL : (caught ? AI_R_GHOST : 0.0f);
      aiLearn(reward, true, open);
      gWallHeat *= 0.9f;
      resetRoundState(true);
      gHasMaze = true;
      gPhase = PH_MINE;
      gNoPathCount = 0;
      gNextMoveMs = millis() + MOVE_PACING_MS;
      logf_("MAZE", "%s -> new maze dim=%d growth=%lld",
            goalCaught ? "goal caught" : (caught ? "ghost caught / maze shrunk" : "maze changed"),
            gDim, (long long)gGrowth);
      return;
    }

    // No maze replacement: all supplied coordinates belong to the active
    // maze. Validate before narrowing JSON integers to int8_t.
    if (!st.isNull() && !st["position"].isNull()) {
      int8_t nextCur[3];
      if (!readMazeCoord(st["position"].as<JsonArrayConst>(), gDim, nextCur)) {
        logf_("MOVE", "ack has invalid position coordinates");
        doReconnect("invalid move ack position");
        return;
      }
      memcpy(gCur, nextCur, sizeof(gCur));
    }
    if (!st.isNull() && !st["goal"].isNull()) {
      int8_t nextGoal[3];
      if (!readMazeCoord(st["goal"].as<JsonArrayConst>(), gDim, nextGoal)) {
        logf_("MOVE", "ack has invalid goal coordinates");
        doReconnect("invalid move ack goal");
        return;
      }
      memcpy(gGoal, nextGoal, sizeof(gGoal));
    }

    // The top-level list is the authoritative sealed-wall set for this maze;
    // state-level lists are per-move deltas. Apply them before computing the
    // next-state features used by the learner.
    applyWallList(doc["sealed_walls"].as<JsonVariantConst>(), 1, "sealed");
    if (!st.isNull()) {
      applyWallList(st["sealed_walls"].as<JsonVariantConst>(), 1, "sealed");
      applyWallList(st["opened_walls"].as<JsonVariantConst>(), 0, "opened");
    }

    int open[6];
    computeOpen(open);
    float reward = 0.0f;
    bool terminal = false;
    if (caught) {
      // Defensive fallback: normal server replies for a ghost catch include a
      // replacement maze. If that payload is missing, do not bootstrap across
      // the reset; request full state below.
      reward = AI_R_GHOST;
      terminal = true;
    } else if (goalMoved) {
      reward = 0.0f;
    } else {
      const int d = manhattan(gCur, gGoal);
      reward = (gPrevDist > d) ? AI_R_REWARD_STEP :
               ((gPrevDist < d) ? -AI_R_REWARD_STEP : 0.0f);
    }
    aiLearn(reward, terminal, open);
    gWallHeat *= 0.9f;
    if (caught) requestResync("caught ack without replacement maze");
    gNextMoveMs = millis() + MOVE_PACING_MS;
  } else {
    // Rejections without a position leave the local maze state untrusted.
    // Fetch authoritative state instead of repeating a move from stale coords.
    if (st.isNull() || st["position"].isNull()) {
      gHasPrev = false;
      logf_("MOVE", "rejected: %s; syncing authoritative maze state",
            msg[0] ? msg : "unknown reason");
      requestResync("rejected move has no authoritative position");
      gNextMoveMs = millis() + 1000;
      return;
    }

    if (!st["position"].isNull()) {
      int8_t nextCur[3];
      if (!readMazeCoord(st["position"].as<JsonArrayConst>(), gDim, nextCur)) {
        logf_("MOVE", "rejection has invalid position coordinates");
        doReconnect("invalid rejected move position");
        return;
      }
      memcpy(gCur, nextCur, sizeof(gCur));
    }
    if (!st.isNull() && !st["goal"].isNull()) {
      int8_t nextGoal[3];
      if (!readMazeCoord(st["goal"].as<JsonArrayConst>(), gDim, nextGoal)) {
        logf_("MOVE", "rejection has invalid goal coordinates");
        doReconnect("invalid rejected move goal");
        return;
      }
      memcpy(gGoal, nextGoal, sizeof(gGoal));
    }

    if (strncmp(msg, "Nonce mismatch", 14) == 0) {
      const char* pExpected = strstr(msg, "expected");
      if (pExpected) {
        const long long expected = atoll(pExpected + 8);
        if (expected > 0) gNonce = expected - 1;
      }
      logf_("MOVE", "nonce resync -> %lld", (long long)gNonce);
      applyWallList(doc["sealed_walls"].as<JsonVariantConst>(), 1, "sealed");
      int open[6];
      computeOpen(open);
      aiLearn(AI_R_REJECT, false, open);
      gNextMoveMs = millis();
    } else {
      applyWallList(doc["sealed_walls"].as<JsonVariantConst>(), 1, "sealed");
      int open[6];
      computeOpen(open);
      aiLearn(AI_R_REJECT, false, open);
      gWallHeat = 1.0f;
      logf_("MOVE", "rejected: %s", msg);
      gNextMoveMs = millis() + MOVE_PACING_MS;
    }
  }
}

static void handleWallHit(JsonDocument& doc) {
  // reply to our move: a wall PoW challenge is pending server-side.
  gAwait = AWAIT_NONE;
  gAwaitFails = 0;
  if (!doc["movenonce"].isNull()) gNonce = doc["movenonce"].as<int64_t>();
  if (!doc["growthcount"].isNull()) gGrowth = doc["growthcount"].as<int64_t>();

  const char* seed = doc["seed"] | (const char*)"";
  int diff = doc["difficulty"] | 5;
  if (!*seed) { requestResync("wall_hit without seed"); return; }
  if (strlen(seed) >= sizeof(gPowSeed)) {
    logf_("POW", "challenge seed too long (%u bytes)", (unsigned)strlen(seed));
    doReconnect("oversized PoW seed");
    return;
  }
  // Repeat of the challenge we're already solving (e.g. stale in-flight
  // move answered while _pending_pow was set): keep our nonce progress.
  if (gPowPending && strcmp(gPowSeed, seed) == 0) {
    if (diff == gPowDiff) { gAwaitFails = 0; return; }
    if (diff < 1) diff = 1;
    if (diff > 64) diff = 64;
    gPowDiff = diff;   // same seed, retargeted difficulty: keep progress
    gAwaitFails = 0;
    return;
  }
  strncpy(gPowSeed, seed, sizeof(gPowSeed) - 1);
  gPowSeed[sizeof(gPowSeed) - 1] = 0;
  gPowDiff = diff;
  if (gPowDiff < 1) gPowDiff = 1;
  if (gPowDiff > 64) gPowDiff = 64;
  gPowPending = true;
  gPowSolved = false;
  gPowNonce = 0;
  gPowStartMs = millis();

  int open[6];
  computeOpen(open);
  aiLearn(AI_R_WALL, false, open);
  gWallHeat = 1.0f;
  logf_("POW", "wall hit, difficulty=%d", gPowDiff);
}

static void handleWallSolved(JsonDocument& doc) {
  gAwait = AWAIT_NONE;
  gAwaitFails = 0;
  bool accepted = doc["accepted"] | false;
  if (!doc["movenonce"].isNull()) gNonce = doc["movenonce"].as<int64_t>();
  if (!doc["growthcount"].isNull()) gGrowth = doc["growthcount"].as<int64_t>();
  if (!accepted) {
    logf_("POW", "solve REJECTED");
    requestResync("pow rejected");
    return;
  }
  bool caught = doc["caught"] | false;
  logf_("POW", "solved OK%s", caught ? " (ghost caught us)" : "");
  // The accepted reply already carries the authoritative post-solve
  // state (position/goal/size/maze, sealed walls baked in) — adopt it
  // directly and skip a full get_maze_state round trip. Fall back to
  // resync if the reply is incomplete.
  JsonVariantConst arr = doc["maze"].as<JsonVariantConst>();
  JsonArrayConst pos = doc["position"].as<JsonArrayConst>();
  JsonArrayConst go = doc["goal"].as<JsonArrayConst>();
  int size = doc["size"] | 0;
  if (!arr.isNull() && adoptMazeArr(arr, size)) {
    int8_t nextCur[3], nextGoal[3];
    if (!readMazeCoord(pos, size, nextCur) || !readMazeCoord(go, size, nextGoal)) {
      logf_("POW", "wall_hit_solved has invalid position/goal coordinates");
      doReconnect("invalid wall solve coordinates");
      return;
    }
    memcpy(gCur, nextCur, sizeof(gCur));
    memcpy(gGoal, nextGoal, sizeof(gGoal));
    gHasMaze = true;
    if (gPhase != PH_MINE) gPhase = PH_MINE;
    gHasPrev = false;
    gNoPathCount = 0;
    if (caught) resetRoundState(true);
    logf_("SYNC", "adopted post-solve pos=(%d,%d,%d) goal=(%d,%d,%d)",
          gCur[0], gCur[1], gCur[2], gGoal[0], gGoal[1], gGoal[2]);
    gNextMoveMs = millis() + MOVE_PACING_MS;
  } else if (gMazeTooBig) {
    waitForSupportedMaze("wall_hit_solved");
  } else {
    requestResync("after wall solve");
  }
}

static void handleMessage(const char* payload, size_t len) {
  gLastFrameMs = millis();
  if (!payload || len == 0 || len > MCX_MAX_JSON_BYTES) {
    logf_("RX", "ignored invalid text frame size=%u", (unsigned)len);
    return;
  }
  if (!mcxValidUtf8((const uint8_t*)payload, len)) {
    char head[49];
    const size_t take = len < 24 ? len : 24;
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < take; ++i) {
      uint8_t b = (uint8_t)payload[i];
      head[2 * i] = hx[b >> 4];
      head[2 * i + 1] = hx[b & 0x0F];
    }
    head[2 * take] = 0;
    logf_("RX", "rejected invalid UTF-8 frame (len=%u, head_hex=%s)",
          (unsigned)len, head);
    return;
  }

  // produce_block needs byte-exact canonical JSON -> custom parser
  static const char kProduce[] = "\"produce_block\"";
  if (len >= sizeof(kProduce)) {
    for (size_t i = 0; i + sizeof(kProduce) - 1 <= len; i++) {
      if (memcmp(payload + i, kProduce, sizeof(kProduce) - 1) == 0) {
        handleProduceBlock(payload, len);
        return;
      }
    }
  }

#if defined(ARDUINOJSON_VERSION_MAJOR) && ARDUINOJSON_VERSION_MAJOR >= 7
  JsonDocument doc;
#else
  DynamicJsonDocument doc((size_t)len * 2 + 2048);
#endif
  DeserializationError err = deserializeJson(doc, payload, len);
  if (err) {
    logf_("RX", "JSON error: %s (len=%u); check the installed WebSockets library frame limit",
          err.c_str(), (unsigned)len);
    return;
  }
  const char* type = doc["type"] | "";
  if (!*type) return;

  if (strcmp(type, "registered") == 0) {
    gRegistered = true;
    gRegFailStreak = 0;
    gPhase = PH_WAIT_MAZE;
    gConnectedMs = millis();
    gMazeAskDone = false;
    logf_("REG", "registered OK (balance %lld)", (long long)(doc["confirmed_balance"] | 0LL));
  } else if (strcmp(type, "registration_failed") == 0) {
    gRegFailStreak++;
    logf_("REG", "FAILED: %s (streak %d)", doc["error"] | "?", gRegFailStreak);
    doReconnect("registration failed");
  } else if (strcmp(type, "memory_challenge_request") == 0) {
    const char* seed = doc["seed"] | (const char*)"";
    uint32_t memSize = (uint32_t)(doc["memory_size"] | 8388608);
    size_t sl = strlen(seed);
    size_t outl = 0;
    if (!*seed || sl >= sizeof(gChalSeedB64) ||
        mbedtls_base64_decode(gChalSeed, sizeof(gChalSeed), &outl,
                              (const unsigned char*)seed, sl) != 0 ||
        outl != 32) {
      logf_("CHAL", "bad challenge seed");
      doReconnect("bad challenge");
      return;
    }
    if (memSize > MAX_MEM_CHALLENGE_BYTES) {
      logf_("CHAL", "memory_size %u exceeds cap", (unsigned)memSize);
      doReconnect("challenge too big");
      return;
    }
    memcpy(gChalSeedB64, seed, sl + 1);
    gChalMemSize = memSize;
    gChalProduced = 0;
    gChalCounter = 0;
    if (gChalOuterInit) mbedtls_sha256_free(&gChalOuter);
    mbedtls_sha256_init(&gChalOuter);
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_sha256_starts(&gChalOuter, 0);
#else
    mbedtls_sha256_starts_ret(&gChalOuter, 0);
#endif
    gChalOuterInit = true;
    gChalPending = true;
    gPhase = PH_CHALLENGE;
    logf_("CHAL", "computing %u bytes commitment...", (unsigned)memSize);
  } else if (strcmp(type, "error") == 0) {
    const char* m = doc["message"] | "";
    logf_("RX", "server error: %s", m);
    if (strstr(m, "Maze already in use")) {
      logf_("RX", "HINT: this key/miner_id already has a live session on this "
            "node - use a dedicated ESP key or close the other session.");
      gRegFailStreak = 3;
      doReconnect("maze in use");
    } else if (gPhase == PH_MINE) {
      requestResync("server error");
    }
  } else if (strcmp(type, "maze_init") == 0) {
    handleMazeInit(doc);
  } else if (strcmp(type, "maze_state") == 0) {
    handleMazeState(doc);
  } else if (strcmp(type, "maze_move_ack") == 0) {
    handleMoveAck(doc);
  } else if (strcmp(type, "wall_hit") == 0) {
    handleWallHit(doc);
  } else if (strcmp(type, "wall_hit_solved") == 0) {
    handleWallSolved(doc);
  } else if (strcmp(type, "block_height_update") == 0 ||
             strcmp(type, "block_accepted") == 0 ||
             strcmp(type, "wallet_update") == 0 ||
             strcmp(type, "uptime_ping") == 0) {
    // keepalive / bookkeeping — ignore (frame time already recorded)
  } else {
    logf_("RX", "unhandled type '%s'", type);
  }
}

static void onWsEvent(WStype_t type, uint8_t* payload, size_t len) {
  switch (type) {
    case WStype_CONNECTED: {
      gWsUp = true;
      gConnectedMs = millis();
      gLastFrameMs = millis();
      gMazeAskDone = false;
      logf_("WS", "connected to %s:%d", MCX_NODE_HOST, MCX_NODE_PORT);
      if (!gNtpOk && !gNtpDead) {
        logf_("WS", "NTP not synced yet - refusing register, retrying");
        doReconnect("ntp pending");
        break;
      }
      if (gNtpDead) logf_("WS", "WARNING: registering with unsynced clock (no NTP) - node may reject timestamp");
      sendRegister();
      break;
    }
    case WStype_DISCONNECTED: {
      bool wasUp = gWsUp;
      gWsUp = false;
      gRegistered = false;
      gHasMaze = false;
      gAwait = AWAIT_NONE;
      gChalPending = false;
      if (gChalOuterInit) { mbedtls_sha256_free(&gChalOuter); gChalOuterInit = false; }
      gPowPending = false;
      gHasPrev = false;
      gMazeAskDone = false;
      gPhase = PH_WS;
      // Transport detail, bounded: never %s a raw payload (not guaranteed
      // NUL-terminated). Library redials automatically; no timer to arm.
      logf_("WS", "disconnected (wasUp=%d)", wasUp ? 1 : 0);
      break;
    }
    case WStype_TEXT:
      handleMessage((const char*)payload, len);
      break;
    case WStype_PING:
    case WStype_PONG:
      gLastFrameMs = millis();
      break;
    case WStype_ERROR: {
      // Length-delimited hex prefix: payload is NOT NUL-terminated, so %s
      // would overread into adjacent memory (garbage/crash class).
      char ehex[65];
      size_t ecopy = (payload && len < 32) ? len : (payload ? 32 : 0);
      for (size_t i = 0; i < ecopy; i++) {
        ehex[i * 2] = "0123456789abcdef"[(payload[i] >> 4) & 0xF];
        ehex[i * 2 + 1] = "0123456789abcdef"[payload[i] & 0xF];
      }
      ehex[ecopy * 2] = 0;
      logf_("WS", "socket error len=%u head=%s (TCP refused/reset/DNS/handshake?)",
            (unsigned)len, ecopy ? ehex : "-");
      break;
    }
    default:
      break;
  }
}
// ======= WATCHDOGS =======
static void mcxWdtInit() {
#if defined(ESP_ARDUINO_VERSION) && ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
  esp_task_wdt_config_t cfg;
  cfg.idle_core_mask = 0;
  cfg.trigger_panic = true;
  cfg.timeout_ms = WDT_TIMEOUT_S * 1000;
  if (esp_task_wdt_reconfigure(&cfg) != ESP_OK) esp_task_wdt_init(&cfg);
#else
  (void)esp_task_wdt_init(WDT_TIMEOUT_S, true);   // ignore "already inited"
#endif
  esp_err_t e = esp_task_wdt_add(NULL);           // subscribe loopTask
  if (e != ESP_OK && e != ESP_ERR_INVALID_ARG)
    logf_("WDT", "add failed (%d)", (int)e);
  logf_("WDT", "task watchdog armed (%ds, panic->reboot)", WDT_TIMEOUT_S);
}

static void wifiWatchdog(uint32_t now) {
  if (WiFi.status() == WL_CONNECTED) {
    if (gWifiState != WIFI_UP) {
      logf_("WIFI", "connected, rssi=%d", (int)WiFi.RSSI());
      if (gWsUp) doReconnect("wifi recovered");   // force clean re-register
    }
    gWifiState = WIFI_UP;
    gWifiBackoffMs = 0;
    gWifiRetryAtMs = 0;
    return;
  }
  // not connected
  if (gWifiState == WIFI_UP) {
    // link just dropped
    logf_("WIFI", "link lost");
    gWifiState = WIFI_ATTEMPT;
    gWifiAttemptMs = now;
    if (gWsUp) doReconnect("wifi lost");
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    return;
  }
  if (gWifiState == WIFI_ATTEMPT) {
    if ((now - gWifiAttemptMs) >= WIFI_CONNECT_TIMEOUT_MS) {
      WiFi.disconnect();
      gWifiBackoffMs = (gWifiBackoffMs == 0) ? WS_RECONNECT_MIN_MS : gWifiBackoffMs * 2;
      if (gWifiBackoffMs > WIFI_MAX_BACKOFF_MS) gWifiBackoffMs = WIFI_MAX_BACKOFF_MS;
      gWifiRetryAtMs = now + gWifiBackoffMs;
      gWifiState = WIFI_BACKOFF;
      logf_("WIFI", "attempt failed - next try in %lums", (unsigned long)gWifiBackoffMs);
    }
    return;
  }
  // WIFI_BACKOFF
  if (DUE(gWifiRetryAtMs)) {
    gWifiState = WIFI_ATTEMPT;
    gWifiAttemptMs = now;
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    logf_("WIFI", "retrying connect");
  }
}

static void wsWatchdog(uint32_t now) {
  // silence: no frames (incl. pings) for too long
  if (gWsUp && gRegistered && (now - gLastFrameMs) > WS_SILENCE_TIMEOUT_MS) {
    doReconnect("silence timeout");
    return;
  }
  // register/challenge stall
  if (gWsUp && !gRegistered && gRegisterSentMs != 0 &&
      (now - gRegisterSentMs) > REGISTER_TIMEOUT_MS) {
    doReconnect("register timeout");
    return;
  }
  // waiting for first maze: ask explicitly once, then reconnect —
  // unless the maze is known-oversize (adoptMazeArr said so): then idle
  // loudly until shrink brings it back instead of spinning reconnects.
  if (gWsUp && gRegistered && gPhase == PH_WAIT_MAZE && !gHasMaze &&
      (now - gConnectedMs) > MAZE_WAIT_TIMEOUT_MS) {
    if (gMazeTooBig) {
      static uint32_t lastBigLog = 0;
      if ((now - lastBigLog) > 30000) {
        lastBigLog = now;
        logf_("MAZE", "waiting: chain maze exceeds firmware cap %d; probing for a smaller maze", MAX_MAZE_DIM);
      }
      if (gAwait == AWAIT_NONE) {
        sendGetMazeState();
        gConnectedMs = now;
      }
      // Keep falling through so an outstanding maze-state request reaches the
      // normal await timeout; never hammer the node while a request is pending.
    } else {
      if (!gMazeAskDone) {
        gMazeAskDone = true;
        sendGetMazeState();
        gConnectedMs = now;               // second window for the reply
        return;
      }
      doReconnect("no maze_init");
      return;
    }
  }
  // Reconnects are owned by the library (setReconnectInterval). This branch
  // must NEVER call begin() again (see doReconnect). It only guarantees the
  // one-time begin once WiFi is up, plus a rate-limited "still down" note so
  // a silent stall is distinguishable from a quiet-but-working link.
  if (!gWsUp && WiFi.status() == WL_CONNECTED) {
    wsEnsureBegun();
    static uint32_t lastDownLog = 0;
    if ((now - lastDownLog) > 30000) {
      lastDownLog = now;
      logf_("WS", "link down, library retrying %s:%d/ws (wifi %s, ntp %s)...",
            MCX_NODE_HOST, (int)MCX_NODE_PORT,
            WiFi.localIP().toString().c_str(), gNtpOk ? "ok" : (gNtpDead ? "dead" : "wait"));
    }
  }

  // awaiting-reply timeouts
  if (gAwait != AWAIT_NONE) {
    uint32_t timeout = MOVE_ACK_TIMEOUT_MS;
    if (gAwait == AWAIT_MAZE_STATE) timeout = MAZE_STATE_TIMEOUT_MS;
    else if (gAwait == AWAIT_POW) timeout = POW_ACK_TIMEOUT_MS;
    if ((now - gAwaitStartMs) > timeout) {
      gAwaitFails++;
      logf_("AWAIT", "timeout (kind=%d, fails=%d)", gAwait, gAwaitFails);
      gAwait = AWAIT_NONE;
      if (gAwaitFails >= MAX_CONSECUTIVE_FAILS) {
        gAwaitFails = 0;
        doReconnect("await stall");
      } else if (gPhase == PH_MINE) {
        requestResync("await timeout");
      }
    }
  }
}

static void heapWatchdog(uint32_t now) {
  static uint32_t lastCheck = 0;
  if ((now - lastCheck) < 5000) return;
  lastCheck = now;
  uint32_t h = ESP.getFreeHeap();
  if (h < MIN_FREE_HEAP) {
    logf_("HEAP", "CRITICAL %u < %u - rebooting", (unsigned)h, (unsigned)MIN_FREE_HEAP);
    delay(50);
    ESP.restart();
  }
  if (gPhase == PH_MINE && (now - gLastHbLogMs) > 30000) {
    gLastHbLogMs = now;
    logf_("HB", "heap=%u pos=(%d,%d,%d) nonce=%lld eps=%.2f",
          (unsigned)h, gCur[0], gCur[1], gCur[2], (long long)gNonce, (double)gEps);
  }
}

static void ntpWatchdog(uint32_t now) {
  time_t t = time(nullptr);
  if (t > 1600000000) {
    if (!gNtpOk) logf_("NTP", "synced: %lld", (long long)t);
    gNtpOk = true;
    return;
  }
  if (gNtpWaitStartMs == 0) gNtpWaitStartMs = now;
  if ((now - gNtpWaitStartMs) > NTP_MAX_WAIT_MS) {
    // ISOLATED-LAN: no NTP reachable (offline LAN). Rebooting here used to
    // loop forever; instead proceed WITHOUT time sync and say so loudly.
    // Registration needs +/-120s-accurate time, so expect the node to
    // reject registration until the clock is fixed — but transport,
    // handshake and diagnostics below now work and show the real stage.
    if (!gNtpDead) {
      gNtpDead = true;
      logf_("NTP", "no sync after %lums - proceeding WITHOUT time sync "
            "(registration needs valid time; fix NTP for mining)",
            (unsigned long)NTP_MAX_WAIT_MS);
    }
  }
}
// ======= DEFERRED HEAVY WORK (time-sliced) =======
static void challengeTick() {
  if (!gChalPending || !gChalOuterInit) return;
  uint32_t t0 = millis();
  uint8_t inbuf[40], inner[32];
  memcpy(inbuf, gChalSeed, 32);
  while (gChalProduced < gChalMemSize) {
    for (int i = 0; i < 8; i++)
      inbuf[32 + i] = (uint8_t)((gChalCounter >> (56 - 8 * i)) & 0xFF);
    mcxSha256(inbuf, 40, inner);
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_sha256_update(&gChalOuter, inner, 32);
#else
    mbedtls_sha256_update_ret(&gChalOuter, inner, 32);
#endif
    gChalCounter++;
    gChalProduced += 32;
    if ((gChalCounter & 0x3FF) == 0 && (millis() - t0) > 8) break;
  }
  if (gChalProduced >= gChalMemSize) {
    uint8_t digest[32];
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_sha256_finish(&gChalOuter, digest);
#else
    mbedtls_sha256_finish_ret(&gChalOuter, digest);
#endif
    mbedtls_sha256_free(&gChalOuter);
    gChalOuterInit = false;
    gChalPending = false;
    char b64[48];
    size_t olen = 0;
    mbedtls_base64_encode((unsigned char*)b64, sizeof(b64), &olen, digest, 32);
    b64[olen] = 0;
    char out[320];
    int n = snprintf(out, sizeof(out),
        "{\"type\":\"memory_challenge_response\",\"miner_id\":\"%s\","
        "\"seed\":\"%s\",\"commitment\":\"%s\"}",
        gMinerId, gChalSeedB64, b64);
    if (n <= 0 || n >= (int)sizeof(out) || !wsSend(out, (size_t)n)) {
      logf_("CHAL", "commitment response TX failed");
      doReconnect("challenge response TX failed");
      return;
    }
    gRegisterSentMs = millis();   // reuse register timer for the reply window
    gPhase = PH_REGISTER;
    logf_("CHAL", "commitment response queued (%u bytes hashed)", (unsigned)gChalMemSize);
  }
}

static void powTick() {
  if (!gPowPending) return;
  uint32_t now = millis();
  if ((now - gPowStartMs) > POW_MAX_SOLVE_MS) {
    logf_("POW", "solve timeout after %lums", (unsigned long)POW_MAX_SOLVE_MS);
    gPowPending = false;
    requestResync("pow timeout");
    return;
  }
  // top `gPowDiff` bits of sha256(seed || decimal(nonce)) must be zero
  char seedN[176];
  int seedLen = snprintf(seedN, sizeof(seedN), "%s", gPowSeed);
  uint32_t t0 = now;
  while (!gPowSolved && (millis() - t0) < 8) {
    char tail[24];
    int tn = snprintf(tail, sizeof(tail), "%llu", (unsigned long long)gPowNonce);
    uint8_t digest[32];
    // sha256(seed || nonce) computed in two updates
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, (const uint8_t*)seedN, (size_t)seedLen);
    mbedtls_sha256_update(&c, (const uint8_t*)tail, (size_t)tn);
    mbedtls_sha256_finish(&c, digest);
#else
    mbedtls_sha256_starts_ret(&c, 0);
    mbedtls_sha256_update_ret(&c, (const uint8_t*)seedN, (size_t)seedLen);
    mbedtls_sha256_update_ret(&c, (const uint8_t*)tail, (size_t)tn);
    mbedtls_sha256_finish_ret(&c, digest);
#endif
    mbedtls_sha256_free(&c);
    // check top `diff` bits zero
    int fullBytes = gPowDiff / 8;
    int remBits = gPowDiff % 8;
    bool ok = true;
    for (int i = 0; i < fullBytes && ok; i++)
      if (digest[i] != 0) ok = false;
    if (ok && remBits && (digest[fullBytes] >> (8 - remBits)) != 0) ok = false;
    if (ok) { gPowSolved = true; break; }
    gPowNonce++;
    if ((gPowNonce & 0x3FF) == 0) esp_task_wdt_reset();
  }
  if (gPowSolved) {
    gPowPending = false;
    logf_("POW", "solved nonce=%llu", (unsigned long long)gPowNonce);
    sendWallSolve();
  }
}
// ======= MINING TICK =======
static void miningTick(uint32_t now) {
  if (gPhase != PH_MINE || !gHasMaze || gAwait != AWAIT_NONE) return;
  // A wall-hit PoW is being solved: the node rejects ALL moves with a
  // repeat wall_hit while _pending_pow is set, so sending would only
  // reset our PoW nonce counter (livelock). Wait for wall_hit_solved.
  if (gPowPending) return;

#if MCX_HAVE_LLM
  if (gLlmNeedScore) {
    gLlmNeedScore = false;
    if (gLlmReady) gLlmPref = (int8_t)llmScoreDirections();
    else gLlmPref = -1;
  }
#endif

  if ((int32_t)(now - gNextMoveMs) < 0) return;

  int nextCell[3];
  int rc = bfsFirstStep(gCur, gGoal, nextCell);
  if (rc < 0) {
    // no path (growth/seal divergence): resync, limited retries
    gNoPathCount++;
    if (gNoPathCount > NO_PATH_RESYNC_LIMIT) {
      gNoPathCount = 0;
      doReconnect("no path (limit)");
    } else {
      requestResync("no path");
    }
    gNextMoveMs = now + 3000;
    return;
  }
  if (rc == 0) {
    // local view says cur == goal — server state must advance us
    requestResync("cur == goal");
    gNextMoveMs = now + 2000;
    return;
  }

  int bfsDir = -1;
  int dx = nextCell[0] - gCur[0];
  int dy = nextCell[1] - gCur[1];
  int dz = nextCell[2] - gCur[2];
  for (int d = 0; d < 6; d++)
    if (kDirDx[d] == dx && kDirDy[d] == dy && kDirDz[d] == dz) { bfsDir = d; break; }
  if (bfsDir < 0) { gNextMoveMs = now + 1000; return; }

  int open[6];
  computeOpen(open);
  int dir = aiChoose(bfsDir, open);
  if (dir < 0) { gNextMoveMs = now + 500; return; }

  const int targetX = gCur[0] + kDirDx[dir];
  const int targetY = gCur[1] + kDirDy[dir];
  const int targetZ = gCur[2] + kDirDz[dir];
  if (!inBounds(targetX, targetY, targetZ) || !isOpen(targetX, targetY, targetZ)) {
    gHasPrev = false;
    requestResync("planner selected invalid local step");
    gNextMoveMs = millis() + 1000;
    return;
  }

  // remember learning context for the ack
  gPrevA = dir;
  aiFeatures(open, dir, gPrevPhi);
  gHasPrev = true;
  gPrevDist = manhattan(gCur, gGoal);

  if (!sendMove(dir)) {
    gHasPrev = false;
    gNextMoveMs = now + 1000;
    return;
  }
  gAwait = AWAIT_MOVE;
  gAwaitStartMs = now;
  logf_("MOVE", "-> %s from=(%d,%d,%d) to=(%d,%d,%d) dim=%d bfs=%s eps=%.2f llm=%d",
        kDirName[dir], gCur[0], gCur[1], gCur[2],
        targetX, targetY, targetZ, gDim, kDirName[bfsDir],
        (double)gEps, (int)gLlmPref);
}
// ======= LOOP =======
static void identitySelfPrint() {
  logf_("BOOT", "Munex ESP miner - chain=%d node=%s:%d", MCX_CHAIN_ID,
        MCX_NODE_HOST, MCX_NODE_PORT);
  logf_("BOOT", "heap=%u psram=%u", (unsigned)ESP.getFreeHeap(),
        (unsigned)ESP.getFreePsram());
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  identitySelfPrint();
  if (!WIFI_SSID[0] || !WIFI_PASSWORD[0] ||
      strcmp(WIFI_SSID, "CHANGE_ME_WIFI_SSID") == 0 ||
      strcmp(WIFI_PASSWORD, "CHANGE_ME_WIFI_PASSWORD") == 0) {
    logf_("BOOT", "ERROR: set WIFI_SSID and WIFI_PASSWORD in esp.ino before flashing");
    while (true) { delay(1000); }
  }

  uECC_set_rng(mcxUeccRng);

  if (!deriveIdentity(nullptr)) {
    logf_("BOOT", "identity failure - halt (fix MCX_PRIVKEY_HEX / micro-ecc secp256k1)");
    while (true) { delay(1000); }
  }

  mcxWdtInit();

  WiFi.persistent(false);                // credentials stay in RAM
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);          // watchdog owns reconnection
  gWifiState = WIFI_ATTEMPT;
  gWifiAttemptMs = millis();
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  logf_("WIFI", "connecting to %s ...", WIFI_SSID);

  configTime(0, 0, "pool.ntp.org", "time.google.com", "time.nist.gov");
  gNtpWaitStartMs = millis();
  gPhase = PH_WIFI;

#if MCX_HAVE_LLM
  gLlmReady = llmInit();
#else
  logf_("LLM", "headers not found - learner-only mode");
#endif

  webSocket.onEvent(onWsEvent);
  // Single reconnect mechanism: the LIBRARY owns ordinary retries at
  // WS_RECONNECT_MIN_MS. The watchdog only handles application-level stalls
  // (silence/register/maze/await timeouts) via doReconnect()->disconnect().
  webSocket.setReconnectInterval(WS_RECONNECT_MIN_MS);
  // initial begin happens once in wsEnsureBegun as soon as WiFi is up
  // (NTP gates REGISTER only, never the TCP client itself)

  logf_("BOOT", "setup complete");
}

void loop() {
  esp_task_wdt_reset();
  uint32_t now = millis();

  // phase progression: WiFi -> NTP -> WS (armed once per transition)
  if (gPhase == PH_WIFI && WiFi.status() == WL_CONNECTED) {
    gPhase = PH_NTP;
    logf_("PHASE", "wifi up -> waiting for NTP");
  } else if (gPhase == PH_NTP && (gNtpOk || gNtpDead)) {
    gPhase = PH_WS;
    logf_("PHASE", "ntp ok -> websocket connecting");
  }

  wifiWatchdog(now);
  ntpWatchdog(now);
  wsWatchdog(now);

  webSocket.loop();

  challengeTick();
  powTick();
  miningTick(now);
  pingTick(now);
  heapWatchdog(now);

  delay(2);
}
