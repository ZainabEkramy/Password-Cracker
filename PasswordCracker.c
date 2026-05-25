#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <omp.h>

/* ============== FULL SHA-256 ============== */
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, t1, t2, m[64];
    for (i = 0; i < 16; ++i) m[i] = (data[i*4] << 24) | (data[i*4+1] << 16) | (data[i*4+2] << 8) | data[i*4+3];
    for (; i < 64; ++i) m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256(const char *msg, uint8_t hash[32]) {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t len = strlen(msg);
    size_t bitlen = len * 8;
    size_t padded_len = ((len + 9) / 64 + 1) * 64;
    uint8_t *data = calloc(padded_len, 1);
    memcpy(data, msg, len);
    data[len] = 0x80;
    for (int i = 0; i < 8; ++i) data[padded_len - 8 + i] = (bitlen >> (56 - 8*i)) & 0xff;
    for (size_t i = 0; i < padded_len; i += 64) sha256_transform(state, data + i);
    free(data);
    for (int i = 0; i < 8; ++i) {
        hash[i*4]   = (state[i] >> 24) & 0xff;
        hash[i*4+1] = (state[i] >> 16) & 0xff;
        hash[i*4+2] = (state[i] >> 8)  & 0xff;
        hash[i*4+3] = state[i]         & 0xff;
    }
}

void to_hex(const uint8_t hash[32], char hex[65]) {
    for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", hash[i]);
    hex[64] = '\0';
}

/* ============== VARIABLES ============== */
char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
char target_hash_hex[65];
volatile int found = 0;
char found_password[100] = "";
const char *dict_file = "dictionary.txt";

/* ============== HELPER ============== */
long get_total_combinations(int length) {
    long total = 1;
    long cs = strlen(charset);
    for (int i = 0; i < length; ++i) total *= cs;
    return total;
}

/* ============== BENCHMARK (for demo) ============== */
double benchmark_brute_force(int length, int num_threads) {
    long total = get_total_combinations(length);
    long test_count = (total > 50000000L) ? 50000000L : total;

    double start = omp_get_wtime();

    #pragma omp parallel for schedule(static) num_threads(num_threads)
    for (long index = 0; index < test_count; ++index) {
        char guess[20] = {0};
        long n = index;
        for (int pos = length - 1; pos >= 0; --pos) {
            guess[pos] = charset[n % 62];
            n /= 62;
        }
        uint8_t h[32];
        sha256(guess, h);
    }
    return omp_get_wtime() - start;
}

/* ============== SHOW SPEEDUP DEMO ============== */
void show_speedup_demo(int demo_length) {
    printf("\n=== PARALLEL SPEEDUP DEMO (Length %d) ===\n", demo_length);
    printf("Threads | Combinations    | Time (sec) | Speedup   | Efficiency\n");
    printf("--------|-----------------|------------|-----------|-----------\n");

    double serial_time = benchmark_brute_force(demo_length, 1);
    long displayed = get_total_combinations(demo_length);
    if (displayed > 50000000L) displayed = 50000000L;

    printf("%7d | %15ld | %10.3f | %9.2fx | %8.2f%%\n", 1, displayed, serial_time, 1.00, 100.00);

    int max_th = omp_get_max_threads();
    for (int th = 2; th <= max_th; th *= 2) {
        double time = benchmark_brute_force(demo_length, th);
        double speedup = serial_time / time;
        double eff = (speedup / th) * 100.0;
        printf("%7d | %15ld | %10.3f | %9.2fx | %8.2f%%\n", th, displayed, time, speedup, eff);
    }
    printf("==================================================\n\n");
}

/* ============== BRUTE FORCE LENGTH ============== */
double brute_force_length(int length, int num_threads) {
    long total = get_total_combinations(length);
    double start = omp_get_wtime();

    #pragma omp parallel for schedule(static) num_threads(num_threads)
    for (long index = 0; index < total; ++index) {
        if (found) continue;

        char guess[20] = {0};
        long n = index;
        for (int pos = length - 1; pos >= 0; --pos) {
            guess[pos] = charset[n % 62];
            n /= 62;
        }
        guess[length] = '\0';

        uint8_t h[32];
        char hex[65];
        sha256(guess, h);
        to_hex(h, hex);

        if (strcmp(hex, target_hash_hex) == 0) {
            #pragma omp critical
            {
                if (!found) {
                    found = 1;
                    strcpy(found_password, guess);
                }
            }
        }
    }
    return omp_get_wtime() - start;
}

/* ============== DICTIONARY ATTACK ============== */
int dictionary_attack() {
    FILE *fp = fopen(dict_file, "r");
    if (!fp) {
        printf("Warning: %s not found - skipping dictionary attack\n", dict_file);
        return 0;
    }

    char **words = malloc(200000 * sizeof(char*));
    int word_count = 0;
    char line[100];
    while (fgets(line, sizeof(line), fp) && word_count < 200000) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) > 0) {
            words[word_count] = strdup(line);
            word_count++;
        }
    }
    fclose(fp);

    printf("Dictionary Attack: Testing %d common passwords...\n", word_count);
    double start = omp_get_wtime();

    #pragma omp parallel for schedule(dynamic)
    for (int i = 0; i < word_count; ++i) {
        if (found) continue;
        uint8_t h[32];
        char hex[65];
        sha256(words[i], h);
        to_hex(h, hex);
        if (strcmp(hex, target_hash_hex) == 0) {
            #pragma omp critical
            {
                if (!found) {
                    found = 1;
                    strcpy(found_password, words[i]);
                }
            }
        }
    }

    for (int i = 0; i < word_count; ++i) free(words[i]);
    free(words);

    if (found) {
        printf("\n*** PASSWORD CRACKED via DICTIONARY in %.3f sec: %s ***\n",
               omp_get_wtime() - start, found_password);
        return 1;
    }
    printf("Not in dictionary (%.3f sec)\n\n", omp_get_wtime() - start);
    return 0;
}

int main() {
    char password[100];
    uint8_t hash[32];

    printf("=== Parallel Password Cracker ===\n");
    printf("Enter password to crack: ");
    scanf("%99s", password);

    sha256(password, hash);
    to_hex(hash, target_hash_hex);
    printf("\nTarget Hash: %s\n\n", target_hash_hex);

    show_speedup_demo(4);

    found = 0;
    if (dictionary_attack()) {
        return 0;
    }

    found = 0;
    int cracked = 0;
    for (int len = 1; len <= 8 && !cracked; ++len) {
        printf("Trying brute force length %d (%ld combos)...\n", len, get_total_combinations(len));
        double time = brute_force_length(len, omp_get_max_threads());
        if (found) {
            printf("\n*** PASSWORD CRACKED via BRUTE FORCE: %s ***\n", found_password);
            printf("Time: %.3f seconds\n", time);
            cracked = 1;
        }
    }

    if (!cracked) {
        printf("\nPassword is STRONG - not cracked.\n");
    }
    return 0;
}