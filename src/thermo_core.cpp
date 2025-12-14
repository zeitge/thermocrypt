/*
THERMOCRYPT CORE v1.0.0
Licensed under the MIT License.

MIT License

Copyright (c) 2025 Herman Nythe

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

---------------------------------------------------------------------------
DISCLAIMER OF WARRANTY & SCOPE
---------------------------------------------------------------------------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF DATA OR CRYPTOGRAPHIC 
FAILURE), OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE 
USE OR OTHER DEALINGS IN THE SOFTWARE.

THIS SOFTWARE IS A RESEARCH PROTOTYPE. IT HAS NOT UNDERGONE A FORMAL 
SECURITY AUDIT. USE FOR CRITICAL SECURITY APPLICATIONS IS AT THE USER'S 
SOLE RISK.

---------------------------------------------------------------------------
IMPLEMENTATION SCOPE & LIMITATIONS
---------------------------------------------------------------------------
This software is a research prototype implementing Hybrid Post-Quantum 
Cryptography (ML-KEM-768 + X25519) with Hardware Binding.

1. Verified Environment: Linux (x86_64), Windows.
2. Verified Binding: Disk-mode (Argon2id), tpm (Linux)

COMPILATION (Linux Example):
g++ -o thermo_core thermo_core.cpp -std=c++17 -O3 \
-DENABLE_TPM \
-lsodium -loqs -ltss2-esys -ltss2-mu -ltss2-tctildr

*/

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <sodium.h>
#include <oqs/oqs.h>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <thread>
#include <regex>
#include <memory>
#include <csignal>

#ifdef _WIN32
    #include <windows.h>
    #include <conio.h>
    #include <io.h>
    #include <fcntl.h>
#else
    #include <sys/resource.h>
    #include <sys/ptrace.h>
    #include <sys/mman.h>
    #include <termios.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <fcntl.h>
#endif

#ifdef ENABLE_TPM
    #include <tss2/tss2_esys.h>
    #include <tss2/tss2_mu.h>
    #include <tss2/tss2_tctildr.h>
#endif

using namespace std;
namespace fs = std::filesystem;
const string HEADER_MAGIC_V1 = "THERMO_V1";
const string IDENTITY_EXT = ".thermoid";
const string VAULT_FILENAME = "resonance.vault";
const size_t CHUNK_SIZE = 64 * 1024;
string KEY_DIR = "keys/";
bool GLOBAL_RATE_LIMIT = false;
string ARGON_LEVEL = "interactive";
bool NO_PROGRESS = false;
size_t STREAM_SIZE_HINT = 0;
enum class BindingType : uint8_t { Disk = 0, TPM = 1 };
BindingType CURRENT_BINDING = BindingType::Disk;

#ifdef ENABLE_TPM
const TPM2_HANDLE TPM_PERSISTENT_HANDLE = 0x81018100;
#else
const uint32_t TPM_PERSISTENT_HANDLE = 0;
#endif

unsigned long long get_opslimit() {
    if (ARGON_LEVEL == "sensitive") return crypto_pwhash_OPSLIMIT_SENSITIVE;
    if (ARGON_LEVEL == "moderate") return crypto_pwhash_OPSLIMIT_MODERATE;
    return crypto_pwhash_OPSLIMIT_INTERACTIVE;
}

size_t get_memlimit() {
    if (ARGON_LEVEL == "sensitive") return crypto_pwhash_MEMLIMIT_SENSITIVE;
    if (ARGON_LEVEL == "moderate") return crypto_pwhash_MEMLIMIT_MODERATE;
    return crypto_pwhash_MEMLIMIT_INTERACTIVE;
}

uint8_t get_argon_level_byte() {
    if (ARGON_LEVEL == "sensitive") return 2;
    if (ARGON_LEVEL == "moderate") return 1;
    return 0;
}

void get_argon_params_from_byte(uint8_t level_byte, unsigned long long& ops, size_t& mem) {
    if (level_byte == 2) {
        ops = crypto_pwhash_OPSLIMIT_SENSITIVE;
        mem = crypto_pwhash_MEMLIMIT_SENSITIVE;
    } else if (level_byte == 1) {
        ops = crypto_pwhash_OPSLIMIT_MODERATE;
        mem = crypto_pwhash_MEMLIMIT_MODERATE;
    } else {
        ops = crypto_pwhash_OPSLIMIT_INTERACTIVE;
        mem = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    }
}

#pragma pack(push, 1)
struct ThermoHeader {
    uint8_t magic[9];
    uint8_t format_version;
    uint8_t binding_type;
    uint8_t pq_algo; uint8_t cl_algo; uint8_t sig_algo;
    uint8_t argon_level;     // 0 = interactive, 1 = moderate, 2 = sensitive
    uint8_t reserved[1];
    uint64_t timestamp;
    uint8_t fingerprint[32];
    uint8_t hmac[32];
};
#pragma pack(pop)

struct OQSKEMDeleter { void operator()(OQS_KEM* p) { if(p) OQS_KEM_free(p); } };
using OqsKemPtr = std::unique_ptr<OQS_KEM, OQSKEMDeleter>;
struct OQSSIGDeleter { void operator()(OQS_SIG* p) { if(p) OQS_SIG_free(p); } };
using OqsSigPtr = std::unique_ptr<OQS_SIG, OQSSIGDeleter>;

#ifdef ENABLE_TPM
struct EsysDeleter { void operator()(ESYS_CONTEXT* p) { if(p) Esys_Finalize(&p); } };
using EsysPtr = std::unique_ptr<ESYS_CONTEXT, EsysDeleter>;
#endif

class SecretString {
    string s;
public:
    SecretString() = default;
    explicit SecretString(const string& str) : s(str) { if (!s.empty()) sodium_mlock(s.data(), s.size()); }
    ~SecretString() { if (!s.empty()) { sodium_memzero(&s[0], s.size()); sodium_munlock(s.data(), s.size()); } }
    const string& get() const { return s; }
    string& get() { return s; }
};

struct SecureBuffer {
    vector<uint8_t> data;
    SecureBuffer(size_t size) : data(size) { if (size > 0) sodium_mlock(data.data(), size); }
    ~SecureBuffer() { if (!data.empty()) { sodium_memzero(data.data(), data.size()); sodium_munlock(data.data(), data.size()); } }
    uint8_t* ptr() { return data.data(); }
    const uint8_t* ptr() const { return data.data(); }
    size_t size() const { return data.size(); }
};

string resolve_safe_path(const string& path, bool input_mode = false) {
    try {
        fs::path p(path);
        if (fs::is_symlink(p)) {
            throw runtime_error("Security Risk: Path is a symlink (" + path + ")");
        }

        if (!input_mode && fs::exists(p) && fs::is_symlink(p)) {
            throw runtime_error("Security Risk: Cannot overwrite a symlink");
        }
        fs::path abs_path = fs::absolute(p);
        string s_path = abs_path.string();
        string lower = s_path;
        transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("/etc/") == 0 || lower.find("/proc/") == 0 || lower.find("/sys/") == 0 ||
            lower.find("/dev/") == 0 || lower.find("/.ssh") != string::npos || lower.find("/root") == 0) {
            throw runtime_error("Access to protected system path denied.");
        }
#ifdef _WIN32
        if (lower.find("c:\\windows\\") != string::npos || lower.find("system32") != string::npos) {
            throw runtime_error("Access to Windows system directory denied.");
        }
#endif
        if (input_mode && !fs::exists(abs_path)) throw runtime_error("File not found: " + path);
        return s_path;
    } catch (const fs::filesystem_error& e) {
        throw runtime_error("Invalid path: " + string(e.what()));
    }
}

void set_secure_permissions(const string& path) {
#ifndef _WIN32
    chmod(path.c_str(), S_IRUSR | S_IWUSR);
#endif
}

bool is_valid_identity_name(const string& name) {
    return regex_match(name, regex("^[a-zA-Z0-9_]+$"));
}

void enforce_rate_limit() {
    if (GLOBAL_RATE_LIMIT) this_thread::sleep_for(chrono::seconds(1));
}

void report_progress(size_t current, size_t total) {
    if (NO_PROGRESS) return;
    static size_t last_bytes = 0;
    static auto start = chrono::steady_clock::now();
    if (current < last_bytes) { start = chrono::steady_clock::now(); last_bytes = 0; }
    auto now = chrono::steady_clock::now();
    auto ms = chrono::duration_cast<chrono::milliseconds>(now - start).count();
    if (ms > 500 && (current - last_bytes > 1024*1024 || total > 0)) {
        double speed = ms > 0 ? (double)(current - last_bytes) / (ms / 1000.0) : 0;
        long long eta = (total > 0 && speed > 0.001) ? (long long)((total - current) / speed) : -1;
        cerr << "PROGRESS_METRICS:" << (size_t)speed << ":" << eta << endl;
        if (total > 0) cerr << "PROGRESS:" << (int)((double)current / total * 100.0) << endl;
        cerr.flush();
        last_bytes = current;
        start = now;
    }
}

void get_password_silent(string& out, const string& prompt) {
    cerr << prompt << flush;
    out.clear();
#ifdef _WIN32
    if (!_isatty(_fileno(stdin))) {
        getline(cin, out);
        if (!out.empty() && out.back() == '\r') out.pop_back();
    } else {
        char ch;
        while ((ch = _getch()) != '\r') {
            if (ch == '\b' && !out.empty()) {
                out.pop_back();
                cerr << "\b \b";
            } else if (ch != '\b') {
                out += ch;
                cerr << "*";
            }
        }
        cerr << endl;
    }
#else
    termios oldt{}, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    getline(cin, out);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    cerr << endl;
#endif
    size_t start = out.find_first_not_of(" \t\r\n");
    size_t end = out.find_last_not_of(" \t\r\n");
    if (start != string::npos) out = out.substr(start, end - start + 1);
    else out.clear();
}

SecureBuffer read_file_secure(const string& f) {
    string safe = resolve_safe_path(f, true);
    ifstream in(safe, ios::binary | ios::ate);
    if (!in) throw runtime_error("Cannot open file: " + f);
    size_t sz = in.tellg();
    in.seekg(0);
    SecureBuffer buf(sz);
    in.read((char*)buf.ptr(), sz);
    return buf;
}

void clean_stale_artifacts() {
    if (!fs::exists(KEY_DIR)) return;
    auto now = fs::file_time_type::clock::now();
    for (const auto& entry : fs::directory_iterator(KEY_DIR)) {
        string ext = entry.path().extension().string();
        if (ext == ".lock" || ext == ".tmp") {
            try {
                if (chrono::duration_cast<chrono::minutes>(now - fs::last_write_time(entry)).count() > 60) {
                    fs::remove(entry);
                }
            } catch (...) {}
        }
    }
}

class HardwareBindingManager {
public:
    static vector<uint8_t> generate_keypair(BindingType type, const vector<uint8_t>& payload);
    static vector<uint8_t> decapsulate(const vector<uint8_t>& ct, BindingType type);
    static bool is_available(BindingType type);
};

vector<uint8_t> HardwareBindingManager::generate_keypair(BindingType type, const vector<uint8_t>& payload) {
    if (type == BindingType::Disk) return {};

    if (type == BindingType::TPM) {
#ifdef ENABLE_TPM
        ESYS_CONTEXT* ctx_raw = nullptr;
        if (Esys_Initialize(&ctx_raw, nullptr, nullptr) != TSS2_RC_SUCCESS) throw runtime_error("TPM initialization failed");
        EsysPtr ctx(ctx_raw);

        TPMS_CAPABILITY_DATA* capData = nullptr;
        bool exists = false;
        
        TSS2_RC rc = Esys_GetCapability(ctx.get(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                        TPM2_CAP_HANDLES, TPM_PERSISTENT_HANDLE, 1,
                                        nullptr, &capData);
        
        if (rc == TSS2_RC_SUCCESS && capData->data.handles.count > 0) {
            if (capData->data.handles.handle[0] == TPM_PERSISTENT_HANDLE) {
                exists = true;
            }
        }
        Esys_Free(capData);

        if (exists) {
            throw runtime_error("TPM key already exists. Run 'tpm2_evictcontrol -C o -c 0x81018100' to clear it.");
        }

        TPM2B_PUBLIC inPublic = {0};
        inPublic.publicArea.type = TPM2_ALG_RSA;
        inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
        inPublic.publicArea.objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
        inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic.publicArea.unique.rsa.size = 0;

        TPM2B_SENSITIVE_CREATE inSensitive = {0};
        TPM2B_DATA outsideInfo = {0};
        TPML_PCR_SELECTION creationPCR = {0};
        ESYS_TR keyHandle = ESYS_TR_NONE;
        TPM2B_PUBLIC* outPublic = nullptr;

        if (Esys_CreatePrimary(ctx.get(), ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               &inSensitive, &inPublic, &outsideInfo, &creationPCR, 
                               &keyHandle, &outPublic, nullptr, nullptr, nullptr) != TSS2_RC_SUCCESS) {
            throw runtime_error("TPM CreatePrimary failed");
        }
        free(outPublic);

        TPM2B_PUBLIC_KEY_RSA message = {0};
        if (payload.size() > sizeof(message.buffer)) {
             Esys_FlushContext(ctx.get(), keyHandle);
             throw runtime_error("Payload too large for TPM");
        }
        message.size = payload.size();
        memcpy(message.buffer, payload.data(), payload.size());

        TPMT_RSA_DECRYPT scheme{};
        scheme.scheme = TPM2_ALG_OAEP;
        scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;
        TPM2B_DATA label = {0};
        TPM2B_PUBLIC_KEY_RSA* outCipher = nullptr;

        if (Esys_RSA_Encrypt(ctx.get(), keyHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                             &message, &scheme, &label, &outCipher) != TSS2_RC_SUCCESS) {
            Esys_FlushContext(ctx.get(), keyHandle);
            throw runtime_error("TPM Encryption failed");
        }
        
        vector<uint8_t> encrypted_data(outCipher->buffer, outCipher->buffer + outCipher->size);
        free(outCipher);

        ESYS_TR newHandle = ESYS_TR_NONE;
        if (Esys_EvictControl(ctx.get(), ESYS_TR_RH_OWNER, keyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, TPM_PERSISTENT_HANDLE, &newHandle) != TSS2_RC_SUCCESS) {
            Esys_FlushContext(ctx.get(), keyHandle);
            throw runtime_error("Failed to persist TPM key");
        }
        Esys_FlushContext(ctx.get(), keyHandle);

        return encrypted_data;
#else
        throw runtime_error("TPM not compiled");
#endif
    }
    return {};
}

vector<uint8_t> HardwareBindingManager::decapsulate(const vector<uint8_t>& ct, BindingType type) {
    if (type == BindingType::Disk) throw runtime_error("Decapsulate not used for Disk binding");
    if (type == BindingType::TPM) {
#ifdef ENABLE_TPM
        ESYS_CONTEXT* ctx_raw = nullptr;
        if (Esys_Initialize(&ctx_raw, nullptr, nullptr) != TSS2_RC_SUCCESS) throw runtime_error("TPM init failed");
        EsysPtr ctx(ctx_raw);

        ESYS_TR keyHandle = ESYS_TR_NONE;
        TSS2_RC rc = Esys_TR_FromTPMPublic(ctx.get(), TPM_PERSISTENT_HANDLE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
        if (rc != TSS2_RC_SUCCESS) throw runtime_error("TPM key not found – wrong machine or identity not bound");

        TPM2B_PUBLIC_KEY_RSA inData = {0};
        inData.size = ct.size();
        memcpy(inData.buffer, ct.data(), ct.size());
        
        TPMT_RSA_DECRYPT scheme{};
        scheme.scheme = TPM2_ALG_OAEP;
        scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;
        TPM2B_DATA label = {0};
        TPM2B_PUBLIC_KEY_RSA* outData = nullptr;

        rc = Esys_RSA_Decrypt(ctx.get(), keyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              &inData, &scheme, &label, &outData);
        
        if (rc != TSS2_RC_SUCCESS) throw runtime_error("TPM decryption failed");
        
        vector<uint8_t> result(outData->buffer, outData->buffer + outData->size);
        free(outData);
        return result;
#else
        throw runtime_error("TPM support not compiled");
#endif
    }
    throw runtime_error("Unsupported binding type");
}

bool HardwareBindingManager::is_available(BindingType type) {
    if (type == BindingType::Disk) return true;
#ifdef ENABLE_TPM
    if (type == BindingType::TPM) {
        ESYS_CONTEXT* ctx = nullptr;
        if (Esys_Initialize(&ctx, nullptr, nullptr) == TSS2_RC_SUCCESS) {
            Esys_Finalize(&ctx);
            return true;
        }
        return false;
    }
#endif
    return false;
}

void create_header_v3(ThermoHeader& header, const string& password, BindingType bind_type, const vector<uint8_t>& pub_key) {
    sodium_memzero(&header, sizeof(header));
    memcpy(header.magic, HEADER_MAGIC_V1.c_str(), 9);
    header.format_version = 3;
    header.binding_type = static_cast<uint8_t>(bind_type);
    header.argon_level = get_argon_level_byte();
    header.timestamp = time(nullptr);
    crypto_hash_sha256(header.fingerprint, pub_key.data(), pub_key.size());
    SecureBuffer hmac_key(32);
    if (crypto_pwhash(hmac_key.ptr(), 32, password.c_str(), password.length(), header.fingerprint,
                      get_opslimit(), get_memlimit(), crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw runtime_error("Failed to derive HMAC key");
    }
    crypto_auth_hmacsha256(header.hmac, (const unsigned char*)&header, sizeof(header) - 32, hmac_key.ptr());
}

void verify_header_v3(const ThermoHeader& header, const string& password) {
    if (memcmp(header.magic, HEADER_MAGIC_V1.c_str(), 9) != 0) throw runtime_error("Invalid magic");
    unsigned long long ops;
    size_t mem;
    get_argon_params_from_byte(header.argon_level, ops, mem);
    SecureBuffer hmac_key(32);
    if (crypto_pwhash(hmac_key.ptr(), 32, password.c_str(), password.length(), header.fingerprint,
                      ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw runtime_error("HMAC key derivation failed");
    }
    uint8_t computed[32];
    crypto_auth_hmacsha256(computed, (const unsigned char*)&header, sizeof(header) - 32, hmac_key.ptr());
    if (sodium_memcmp(computed, header.hmac, 32) != 0) {
        enforce_rate_limit();
        throw runtime_error("Header integrity check failed - possible tampering or wrong password");
    }
}

void generate_identity_v4(const string& name) {
    if (sodium_init() < 0) throw runtime_error("Sodium init failed");
    
    OQS_init();
    if (!is_valid_identity_name(name)) throw runtime_error("Identity name must contain only letters, numbers and underscore");
    fs::create_directories(KEY_DIR);
    
    string id_path = KEY_DIR + name + IDENTITY_EXT;
    if (fs::exists(id_path)) throw runtime_error("Identity already exists");
    
    SecretString password;
    string pw;
    get_password_silent(pw, "Set password for identity: ");
    password = SecretString(pw);
    
    OqsKemPtr kem(OQS_KEM_new("ML-KEM-768"));
    if (!kem) throw runtime_error("ML-KEM-768 not available");
    vector<uint8_t> pq_pk(kem->length_public_key);
    
    SecureBuffer pq_sk(kem->length_secret_key);
    OQS_KEM_keypair(kem.get(), pq_pk.data(), pq_sk.ptr());
    vector<uint8_t> x_pk(crypto_box_PUBLICKEYBYTES);
    
    SecureBuffer x_sk(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(x_pk.data(), x_sk.ptr());
    
    OqsSigPtr sig(OQS_SIG_new("ML-DSA-65"));
    if (!sig) throw runtime_error("ML-DSA-65 not available");
    
    vector<uint8_t> sig_pk(sig->length_public_key);
    SecureBuffer sig_sk(sig->length_secret_key);
    OQS_SIG_keypair(sig.get(), sig_pk.data(), sig_sk.ptr());
    vector<uint8_t> pub_keys;
    pub_keys.insert(pub_keys.end(), pq_pk.begin(), pq_pk.end());
    pub_keys.insert(pub_keys.end(), x_pk.begin(), x_pk.end());
    pub_keys.insert(pub_keys.end(), sig_pk.begin(), sig_pk.end());
    
    vector<uint8_t> signature(sig->length_signature);
    size_t sig_len;
    OQS_SIG_sign(sig.get(), signature.data(), &sig_len, pub_keys.data(), pub_keys.size(), sig_sk.ptr());
    
    SecureBuffer priv_blob(pq_sk.size() + x_sk.size() + sig_sk.size());
    uint8_t* p = priv_blob.ptr();
    memcpy(p, pq_sk.ptr(), pq_sk.size()); p += pq_sk.size();
    memcpy(p, x_sk.ptr(), x_sk.size()); p += x_sk.size();
    memcpy(p, sig_sk.ptr(), sig_sk.size());
    
    uint8_t dek[32];
    randombytes_buf(dek, 32);
    SecureBuffer nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.ptr(), nonce.size());
    
    vector<uint8_t> enc_priv(priv_blob.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(enc_priv.data(), &clen, priv_blob.ptr(), priv_blob.size(),
                                              nullptr, 0, nullptr, nonce.ptr(), dek);
    vector<uint8_t> sealed_dek;
    if (CURRENT_BINDING == BindingType::Disk) {
        SecureBuffer salt(crypto_pwhash_SALTBYTES);
        randombytes_buf(salt.ptr(), salt.size());
        SecureBuffer dek_nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(dek_nonce.ptr(), dek_nonce.size());
        SecureBuffer kek(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        if (crypto_pwhash(kek.ptr(), kek.size(), password.get().c_str(), password.get().length(), salt.ptr(),
                          get_opslimit(), get_memlimit(), crypto_pwhash_ALG_ARGON2ID13) != 0) {
            throw runtime_error("Argon2id failed");
        }
        vector<uint8_t> enc_dek(32 + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long dlen;
        crypto_aead_xchacha20poly1305_ietf_encrypt(enc_dek.data(), &dlen, dek, 32, nullptr, 0, nullptr, dek_nonce.ptr(), kek.ptr());
        sealed_dek.insert(sealed_dek.end(), salt.ptr(), salt.ptr() + salt.size());
        sealed_dek.insert(sealed_dek.end(), dek_nonce.ptr(), dek_nonce.ptr() + dek_nonce.size());
        sealed_dek.insert(sealed_dek.end(), enc_dek.begin(), enc_dek.end());
    } else {
        vector<uint8_t> payload(dek, dek + 32);
        sealed_dek = HardwareBindingManager::generate_keypair(CURRENT_BINDING, payload);
        if (sealed_dek.empty()) {
            throw runtime_error("Hardware binding returned empty data (Encryption failed)");
        }
    }
    
    string vault_path = KEY_DIR + name + "/" + VAULT_FILENAME;
    fs::create_directories(KEY_DIR + name);
    ofstream vout(vault_path, ios::binary);
    uint64_t sd_len = sealed_dek.size();
    vout.write((char*)&sd_len, 8);
    vout.write((char*)sealed_dek.data(), sd_len);
    vout.write((char*)nonce.ptr(), nonce.size());
    vout.write((char*)enc_priv.data(), clen);
    vout.close();
    ThermoHeader header{};
    create_header_v3(header, password.get(), CURRENT_BINDING, pub_keys);
    ofstream pout(id_path, ios::binary);
    pout.write((char*)&header, sizeof(header));
    uint32_t pk_len = pub_keys.size();
    pout.write((char*)&pk_len, 4);
    pout.write((char*)pub_keys.data(), pk_len);
    uint32_t slen = sig_len;
    pout.write((char*)&slen, 4);
    pout.write((char*)signature.data(), slen);
    pout.close();
    set_secure_permissions(vault_path);
    set_secure_permissions(id_path);
    cerr << "Identity '" << name << "' created successfully." << endl;
}

void encrypt_stream_v3(istream& in, ostream& out, const string& recipient_file, size_t size_hint) {
    auto recipient_data = read_file_secure(recipient_file);
    ThermoHeader header{};
    if (recipient_data.size() < sizeof(header)) throw runtime_error("Invalid identity file (too small)");
    memcpy(&header, recipient_data.ptr(), sizeof(header));
    if (memcmp(header.magic, HEADER_MAGIC_V1.c_str(), 9) != 0) throw runtime_error("Invalid recipient identity magic");
    size_t offset = sizeof(header);
    if (recipient_data.size() < offset + 4) throw runtime_error("Corrupted identity (missing pk len)");
    uint32_t pk_len;
    memcpy(&pk_len, recipient_data.ptr() + offset, 4);
    offset += 4;
    if (recipient_data.size() < offset + pk_len) throw runtime_error("Corrupted identity (truncated keys)");
    vector<uint8_t> pub_keys(recipient_data.ptr() + offset, recipient_data.ptr() + offset + pk_len);
    offset += pk_len;
    if (recipient_data.size() < offset + 4) throw runtime_error("Corrupted identity (missing sig len)");
    uint32_t sig_len;
    memcpy(&sig_len, recipient_data.ptr() + offset, 4);
    offset += 4;
    if (recipient_data.size() < offset + sig_len) throw runtime_error("Corrupted identity (truncated signature)");
    vector<uint8_t> signature(recipient_data.ptr() + offset, recipient_data.ptr() + offset + sig_len);
    OqsSigPtr sig(OQS_SIG_new("ML-DSA-65"));
    if (!sig) throw runtime_error("ML-DSA-65 not supported");
    OqsKemPtr kem_dummy(OQS_KEM_new("ML-KEM-768"));
    if (!kem_dummy) throw runtime_error("Failed to initialize ML-KEM-768 for offset calculation");
    size_t kem_len = kem_dummy->length_public_key;
    size_t x_len = crypto_box_PUBLICKEYBYTES;
    size_t sig_pk_offset = kem_len + x_len;
    if (pub_keys.size() < sig_pk_offset + sig->length_public_key) {
        throw runtime_error("Public key blob invalid size");
    }
    OQS_STATUS rc = OQS_SIG_verify(sig.get(), 
                                   pub_keys.data(), pub_keys.size(),
                                   signature.data(), signature.size(),
                                   pub_keys.data() + sig_pk_offset);
    if (rc != OQS_SUCCESS) {
        enforce_rate_limit();
        throw runtime_error("SECURITY ALERT: Identity signature verification FAILED! The file may be forged.");
    }
    OqsKemPtr kem(OQS_KEM_new("ML-KEM-768"));
    if (!kem) throw runtime_error("ML-KEM-768 not supported");
    size_t pq_offset = 0;
    vector<uint8_t> pq_pk(pub_keys.begin() + pq_offset, pub_keys.begin() + pq_offset + kem->length_public_key);
    SecureBuffer shared_secret(kem->length_shared_secret);
    vector<uint8_t> ciphertext(kem->length_ciphertext);
    OQS_KEM_encaps(kem.get(), ciphertext.data(), shared_secret.ptr(), pq_pk.data());
    vector<uint8_t> x_eph_pk(crypto_box_PUBLICKEYBYTES);
    SecureBuffer x_eph_sk(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(x_eph_pk.data(), x_eph_sk.ptr());
    size_t x_offset = kem->length_public_key;
    vector<uint8_t> x_pk(pub_keys.begin() + x_offset, pub_keys.begin() + x_offset + crypto_box_PUBLICKEYBYTES);
    SecureBuffer x_shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(x_shared.ptr(), x_eph_sk.ptr(), x_pk.data()) != 0) {
        throw runtime_error("X25519 scalar multiplication failed");
    }
    SecureBuffer master_key(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, master_key.size());
    crypto_generichash_update(&st, shared_secret.ptr(), shared_secret.size());
    crypto_generichash_update(&st, x_shared.ptr(), x_shared.size());
    crypto_generichash_final(&st, master_key.ptr(), master_key.size());
    crypto_secretstream_xchacha20poly1305_state stream_state;
    unsigned char header_bytes[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&stream_state, header_bytes, master_key.ptr());
    out.write(HEADER_MAGIC_V1.c_str(), 9);
    if (ciphertext.size() != 1088) throw runtime_error("Critical crypto failure: Invalid Kyber CT size");
    out.write((char*)ciphertext.data(), ciphertext.size());
    out.write((char*)x_eph_pk.data(), x_eph_pk.size());
    out.write((char*)header_bytes, sizeof(header_bytes));
    SecureBuffer in_buf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    SecureBuffer out_buf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    size_t processed = 0;
    while (in) {
        in.read((char*)in_buf.ptr(), CHUNK_SIZE);
        size_t read = in.gcount();
        if (read == 0) break;
        unsigned char tag = in.eof() ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        unsigned long long out_len;
        crypto_secretstream_xchacha20poly1305_push(&stream_state, out_buf.ptr(), &out_len,
                                                   in_buf.ptr(), read, nullptr, 0, tag);
        out.write((char*)out_buf.ptr(), out_len);
        processed += read;
        report_progress(processed, size_hint ? size_hint : STREAM_SIZE_HINT);
    }
    cerr << "[+] File encrypted successfully (Identity Verified)." << endl;
}

void decrypt_logic_v4(istream& in, ostream& out, const string& id_name, size_t hint) {
    if (sodium_init() < 0) throw runtime_error("Sodium init failed");
    OQS_init();
    string id_path = KEY_DIR + id_name + IDENTITY_EXT;
    auto id_data = read_file_secure(id_path);
    ThermoHeader header{};
    memcpy(&header, id_data.ptr(), sizeof(header));
    BindingType bind = static_cast<BindingType>(header.binding_type);
    
    SecretString password;
    string pw_prompt = "Password: ";
    get_password_silent(password.get(), pw_prompt);
    
    verify_header_v3(header, password.get());
    string vault_path = KEY_DIR + id_name + "/" + VAULT_FILENAME;
    auto vault_data = read_file_secure(vault_path);
    uint8_t* ptr = vault_data.ptr();
    size_t remain = vault_data.size();
    if (remain < 8) throw runtime_error("Corrupted vault");
    uint64_t sealed_len;
    memcpy(&sealed_len, ptr, 8);
    ptr += 8; remain -= 8;
    if (sealed_len > remain) {
        throw runtime_error("Corrupted vault file: Data shorter than declared length");
    }
    vector<uint8_t> sealed_dek(ptr, ptr + sealed_len);
    ptr += sealed_len; remain -= sealed_len;
    SecureBuffer dek(32);
    if (bind == BindingType::Disk) {
        if (sealed_dek.size() < crypto_pwhash_SALTBYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
            throw runtime_error("Corrupted disk vault");
        const uint8_t* salt = sealed_dek.data();
        const uint8_t* nonce = salt + crypto_pwhash_SALTBYTES;
        const uint8_t* ct = nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        size_t ct_len = sealed_dek.size() - crypto_pwhash_SALTBYTES - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        unsigned long long ops;
        size_t mem;
        get_argon_params_from_byte(header.argon_level, ops, mem);
        SecureBuffer kek(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        if (crypto_pwhash(kek.ptr(), kek.size(), password.get().c_str(), password.get().length(),
                          salt, ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
            enforce_rate_limit();
            throw runtime_error("Wrong password or corrupted vault");
        }
        unsigned long long mlen;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(dek.ptr(), &mlen, nullptr, ct, ct_len, nullptr, 0, nonce, kek.ptr()) != 0) {
            enforce_rate_limit();
            throw runtime_error("Wrong password");
        }
    } else {
        vector<uint8_t> raw_dek = HardwareBindingManager::decapsulate(sealed_dek, bind);
        
        if (raw_dek.size() != 32) throw runtime_error("Hardware returned invalid key");
        memcpy(dek.ptr(), raw_dek.data(), 32);
    }
    if (remain < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) throw runtime_error("Corrupted vault (nonce)");
    const uint8_t* main_nonce = ptr;
    ptr += crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    remain -= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    SecureBuffer priv_blob(remain - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long mlen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(priv_blob.ptr(), &mlen, nullptr, ptr, remain, nullptr, 0, main_nonce, dek.ptr()) != 0) {
        throw runtime_error("Vault integrity check failed");
    }
    OqsKemPtr kem(OQS_KEM_new("ML-KEM-768"));
    if (!kem) throw runtime_error("ML-KEM-768 not available");
    SecureBuffer pq_sk(kem->length_secret_key);
    SecureBuffer x_sk(crypto_box_SECRETKEYBYTES);
    size_t offset = 0;
    memcpy(pq_sk.ptr(), priv_blob.ptr() + offset, pq_sk.size());
    offset += pq_sk.size();
    memcpy(x_sk.ptr(), priv_blob.ptr() + offset, x_sk.size());
    char magic[9];
    in.read(magic, 9);
    if (memcmp(magic, HEADER_MAGIC_V1.c_str(), 9) != 0) throw runtime_error("Not a ThermoCrypt file");
    const size_t KYBER_CT_LEN = 1088; 
    vector<uint8_t> ct(KYBER_CT_LEN);
    in.read((char*)ct.data(), KYBER_CT_LEN);
    if (in.gcount() != KYBER_CT_LEN) throw runtime_error("File too short (truncated ciphertext)");
    vector<uint8_t> eph_x_pk(crypto_box_PUBLICKEYBYTES);
    in.read((char*)eph_x_pk.data(), eph_x_pk.size());
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    in.read((char*)stream_header, sizeof(stream_header));
    SecureBuffer ss_pq(kem->length_shared_secret);
    OQS_KEM_decaps(kem.get(), ss_pq.ptr(), ct.data(), pq_sk.ptr());
    SecureBuffer ss_x(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(ss_x.ptr(), x_sk.ptr(), eph_x_pk.data()) != 0) {
        throw runtime_error("X25519 scalar multiplication failed");
    }
    SecureBuffer master(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_generichash_state h;
    crypto_generichash_init(&h, nullptr, 0, master.size());
    crypto_generichash_update(&h, ss_pq.ptr(), ss_pq.size());
    crypto_generichash_update(&h, ss_x.ptr(), ss_x.size());
    crypto_generichash_final(&h, master.ptr(), master.size());
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, stream_header, master.ptr()) != 0) {
        throw runtime_error("Stream initialization failed");
    }
    SecureBuffer in_buf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    SecureBuffer out_buf(CHUNK_SIZE);
    size_t processed = 0;
    while (in) {
        in.read((char*)in_buf.ptr(), CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
        streamsize read = in.gcount();
        if (read == 0) break;
        unsigned char tag;
        unsigned long long out_len;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, out_buf.ptr(), &out_len, &tag,
                                                       in_buf.ptr(), read, nullptr, 0) != 0) {
            throw runtime_error("Corrupted or tampered file");
        }
        out.write((char*)out_buf.ptr(), out_len);
        processed += read;
        report_progress(processed, hint);
    }
    cerr << "[+] File decrypted successfully." << endl;
}

void encrypt_file(const string& in_f, const string& id_f) {
    string out_f = in_f + ".thermo";
    if (fs::exists(out_f)) {
        cerr << "Output file exists. Overwrite? (y/n): ";
        char ans; cin >> ans;
        if (ans != 'y' && ans != 'Y') return;
    }
    ifstream fin(in_f, ios::binary | ios::ate);
    size_t sz = fin.tellg();
    fin.seekg(0);
    ofstream fout(out_f, ios::binary);
    encrypt_stream_v3(fin, fout, id_f, sz);
}

void decrypt_file(const string& in_f, const string& id_name) {
    string out_f = in_f + ".dec";
    if (fs::exists(out_f)) {
        cerr << "Output file exists. Overwrite? (y/n): ";
        char ans; cin >> ans;
        if (ans != 'y' && ans != 'Y') return;
    }
    ifstream fin(in_f, ios::binary | ios::ate);
    size_t sz = fin.tellg();
    fin.seekg(0);
    ofstream fout(out_f, ios::binary);
    decrypt_logic_v4(fin, fout, id_name, sz);
}

void decrypt_to_stdout(const string& in_f, const string& id_name) {
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    ifstream fin(in_f, ios::binary | ios::ate);
    size_t sz = fin.tellg();
    fin.seekg(0);
    decrypt_logic_v4(fin, cout, id_name, sz);
}

void disable_core_dumps() {
#ifndef _WIN32
    struct rlimit rlim;
    rlim.rlim_cur = rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
#endif
}

void prevent_debugger_attach() {
#ifndef _WIN32
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        raise(SIGKILL); 
    }
#endif
}

void secure_wipe_file(const string& path) {
    if (!fs::exists(path)) return;
    try {
        FILE* f = fopen(path.c_str(), "rb+");
        if (f) {
            int fd = fileno(f);
            uintmax_t size = fs::file_size(path);
            const int PASSES = 3;
            vector<unsigned char> buf(4096);
            for (int p = 0; p < PASSES; ++p) {
                fseek(f, 0, SEEK_SET);
                uintmax_t written = 0;
                while (written < size) {
                    randombytes_buf(buf.data(), buf.size());
                    size_t chunk = min((uintmax_t)buf.size(), size - written);
                    fwrite(buf.data(), 1, chunk, f);
                    written += chunk;
                }
                fflush(f);
                #ifndef _WIN32
                fsync(fd); 
                #endif
            }
            fseek(f, 0, SEEK_SET);
            sodium_memzero(buf.data(), buf.size());
            uintmax_t written = 0;
            while (written < size) {
                size_t chunk = min((uintmax_t)buf.size(), size - written);
                fwrite(buf.data(), 1, chunk, f);
                written += chunk;
            }
            fflush(f);
            #ifndef _WIN32
            fsync(fd);
            #endif
            #ifndef _WIN32
            if (ftruncate(fd, 0) != 0) {
                
            }
            #endif
            
            fclose(f);
        }
    } catch (...) { 
    }
    fs::remove(path);
}

void print_help() {
    cerr << "ThermoCrypt v1.0.0\n"
         << "Hybrid Post-Quantum Encryption (ML-KEM-768 + X25519) with Hardware Binding\nCopyright (c) 2025 Herman Nythe\n\n"
         << "USAGE:\n"
         << "  ./thermo_core <command> [options]        (Standard Disk Mode)\n"
         << "  sudo ./thermo_core <command> [options]   (Required for TPM Mode)\n\n"
         << "COMMANDS:\n"
         << "  --gen <alias>                     Generate a new identity and vault.\n"
         << "  --encrypt <file> <id_file>        Encrypt a file for a specific recipient.\n"
         << "  --decrypt <file> <alias>          Decrypt a file using your private identity.\n"
         << "  --decrypt-stdout <file> <alias>   Decrypt directly to standard output (pipe).\n"
         << "  --encrypt-text <out> <id_file>    Encrypt stdin stream to a file.\n\n"
         << "OPTIONS:\n"
         << "  --bind <type>         Hardware binding mode (Linux Only).\n"
         << "                        Supported: disk (Standard), tpm (Machine Bound).\n"
         << "                        Default: disk\n\n"
         << "  --argon-level <lvl>   Set Argon2id cost parameters (interactive/moderate/sensitive).\n"
         << "  --keydir <path>       Specify custom directory for keys.\n"
         << "  --rate-limit          Enable artificial delay to slow brute-force.\n"
         << "  --no-progress         Disable progress bar output.\n\n"
         << "TPM MANAGEMENT (Linux Only):\n"
         << "  This software uses the fixed TPM Handle: 0x81018100\n"
         << "  Only one identity can be bound to the TPM at a time.\n"
         << "  To delete/reset the current TPM identity, run (requires tpm2-tools):\n\n"
         << "    sudo tpm2_evictcontrol -C o -c 0x81018100\n\n"
         << "SECURITY NOTE:\n"
         << "  'disk' mode protects keys with a password (Argon2id).\n"
         << "  'tpm' mode binds keys to this specific machine's TPM chip AND a password.\n"
         << "  Ensure you have backups of your data.\n";
}

int main(int argc, char* argv[]) {
    try {
        prevent_debugger_attach();
        #ifndef _WIN32
        if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
            cerr << "Warning: Could not lock entire process in RAM (Swap risk). Run as root for max security." << endl;
        }
        #endif
        disable_core_dumps();
        clean_stale_artifacts();
        if (argc < 2 || (argc == 2 && (string(argv[1]) == "-h" || string(argv[1]) == "--help"))) {
            print_help();
            return 0;
        }
        vector<string> args(argv + 1, argv + argc);
        string cmd = "";
        for (size_t i = 0; i < args.size(); ++i) {
            if (args[i] == "--keydir") {
                if (i + 1 < args.size()) KEY_DIR = args[++i] + "/";
                else throw runtime_error("Missing value for --keydir");
            } 
            else if (args[i] == "--bind") {
                if (i + 1 < args.size()) {
                    string b = args[++i];
                    if (b == "tpm") CURRENT_BINDING = BindingType::TPM;
                    else CURRENT_BINDING = BindingType::Disk;
                } else throw runtime_error("Missing value for --bind");
            } 
            else if (args[i] == "--rate-limit") {
                GLOBAL_RATE_LIMIT = true;
            } 
            else if (args[i] == "--argon-level") {
                if (i + 1 < args.size()) ARGON_LEVEL = args[++i];
                else throw runtime_error("Missing value for --argon-level");
            } 
            else if (args[i] == "--no-progress") {
                NO_PROGRESS = true;
            } 
            else if (args[i] == "--stream-size") {
                if (i + 1 < args.size()) {
                    try { STREAM_SIZE_HINT = stoull(args[++i]); } catch(...) {}
                }
            } 
            else if (cmd.empty()) {
                cmd = args[i];
            }
        }
        if (cmd.empty()) throw runtime_error("No command specified");
        vector<string> clean_args;
        for (size_t i = 0; i < args.size(); ++i) {
            if (args[i].rfind("--", 0) == 0) {
                if (args[i] == "--rate-limit" || args[i] == "--no-progress") continue;
                if (args[i] == cmd) continue;
                i++;
            } else {
                clean_args.push_back(args[i]);
            }
        }
        if (cmd == "--gen") {
            if (clean_args.empty()) throw runtime_error("Missing identity name");
            generate_identity_v4(clean_args[0]);
        } 
        else if (cmd == "--encrypt") {
            if (clean_args.size() < 2) throw runtime_error("Usage: --encrypt <file> <identity>");
            encrypt_file(clean_args[0], clean_args[1]);
        } 
        else if (cmd == "--encrypt-text") {
            if (clean_args.size() < 2) throw runtime_error("Usage: --encrypt-text <outfile> <identity>");
            if (fs::exists(clean_args[0])) {
                throw runtime_error("Security: Output file already exists. Please delete it manually first.");
            }
            #ifdef _WIN32
                _setmode(_fileno(stdin), _O_BINARY);
            #endif
            ofstream fout(clean_args[0], ios::binary);
            if (!fout) throw runtime_error("Cannot open output file");
            encrypt_stream_v3(cin, fout, clean_args[1], 0);
            set_secure_permissions(clean_args[0]);
        } 
        else if (cmd == "--decrypt") {
            if (clean_args.size() < 2) throw runtime_error("Usage: --decrypt <file> <identity_name>");
            decrypt_file(clean_args[0], clean_args[1]);
        } 
        else if (cmd == "--decrypt-stdout") {
             if (clean_args.size() < 2) throw runtime_error("Usage: --decrypt-stdout <file> <identity_name>");
            decrypt_to_stdout(clean_args[0], clean_args[1]);
        } 
        else {
            throw runtime_error("Unknown command: " + cmd);
        }
    } catch (const exception& e) {
        enforce_rate_limit();
        cerr << "CRITICAL ERROR: " << e.what() << endl;
        return 1;
    }
    return 0;
}