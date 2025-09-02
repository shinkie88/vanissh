#pragma once

#include <atomic>
#include <string>

#include <openssl/evp.h>

struct VanityResult {
    std::string private_key_pem;
    std::string private_key_openssh;
    std::string public_key_ssh;
    uint64_t attempts;
};

class SSHKeyGenerator {
   public:
    SSHKeyGenerator();

    ~SSHKeyGenerator();

    // Generate a single key pair
    [[gnu::hot]] inline bool generate_ed25519_key();

    // Get the current public key in SSH format
    [[gnu::hot]] inline const std::string& get_public_key_ssh() const;

    // Get the current private key in PEM format
    std::string get_private_key_pem() const;

    // Get the current private key in OpenSSH format
    std::string get_private_key_openssh() const;

    // Check if the public key matches the vanity criteria
    [[gnu::hot]] inline bool matches_vanity(
        const std::string& prefix,
        const std::string& suffix,
        const std::string& contains,
        bool case_insensitive = false
    ) const;

    // Multi-threaded vanity generation
    static VanityResult generate_vanity_key(
        const std::string& prefix,
        const std::string& suffix,
        const std::string& contains,
        int num_threads = 0,
        bool case_insensitive = false,
        std::atomic<bool>* stop_flag = nullptr,
        std::atomic<uint64_t>* total_attempts = nullptr
    );

   private:
    EVP_PKEY* private_key_;
    mutable std::string cached_public_key_ssh_;
    mutable std::string cached_private_key_pem_;
    mutable std::string cached_private_key_openssh_;
    mutable bool cache_valid_;

    // Convert public key to SSH format
    std::string public_key_to_ssh() const;

    // Convert private key to PEM format
    std::string private_key_to_pem() const;

    // Convert private key to OpenSSH format using ssh-keygen
    std::string private_key_to_openssh() const;

    // Clear cached values
    void clear_cache();

    // Worker function for multi-threaded generation
    static void worker_thread(
        const std::string& prefix,
        const std::string& suffix,
        const std::string& contains,
        bool case_insensitive,
        std::atomic<bool>* found,
        std::atomic<bool>* stop_flag,
        std::atomic<uint64_t>* total_attempts,
        VanityResult* result
    );
};
