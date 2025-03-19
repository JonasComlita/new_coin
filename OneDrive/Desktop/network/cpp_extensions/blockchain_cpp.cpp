#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <future>
#include <random>
#include <functional>
#include <chrono>
#include <algorithm>
#include <condition_variable>

namespace py = pybind11;

// SHA-256 implementation for OpenSSL 3.0
std::string sha256(const std::string &input)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_length);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_length; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// RIPEMD-160 implementation using OpenSSL
std::string ripemd160(const std::string &input)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_ripemd160();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_length);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_length; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string calculate_merkle_root(const std::vector<std::string> &tx_ids)
{
    if (tx_ids.empty())
    {
        return std::string(64, '0');
    }

    std::vector<std::string> tree = tx_ids;
    while (tree.size() > 1)
    {
        std::vector<std::string> new_level;
        for (size_t i = 0; i < tree.size(); i += 2)
        {
            std::string left = tree[i];
            std::string right = (i + 1 < tree.size()) ? tree[i + 1] : left;
            std::string combined = left + right;
            new_level.push_back(sha256(combined));
        }
        tree = new_level;
    }
    return tree[0];
}

// Convert public key to blockchain address
std::string public_key_to_address(const std::string &public_key)
{
    // Perform SHA-256 hash on the public key
    std::string sha256_hash = sha256(public_key);

    // Perform RIPEMD-160 hash on the SHA-256 hash
    std::string ripemd_hash = ripemd160(sha256_hash);

    // Take first 10 characters of RIPEMD-160 hash
    std::string truncated_hash = ripemd_hash.substr(0, 10);

    // Prepend with '1' to indicate a standard public key hash address
    return "1" + truncated_hash;
}

// Modified to return non-atomic types
std::tuple<int, std::string, long> mine_block(const std::string &block_string_base, int difficulty, int max_nonce = INT_MAX)
{
    std::string target(difficulty, '0');

    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0)
        num_threads = 4;

    // Use atomic variables for thread-safe operations
    std::atomic<bool> found_solution(false);
    std::atomic<int> result_nonce(0);
    std::atomic<long> total_hashes(0);
    std::string result_hash;
    std::mutex result_mutex;

    std::vector<std::thread> threads;
    int chunk_size = max_nonce / num_threads;

    for (unsigned int i = 0; i < num_threads; i++)
    {
        int start_nonce = i * chunk_size;
        int end_nonce = (i == num_threads - 1) ? max_nonce : (i + 1) * chunk_size;

        threads.emplace_back([&, start_nonce, end_nonce]()
                             {
            long local_hashes = 0;
            for (int nonce = start_nonce; nonce < end_nonce && !found_solution; nonce++) {
                std::string block_string = block_string_base + std::to_string(nonce);
                std::string hash = sha256(block_string);
                local_hashes++;
                
                if (hash.compare(0, difficulty, target) == 0) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    if (!found_solution) {
                        found_solution = true;
                        // Convert atomic to regular int for std::tuple
                        result_nonce.store(nonce);
                        result_hash = hash;
                    }
                    break;
                }
                
                if (local_hashes % 10000 == 0) {
                    total_hashes += local_hashes;
                    local_hashes = 0;
                }
            }
            total_hashes += local_hashes; });
    }

    for (auto &thread : threads)
    {
        thread.join();
    }

    if (found_solution)
    {
        // Convert atomic to regular types for tuple
        return std::make_tuple(result_nonce.load(), result_hash, total_hashes.load());
    }
    else
    {
        return std::make_tuple(-1, "", total_hashes.load());
    }
}

PYBIND11_MODULE(blockchain_cpp, m)
{
    m.doc() = "C++ acceleration library for blockchain operations";

    m.def("sha256", &sha256, "Calculate SHA-256 hash of input string");
    m.def("calculate_merkle_root", &calculate_merkle_root, "Calculate Merkle root from transaction IDs");
    m.def("mine_block", &mine_block, "Mine a block with the given difficulty",
          py::arg("block_string_base"), py::arg("difficulty"), py::arg("max_nonce") = INT_MAX);
    m.def("public_key_to_address", &public_key_to_address, "Convert public key to blockchain address");
}