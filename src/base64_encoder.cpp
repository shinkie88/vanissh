#include "base64_encoder.h"

#include <cstdint>

constexpr char Base64Encoder::kEncodingTable[];

std::string Base64Encoder::encode_data(const std::vector<unsigned char>& data) {
    return encode_data(data.data(), data.size());
}

std::string Base64Encoder::encode_data(const unsigned char* data, size_t length) {
    if (length == 0) {
        return "";
    }

    size_t output_length = 4 * ((length + 2) / 3);
    std::string encoded_data;
    encoded_data.reserve(output_length);

    for (size_t i = 0; i < length; i += 3) {
        uint32_t octet_a = i < length ? data[i] : 0;
        uint32_t octet_b = i + 1 < length ? data[i + 1] : 0;
        uint32_t octet_c = i + 2 < length ? data[i + 2] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data += kEncodingTable[(triple >> 3 * 6) & 0x3F];
        encoded_data += kEncodingTable[(triple >> 2 * 6) & 0x3F];
        encoded_data += kEncodingTable[(triple >> 1 * 6) & 0x3F];
        encoded_data += kEncodingTable[(triple >> 0 * 6) & 0x3F];
    }

    size_t mod_table[] = {0, 2, 1};
    for (size_t i = 0; i < mod_table[length % 3]; i++) {
        encoded_data[encoded_data.length() - 1 - i] = '=';
    }

    return encoded_data;
}
