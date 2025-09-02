#pragma once

#include <string>
#include <vector>

class Base64Encoder {
   public:
    static std::string encode_data(const std::vector<unsigned char>& data);
    static std::string encode_data(const unsigned char* data, size_t length);

   private:
    static constexpr char kEncodingTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
};
