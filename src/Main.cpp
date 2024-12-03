#include <iostream>

#include <string>

#include <vector>

#include <cctype>

#include <cstdlib>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;



json decode_bencoded_string(const std::string& encoded_value) {

    size_t colon_index = encoded_value.find(':');

    if (colon_index != std::string::npos) {

        std::string number_string = encoded_value.substr(0, colon_index);

        int64_t number = std::atoll(number_string.c_str());

        std::string str = encoded_value.substr(colon_index + 1, number);

        return json(str);

    } else {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }

}

json decode_bencoded_integer(const std::string& encoded_value) {

    size_t end_idx = encoded_value.find('e');
    if (end_idx == std::string::npos)
        throw std::invalid_argument("Invalid bencoded integer");
    
    std::string int_s = encoded_value.substr(1, end_idx - 1);

    return json(stoll(int_s));

}

json decode_bencoded_list(const std::string& encoded_value, int& index) {

    std::vector<json> list;

    while(index < encoded_value.size() - 1)
    {
        if (encoded_value[index] == 'e')
        {
            index++;
            return list;
        }
        if (std::isdigit(encoded_value[index]))
        {
            size_t colon_index = encoded_value.find(':');
            std::string number_string = encoded_value.substr(0, colon_index);

            int64_t number = std::atoll(number_string.c_str());

            std::string str = encoded_value.substr(colon_index + 1, number);
            list.push_back(json(str));
            index = colon_index + number + 1;
        }
        else if (encoded_value[index] == 'l')
        {
            index++;
            list.push_back(decode_bencoded_list(encoded_value, index));
        }
        else
        {
            size_t end_idx = encoded_value.find('e', index);
            if (end_idx == std::string::npos)
                throw std::invalid_argument("Invalid bencoded integer");
    
            std::string int_s = encoded_value.substr(index + 1, end_idx - index - 1);
            list.push_back(json(std::stoll(int_s)));
            index = end_idx + 1;
        }
    }

    return json(list);
}

json decode_bencoded_value(const std::string& encoded_value)
{
    if (std::isdigit(encoded_value[0]))
    {
        return decode_bencoded_string(encoded_value);
    }
    else if (encoded_value[0] == 'i')
    {
        return decode_bencoded_integer(encoded_value);
    }
    else if (encoded_value[0] == 'l')
    {
        int index = 1;
        return decode_bencoded_list(encoded_value, index);
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}
// std::pair<json, size_t> decode_bencoded_dictionary(const std::string& encoded_value) {

//     std::map<json, json> map;

//     size_t index = 1;

//     while (encoded_value[index] != 'e') {

//         auto [key, offset] = decode_bencoded_value(encoded_value.substr(index));

//         index += offset;

//         auto [value, another] = decode_bencoded_value(encoded_value.substr(index));

//         index += another;

//         map.insert(std::pair(key, value));

//     }

//     return std::pair(json(map), index + 1);

// }


int main(int argc, char* argv[]) {

    if (argc < 2) {

        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;

        return 1;

    }

    std::string command = argv[1];

    if (command == "decode") {

        if (argc < 3) {

            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;

            return 1;

        }

        std::string encoded_value = argv[2];

        json decoded_value = decode_bencoded_value(encoded_value);

        std::cout << decoded_value.dump() << std::endl;

    }

    else {

        std::cerr << "unknown command: " << command << std::endl;

        return 1;

    }

    return 0;

}