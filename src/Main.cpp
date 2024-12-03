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

json decode_bencoded_integer(const std::string& encoded_value, size_t& index) {
    size_t end_index = encoded_value.find('e', index);
    if (end_index != std::string::npos) {

        std::string num = encoded_value.substr(index + 1, end_index - index - 1);

        int64_t number = std::atoll(num.c_str());
        index = end_index + 1;

        return json(number);

    } else {

        throw std::runtime_error("Invalid encoded value: " + encoded_value);

    }

}

json decode_bencoded_list(const std::string& encoded_value, size_t& index) {
    
    index++;

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
            std::string number_string = encoded_value.substr(index, colon_index);

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
            list.push_back(json(stoll(int_s)));
            index = end_idx + 1;
        }
    }
    index++;
    return json(list);
}

json decode_bencoded_value(const std::string &encoded_value) {

  size_t index = 0;

  json res = decode_bencoded_value(encoded_value, index);

  if (index != encoded_value.size()) {

    throw std::runtime_error("String not fully consumed.");

  }

  return res;

}

json decode_bencoded_value(const std::string& encoded_value, size_t& index)
{
    if (std::isdigit(encoded_value[index]))
    {
        // Example: "5:hello" -> "hello"
        return decode_bencoded_string(encoded_value);
    }
    else if (encoded_value[index] == 'i')
    {
        // Example: "i45e" - > "45"
        return decode_bencoded_integer(encoded_value, index);
    }
    else if (encoded_value[index] == 'l')
    {
        // Example: "l10:strawberryi559ee" -> "[strawberry, 559]"
        return decode_bencoded_list(encoded_value, index);
    }
    else if (encoded_value[index] == 'd')
    {
        index++;
        // Example: "d3:foo3:bar5:helloi52ee" -> {"foo":"bar", "hello":"52"}
        auto dict = nlohmann::ordered_map<json, json>();
        // skip the 'd'
        while (encoded_value[index] != 'e')
        {
            /*
            d<key1><value1>...<keyN><valueN>
            Example "d3:foo3:bare"
            foo is key, bar is value

            lexicographical order: a generalization of the alphabetical order of the dictionaries to sequences of ordered symbols or, 
            more generally, of elements of a totally ordered set. 
            */
            auto key = decode_bencoded_value(encoded_value, index);
            auto value = decode_bencoded_value(encoded_value, index);
            dict.push_back({key, value});
        }
        return json(dict);
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}


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