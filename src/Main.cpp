#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>

#include "lib/nlohmann/json.hpp"
// #include "utils/bencode.cpp"

using json = nlohmann::json;

json decode_bencoded_value(const std::string& encoded_value, size_t& position) {
    //if encoded value starts with a digit, it is a number
    //get the first number
    //check if digit
    //if yes, look for colon ":"
    if (std::isdigit(encoded_value[position])) {
       return decode_bencoded_string(encoded_value, position); 
    }
    else if (encoded_value[0] == 'i') {
        return decode_bencoded_int(encoded_value, position);
    }
    else if (encoded_value[0] == 'l')
    {
        // Example : "l5:helloi52ee" -> ["hello", 52]
        return decode_bencoded_list(encoded_value, position);
    }
    else {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

json decode_bencoded_value(const std::string& encoded_value)
{
    size_t position = 0;
    return decode_bencoded_value(encoded_value, position);
}

json decode_bencoded_string(const std::string& encoded_value, size_t& position)
{
    // Example: "5:hello" -> "hello"
    size_t colon_index = encoded_value.find(':', position);
    if (colon_index != std::string::npos) {
        std::string number_string = encoded_value.substr(position, colon_index - position);
        int64_t number = std::atoll(number_string.c_str());
        std::string str = encoded_value.substr(colon_index + 1, number);

        //return str as a json variable
        return json(str);
    } else {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }
}

json decode_bencoded_int(const std::string& encoded_value, size_t& position)
{
    position++;
    // Example: "i45e" -> "45"
    size_t e_index = encoded_value.find('e', position);
    if (e_index == std::string::npos)
    {
        throw std::invalid_argument("Invalid encoded integer");
    }
    std::string integer_s = encoded_value.substr(position, e_index - position);
    position = e_index + 1;
    //return str as a json variable
    return std::stoll(integer_s);
}

json decode_bencoded_list(const std::string& encoded_value, size_t& position)
{
    position++;
    json list = json::array();

    while (encoded_value[position] != 'e')
    {
        list.push_back(decode_bencoded_value(encoded_value, position));
    }
    position++;
    return list;
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

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
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        std::cerr << "Logs from your program will appear here!" << std::endl;

        // Uncomment this block to pass the first stage
        std::string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
