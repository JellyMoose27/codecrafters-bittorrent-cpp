// // #include "bencode.h"

// json Bencode::decode(const std::string& encoded_value) {
//     //if encoded value starts with a digit, it is a number
//     //get the first number
//     //check if digit
//     //if yes, look for colon ":"
//     if (std::isdigit(encoded_value[0]))
//     {
//         // Example: "5:hello" -> "hello"
//         size_t colon_index = encoded_value.find(':');
//         if (colon_index != std::string::npos) {
//             std::string number_string = encoded_value.substr(0, colon_index);
//             int64_t number = std::atoll(number_string.c_str());
//             std::string str = encoded_value.substr(colon_index + 1, number);

//             //return str as a json variable
//             return json(str);
//         }
//     } 
//     else if (encoded_value[0] == 'i' && encoded_value[encoded_value.size() - 1] == 'e')
//     {
//         // Example: "i45e" -> "45"
//         std::string x = encoded_value.substr(1, encoded_value.size() - 2);

//         //return str as a json variable
//         return json(std::atoll(x.c_str()));
//     }
//     else
//     {
//         throw std::runtime_error("Unsupported type for encoding");
//     }
// }


