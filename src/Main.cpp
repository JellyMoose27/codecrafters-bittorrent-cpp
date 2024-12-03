#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <array>
#include <curl/curl.h>
#include "lib/nlohmann/json.hpp"
#include "lib/sha1.hpp"


using json = nlohmann::json;


json decode_bencoded_value(const std::string& encoded_value, size_t& index);

json decode_bencoded_string(const std::string& encoded_value, size_t& index) {

    std::string result = "";
    while (std::isdigit(encoded_value[index]))
    {
        result += encoded_value[index];
        index++;
    }
    int length = std::atoll(result.c_str());
    result = "";
    index++;
    while (length--)
    {
        result += encoded_value[index];
        index++;
    }
    return result;
}

json decode_bencoded_integer(const std::string& encoded_value, size_t& index) {
    index++;
    std::string result = "";
    while(encoded_value[index] != 'e')
    {
        result += encoded_value[index];
        index++;
    }
    index++;
    return json(std::atoll(result.c_str()));
}

json decode_bencoded_list(const std::string& encoded_value, size_t& index) {
    index++;
    json list = json::array();
    while(encoded_value[index] != 'e')
    {
        list.push_back(decode_bencoded_value(encoded_value, index));
    }
    index++;
    return list;
}

json decode_bencoded_dict(const std::string& encoded_value, size_t& index)
{
    index++;
    json res = json::object();
    // skip the 'd'
    while(encoded_value[index] != 'e')
    {
        /*
        d<key1><value1>...<keyN><valueN>
        Example "d3:foo3:bare"
        foo is key, bar is value

        lexicographical order: a generalization of the alphabetical order of the dictionaries to sequences of ordered symbols or, 
        more generally, of elements of a totally ordered set. 
        */
        json key = decode_bencoded_value(encoded_value, index);
        json value = decode_bencoded_value(encoded_value, index);
        res[key.get<std::string>()] = value;
    }
    index++;
    return res;
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
        return decode_bencoded_string(encoded_value, index);
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
        // Example: "d3:foo3:bar5:helloi52ee" -> {"foo":"bar", "hello":"52"}
        return decode_bencoded_dict(encoded_value, index);
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

std::string read_file(const std::string& filePath)
{
    /*
    open the file
    */
    std::ifstream file(filePath, std::ios::binary);
    std::stringstream buffer;

    /*
    read the content from the file
    then close
    */
    if(file)
    {
        buffer << file.rdbuf();
        file.close();
        return buffer.str();
    }
    else
    {
        throw std::runtime_error("Failed to open file: " + filePath);
    }
}

std::string json_to_bencode(const json& js)
{
    std::ostringstream os;
    if (js.is_object())
    {
        os << 'd';
        for (auto& el : js.items())
        {
            os << el.key().size() << ':' << el.key() << json_to_bencode(el.value());
        }
        os << 'e'; 
    } 
    else if (js.is_array())
    {
        os << 'l';
        for (const json& item : js)
        {
            os << json_to_bencode(item);
        }
        os << 'e';
    }
    else if (js.is_number_integer())
    {
        os << 'i' << js.get<int>() << 'e';
    }
    else if (js.is_string())
    {
        const std::string& value = js.get<std::string>();
        os << value.size() << ':' << value;
    }
    return os.str();
}

void parse_torrent(const std::string& filePath)
{
    std::string fileContent = read_file(filePath);
    json decoded_torrent = decode_bencoded_value(fileContent);

    // bencode the torrent
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);

    // calculate the info hash
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string infoHash = sha1.final();

    // announceURL
    std::string trackerURL = decoded_torrent["announce"];
    
    // length
    int length = decoded_torrent["info"]["length"];

    // piece length
    int pieceLength = decoded_torrent["info"]["piece length"];
    
    std::cout << "Tracker URL: " << trackerURL << std::endl;
    std::cout << "Length: " << length << std::endl;
    std::cout << "Info Hash: " << infoHash << std::endl;
    std::cout << "Piece Length: " << pieceLength << std::endl;
    std::cout << "Piece Hashes: " << std::endl;

    // concatenated SHA-1 hashes of each piece (20 bytes each)
    for (std::size_t i = 0; i < decoded_torrent["info"]["pieces"].get<std::string>().length(); i += 20)
    {
        std::string piece = decoded_torrent["info"]["pieces"].get<std::string>().substr(i, 20);
        std::stringstream ss;
        for (unsigned char byte : piece)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << ss.str() << std::endl;
    }
}

// Function to convert hexadecimal string to bytes
std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Function to encode info_hash in URL-encoded format
std::string url_encode(const std::string& value) {
    auto rawBytes = hexToBytes(value);

    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : rawBytes) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
        }
    }

    return escaped.str();
}

// Function to perform HTTP GET request
size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

std::string http_get(const std::string& url) {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to initialize CURL");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }

    curl_easy_cleanup(curl);
    return response;
}

// Function to parse compact peer list
std::vector<std::string> parse_peers(const std::string& peers) {
    std::vector<std::string> result;
    for (size_t i = 0; i < peers.size(); i += 6) {
        std::string ip = std::to_string((unsigned char)peers[i]) + "." +
                         std::to_string((unsigned char)peers[i + 1]) + "." +
                         std::to_string((unsigned char)peers[i + 2]) + "." +
                         std::to_string((unsigned char)peers[i + 3]);
        int port = ((unsigned char)peers[i + 4] << 8) | (unsigned char)peers[i + 5];
        result.push_back(ip + ":" + std::to_string(port));
    }
    return result;
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
    else if (command == "info")
    {
        if (argc < 3) {

            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;

            return 1;

        }
        try
        {
            /*
            retrieve the path to the torrent file
            Example: /tmp/torrents586275342/itsworking.gif.torrent
            */ 
            std::string filePath = argv[2];

            parse_torrent(filePath);

        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
        
        
    }
    else if (command == "peers")
    {
        std::string filePath = argv[2];

        try
        {
            std::string fileContent = read_file(filePath);
            json decoded_torrent = decode_bencoded_value(fileContent);

            // bencode the torrent
            std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);

            // calculate the info hash
            SHA1 sha1;
            sha1.update(bencoded_info);
            std::string infoHash = sha1.final();
            std::string urlEncodedHash = url_encode(infoHash);

            // announceURL
            std::string trackerURL = decoded_torrent["announce"];  

            // length
            int length = decoded_torrent["info"]["length"];

            // Contruct GET message
            std::string peerID = "01234567890123456789";
            std::ostringstream url;
            url << trackerURL << "?info_hash=" << urlEncodedHash
                << "&peer_id=" << peerID
                << "&port=6881"
                << "&uploaded=0"
                << "&downloaded=0"
                << "&left=" << length
                << "&compact=1";

            std::string response = http_get(url.str());

            json trackerResponse = decode_bencoded_value(response);
            std::string peers = trackerResponse["peers"];

            std::vector<std::string> peerList = parse_peers(peers);
            for (const auto& peer : peerList)
            {
                std::cout << peer << std::endl;
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            return 1;
        }
    }
    else {

        std::cerr << "unknown command: " << command << std::endl;

        return 1;

    }

    return 0;

}