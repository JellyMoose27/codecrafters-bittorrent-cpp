#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <array>
#include <cstring>
#include <curl/curl.h>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib") // Link Winsock library
#include <BaseTsd.h>
typedef SSIZE_T ssize_t; // Define ssize_t for Wind
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket close
#endif
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

std::string bytes_to_hex(const std::string &bytes) {
    std::ostringstream hex;
    hex.fill('0');
    hex << std::hex;
    for (unsigned char c : bytes) {
        hex << std::setw(2) << static_cast<int>(c);
    }
    return hex.str();
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

// Establish connection to the peer
int connect_to_peer(const std::string &ip, int port) {
    #ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return -1;
    }
    #endif

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        closesocket(sockfd);
        throw std::runtime_error("Failed to connect to peer");
    }

    return sockfd;
}   


// Function to validate the handshake response
void validate_handshake(const std::string& response, const std::string& expected_infohash) {
    if (response.size() != 68) {
        throw std::runtime_error("Invalid handshake size");
    }

    std::string received_infohash = response.substr(28, 20);
    if (received_infohash != expected_infohash) {
        throw std::runtime_error("Invalid handshake response: Infohash mismatch");
    }

    /*
    Remember to convert back to hexadecimal for human readable output
    Prints the hexadecimal value of the Peer ID of the Peer that we (the client) connected to
    Example: received_peer_id: 3030313132323333343435353636373738383939 -> peer_id: 116494218e909827af98a36137026979dabbdcb9
    */
    std::string receivedPeerID(response.substr(48, 20));
    std::cout << "Peer ID: " << bytes_to_hex(receivedPeerID) << std::endl;
}

std::string calculateInfohash(std::string bencoded_info)
{
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string infoHash = sha1.final();
    return infoHash;
}

// Convert hexadecimal to binary (for InfoHash)
std::string hex_to_binary(const std::string& hex) {
    if (hex.size() != 40) {
        throw std::runtime_error("Invalid SHA1 hash length; expected 40 hex characters.");
    }

    std::string binary;
    binary.reserve(20); // 40 hex characters = 20 bytes binary

    for (size_t i = 0; i < hex.size(); i += 2) {
        // Convert each pair of hex characters to a single byte
        unsigned char byte = std::stoul(hex.substr(i, 2), nullptr, 16);
        binary.push_back(static_cast<char>(byte));
    }

    return binary;
}

struct Handshake
{
    uint8_t length;
    char protocol[19];
    uint8_t reservedBytes[8];
    char infoHash[20];
    char peerID[20];

    Handshake(const std::string& infoHashS, const std::string& peerIDS)
    {
        length = 19;
        std::memcpy(protocol, "BitTorrent protocol", 19);
        std::memset(reservedBytes, 0, 8);
        std::memcpy(infoHash, infoHashS.data(), 20);
        std::memcpy(peerID, peerIDS.data(), 20);
    }

    std::vector<char> toVector() const {
        std::vector<char> handshakeVector(sizeof(Handshake), 0);
        std::memcpy(handshakeVector.data(), this, sizeof(Handshake));

        return handshakeVector;
    }
};

const size_t PIECE_BLOCK = 16384; //16 kb

enum MessageType : uint8_t 
{
    choke = 0,
    unchoke = 1,
    interested = 2,
    not_interested = 3,
    have = 4,
    bitfield = 5,
    request = 6,
    piece = 7,
    cancel = 8
};

std::vector<uint8_t> receive_message(int sockfd)
{
    // Read message length (4 bytes)
    uint32_t length = 0;
    // std::cout << "Message length: " << length << std::endl;
    if (recv(sockfd, &length, sizeof(length), 0) != sizeof(length)) // failed after downloading some blocks, but why?
    {
        throw std::runtime_error("Failed to read message");
    }
    length = ntohl(length);

    // Read the payload (can ignore this for now)
    std::vector<uint8_t> buffer(length);

    int totalBytesRead = 0;
    while (totalBytesRead < length) {
        int bytesRead = recv(sockfd, buffer.data() + totalBytesRead, length - totalBytesRead, 0);
        if (bytesRead <= 0) {
            throw std::runtime_error("Failed to read payload: Connection lost or incomplete data");
        }
        totalBytesRead += bytesRead;
    }
    return buffer;
}

void send_message(int sockfd, MessageType messageType, const std::vector<uint8_t>& payload = {})
{
    uint32_t length = htonl(payload.size() + 1);
    send(sockfd, &length, sizeof(length), 0);
    uint8_t id = static_cast<uint8_t>(messageType);
    send(sockfd, &id, sizeof(id), 0);
    if (!payload.empty())
    {
        send(sockfd, payload.data(), payload.size(), 0);
    }
}

void request_block(int sockfd, int index, int begin, int length)
{
    std::vector<uint8_t> payload(12);   
    uint32_t index_n = htonl(index);    //Piece index
    uint32_t begin_n = htonl(begin);    //Block start offset
    uint32_t length_n = htonl(length);  //Block length

    // All later integers sent in the protocol are encoded as four bytes big-endian.
    std::memcpy(&payload[0], &index_n, 4);
    std::memcpy(&payload[4], &begin_n, 4);
    std::memcpy(&payload[8], &length_n, 4);
    send_message(sockfd, MessageType::request, payload);
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
            std::string infoHash = calculateInfohash(bencoded_info);
            std::string urlEncodedHash = url_encode(infoHash);

            // announceURL
            std::string trackerURL = decoded_torrent["announce"];  

            // length
            int length = decoded_torrent["info"]["length"];

            // Parse the torrent
            // Contruct GET message
            /*
            
            info_hash: the info hash of the torrent
                20 bytes long, will need to be URL encoded
                Note: this is NOT the hexadecimal representation, which is 40 bytes long

            peer_id: a unique identifier for your client
                A string of length 20 that you get to pick.

            port: the port your client is listening on
                You can set this to 6881, you will not have to support this functionality during this challenge.

            uploaded: the total amount uploaded so far
                Since your client hasn't uploaded anything yet, you can set this to 0.

            downloaded: the total amount downloaded so far
                Since your client hasn't downloaded anything yet, you can set this to 0.

            left: the number of bytes left to download
                Since you client hasn't downloaded anything yet, this'll be the total length of the file
                (you've extracted this value from the torrent file in previous stages)

            compact: whether the peer list should use the compact representation
                For the purposes of this challenge, set this to 1.
                The compact representation is more commonly used in the wild, 
                non-compact representation is mostly supported for backward-compatibility.

            */
            std::string peerID = "01234567890123456789";
            std::ostringstream url;
            url << trackerURL << "?info_hash=" << urlEncodedHash
                << "&peer_id=" << peerID
                << "&port=6881"
                << "&uploaded=0"
                << "&downloaded=0"
                << "&left=" << length
                << "&compact=1";

            // Send HTTP GET message (request)
            // Then receive tracker response
            /*
            The tracker's response will be a bencoded dictionary with two keys:

            interval:
                An integer, indicating how often your client should make a request to the tracker.
                You can ignore this value for the purposes of this challenge.
            peers.
                A string, which contains list of peers that your client can connect to.
                Each peer is represented using 6 bytes. The first 4 bytes are the peer's IP address
                and the last 2 bytes are the peer's port number.

            */
            std::string response = http_get(url.str());

            // Decode tracker response
            json trackerResponse = decode_bencoded_value(response);

            // list of peers
            std::string peers = trackerResponse["peers"];

            // parse the peers and print them
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
    else if (command == "handshake")
    {
        std::string filePath = argv[2];
        try
        {
            std::string peerInfo = argv[3];
            size_t colon_index = peerInfo.find(':');
            if (colon_index == std::string::npos)
            {
                throw std::runtime_error("Invalid peer address format");
            }
            std::string peerIP = peerInfo.substr(0, colon_index);
            int peerPort = std::stoi(peerInfo.substr(colon_index + 1));

            // read the file 
            // bencode the torrent
            std::string fileContent = read_file(filePath);
            json decoded_torrent = decode_bencoded_value(fileContent);
            std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);
            
            // calculate the info hash
            std::string infoHash = calculateInfohash(bencoded_info);
            std::string binaryInfoHash = hex_to_binary(infoHash);
            // std::cout << binaryInfoHash << std::endl;

            // Peer ID of YOUR client
            std::string peerID = "00112233445566778899";

            /*
            1. length of the protocol string (BitTorrent protocol) which is 19 (1 byte)

            2. the string BitTorrent protocol (19 bytes)

            3. eight reserved bytes, which are all set to zero (8 bytes)

            4. sha1 infohash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)

            5. peer id (20 bytes) (generate 20 random byte values)
            */
            Handshake handshake(binaryInfoHash, peerID);
            std::vector<char> handshakeMessage = handshake.toVector();

            // Step 1: Establish TCP connection with the peer
            int sockfd = connect_to_peer(peerIP, peerPort);

            // Step 2: Send handshake message
            if (send(sockfd, handshakeMessage.data(), handshakeMessage.size(), 0) == -1) {
                closesocket(sockfd);
                throw std::runtime_error("Failed to send handshake message");
            }

            // Step 3: Receive the handshake response
            char response[68];
            ssize_t bytesRead = recv(sockfd, response, sizeof(response), 0);
            if (bytesRead != 68)
            {
                closesocket(sockfd);
                throw std::runtime_error("Invalid handshake response");
            }

            // Step 4: Validate the handshake response
            /*
            Note: the info hash in the handshake message is a binary value, not hexadecimal
            Therefore, the function must use the binary value to check for mismatch
            */ 
            validate_handshake(std::string(response, 68), binaryInfoHash);

            // close the socket
            closesocket(sockfd);
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    else if (command == "download_piece")
    {
        std::string filePath = argv[4];
        try
        {
            // Read the torrent file to get the tracker URL
            std::string fileContent = read_file(filePath);
            json decoded_torrent = decode_bencoded_value(fileContent);

            // bencode the torrent
            std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);

            // calculate the info hash
            std::string infoHash = calculateInfohash(bencoded_info);
            std::string urlEncodedHash = url_encode(infoHash);
            std::string binaryInfoHash = hex_to_binary(infoHash);

            // announceURL
            std::string trackerURL = decoded_torrent["announce"];  

            // length
            size_t length = decoded_torrent["info"]["length"];

            std::string peerID = "01234567890123456789";
            // Perform the tracker GET request to get a list of peers
            std::ostringstream url;
            url << trackerURL << "?info_hash=" << urlEncodedHash
                << "&peer_id=" << peerID
                << "&port=6881"
                << "&uploaded=0"
                << "&downloaded=0"
                << "&left=" << length
                << "&compact=1";
            
            std::string tracker_response = http_get(url.str());

            // Decode tracker response
            json trackerResponse = decode_bencoded_value(tracker_response);

            // list of peers
            std::string peers = trackerResponse["peers"];

            // parse the peers and print them
            std::vector<std::string> peerList = parse_peers(peers);

            // Establish a TCP connection with a peer, and perform a handshake
            Handshake handshake(binaryInfoHash, peerID);
            std::vector<char> handshakeMessage = handshake.toVector();
            
            if (peerList.empty()) {
                throw std::runtime_error("No peers available for connection");
            }           

            // Piece index from command  line
            // "./your_bittorrent.sh download_piece -o /tmp/test-piece sample.torrent <piece_index>"
            int piece_index = std::stoi(argv[5]);
            size_t pieceLength = decoded_torrent["info"]["piece length"];

            std::cout << "Length of file: " << length << std::endl;
            std::cout << "Piece length: " << pieceLength << std::endl;
            size_t totalPieces = (length + pieceLength - 1) / pieceLength;

            std::cout << "Total pieces: " << totalPieces << std::endl;
            bool pieceDownloaded = false;
            std::string peerInfo = peerList[0];
            // for (const auto& peerInfo : peerList)
            // {
            try
            {
                size_t colon_index = peerInfo.find(':');
                if (colon_index == std::string::npos)
                {
                    throw std::runtime_error("Invalid peer address format");
                }
                std::string peerIP = peerInfo.substr(0, colon_index);
                int peerPort = std::stoi(peerInfo.substr(colon_index + 1));

                // Step 1: Establish TCP connection with the peer
                int sockfd = connect_to_peer(peerIP, peerPort);

                // Step 2: Send handshake message
                if (send(sockfd, handshakeMessage.data(), handshakeMessage.size(), 0) == -1) {
                    closesocket(sockfd);
                    throw std::runtime_error("Failed to send handshake message");
                }

                // Step 3: Receive the handshake response
                char response[68];
                ssize_t bytesRead = recv(sockfd, response, sizeof(response), 0);
                if (bytesRead != 68)
                {
                    closesocket(sockfd);
                    throw std::runtime_error("Invalid handshake response");
                }

                // Step 4: Validate the handshake response
                std::string received_infohash = std::string(response, 68).substr(28, 20);
                if (received_infohash != binaryInfoHash) {
                    throw std::runtime_error("Invalid handshake response: Infohash mismatch");
                }
                std::cout << "Handshake established" << std::endl;

                // Exchange multiple peer messages to download the file
                // TODO
                // Receive bitfield message
                std::vector<uint8_t> bitfield = receive_message(sockfd);
                if (bitfield[0] != MessageType::bitfield)
                {
                    throw std::runtime_error("Expected bitfield message");
                }

                int byteIndex = piece_index / 8;
                int bitIndex = piece_index % 8;
                if (byteIndex >= bitfield.size() - 1 || !(bitfield[byteIndex + 1] & (1 << (7 - bitIndex)))) {
                    std::cout << "Peer does not have the requested piece" << std::endl;
                    closesocket(sockfd);
                    // continue;
                }

                std::cout << "Peer has the requested piece. Initiating download..." << std::endl;

                // Send interested message
                send_message(sockfd, MessageType::interested);

                // Receive unchoke message
                std::vector<uint8_t> unchoke = receive_message(sockfd);
                if (unchoke[0] != MessageType::unchoke)
                {
                    throw std::runtime_error("Expected unchoke message");
                }

                // Send request message
                // Divide piece into blocks and request each blocks
                // Receive piece message for each block requested
                // Note: INDEX ALWAYS STARTS FROM ZERO, DO NOT FORGET THIS
                size_t currentPieceSize = (piece_index == totalPieces - 1) ? (length % pieceLength) : pieceLength;
                if (currentPieceSize == 0)
                {
                    currentPieceSize = pieceLength;
                }
                size_t remaining = currentPieceSize;
                size_t offset = 0;
                std::vector<uint8_t> pieceData(currentPieceSize);
                
                // while (remaining > 0)    
                // do all of the below
                // TODO: Modify the below code to update the actual piece length
                while(remaining > 0)
                {
                    size_t blockSize = std::min(PIECE_BLOCK, remaining);

                    // std::cout << "Block size: " << blockSize << std::endl;

                    request_block(sockfd, piece_index, offset, blockSize);

                    // std::cout << "receiving message..." << std::endl;
                    std::vector<uint8_t> message = receive_message(sockfd);
                    if (message[0] != MessageType::piece)
                    {
                        throw std::runtime_error("Expected piece message");
                    }

                    // Extract piece data
                    int index = ntohl(*reinterpret_cast<int*>(&message[1]));
                    int begin = ntohl(*reinterpret_cast<int*>(&message[5]));
                    const uint8_t* block = &message[9];
                    int blockLength = message.size() - 9;

                    // Save the block data
                    std::memcpy(&pieceData[begin], block, blockLength);
                    // std::cout << "Remaining bytes: " << remaining << std::endl;
                    remaining -= blockLength;
                    offset += blockLength;
                }

                std::cout << "Received blocks successfully" << std::endl;

                // Verify integrity
                std::string pieceHash = calculateInfohash(std::string(pieceData.begin(), pieceData.end()));
                pieceHash = hex_to_binary(pieceHash);
                int hashLength = 20; // SHA-1 hash length in bytes
                std::string expectedPieceHash = decoded_torrent["info"]["pieces"].get<std::string>().substr(piece_index * hashLength, hashLength);
                
                if (pieceHash != expectedPieceHash)
                {
                    throw std::runtime_error("Piece hash mismatch");
                }

                // Write piece to disk
                std::ofstream output(argv[3]);
                output.write(reinterpret_cast<const char*>(pieceData.data()), pieceData.size());
                output.close();

                std::cout << "Piece downloaded successfully" << std::endl;
                pieceDownloaded = true;
                closesocket(sockfd);
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error with peer: " << e.what() << std::endl;
                // continue;
            }
            // }
            if (!pieceDownloaded) {
                throw std::runtime_error("Failed to download the requested piece from any peer");
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    else if (command == "download")
    {
        std::string filePath = argv[4];
        try
        {
            // Read the torrent file to get the tracker URL
            std::string fileContent = read_file(filePath);
            json decoded_torrent = decode_bencoded_value(fileContent);

            // bencode the torrent
            std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);

            // calculate the info hash
            std::string infoHash = calculateInfohash(bencoded_info);
            std::string urlEncodedHash = url_encode(infoHash);
            std::string binaryInfoHash = hex_to_binary(infoHash);

            // announceURL
            std::string trackerURL = decoded_torrent["announce"];  

            // length
            size_t length = decoded_torrent["info"]["length"];

            std::string peerID = "01234567890123456789";
            // Perform the tracker GET request to get a list of peers
            std::ostringstream url;
            url << trackerURL << "?info_hash=" << urlEncodedHash
                << "&peer_id=" << peerID
                << "&port=6881"
                << "&uploaded=0"
                << "&downloaded=0"
                << "&left=" << length
                << "&compact=1";
            
            std::string tracker_response = http_get(url.str());

            // Decode tracker response
            json trackerResponse = decode_bencoded_value(tracker_response);

            // list of peers
            std::string peers = trackerResponse["peers"];

            // parse the peers and print them
            std::vector<std::string> peerList = parse_peers(peers);

            // Establish a TCP connection with a peer, and perform a handshake
            Handshake handshake(binaryInfoHash, peerID);
            std::vector<char> handshakeMessage = handshake.toVector();
            
            if (peerList.empty()) {
                throw std::runtime_error("No peers available for connection");
            }           

            size_t pieceLength = decoded_torrent["info"]["piece length"];
            
            size_t totalPieces = (length + pieceLength - 1) / pieceLength;
            int piece_index = 0;
            bool fileDownloaded = false;
            std::string peerInfo = peerList[0];
            // for (const auto& peerInfo : peerList)
            // {
            try
            {
                size_t colon_index = peerInfo.find(':');
                if (colon_index == std::string::npos)
                {
                    throw std::runtime_error("Invalid peer address format");
                }
                std::string peerIP = peerInfo.substr(0, colon_index);
                int peerPort = std::stoi(peerInfo.substr(colon_index + 1));

                // Step 1: Establish TCP connection with the peer
                int sockfd = connect_to_peer(peerIP, peerPort);

                // Step 2: Send handshake message
                if (send(sockfd, handshakeMessage.data(), handshakeMessage.size(), 0) == -1) {
                    closesocket(sockfd);
                    throw std::runtime_error("Failed to send handshake message");
                }

                // Step 3: Receive the handshake response
                char response[68];
                ssize_t bytesRead = recv(sockfd, response, sizeof(response), 0);
                if (bytesRead != 68)
                {
                    closesocket(sockfd);
                    throw std::runtime_error("Invalid handshake response");
                }

                // Step 4: Validate the handshake response
                std::string received_infohash = std::string(response, 68).substr(28, 20);
                if (received_infohash != binaryInfoHash) {
                    throw std::runtime_error("Invalid handshake response: Infohash mismatch");
                }
                std::cout << "Handshake established" << std::endl;

                // Exchange multiple peer messages to download the file piece
                // TODO
                // Receive bitfield message
                std::vector<uint8_t> bitfield = receive_message(sockfd);
                if (bitfield[0] != MessageType::bitfield)
                {
                    throw std::runtime_error("Expected bitfield message");
                }

                int byteIndex = piece_index / 8;
                int bitIndex = piece_index % 8;
                if (byteIndex >= bitfield.size() - 1 || !(bitfield[byteIndex + 1] & (1 << (7 - bitIndex)))) {
                    std::cout << "Peer does not have the requested piece" << std::endl;
                    closesocket(sockfd);
                    // continue;
                }

                std::cout << "Peer has the requested piece. Initiating download..." << std::endl;
                std::ofstream output(argv[3], std::ios::binary | std::ios::in | std::ios::out);

                while (piece_index < totalPieces)
                {
                    try
                    {
                        
                    
                        // Send interested message
                        send_message(sockfd, MessageType::interested);

                        // Receive unchoke message
                        std::vector<uint8_t> unchoke = receive_message(sockfd);
                        if (unchoke[0] != MessageType::unchoke)
                        {
                            throw std::runtime_error("Expected unchoke message");
                        }

                        // Send request message
                        // Divide piece into blocks and request each blocks
                        // Receive piece message for each block requested
                        // Note: INDEX ALWAYS STARTS FROM ZERO, DO NOT FORGET THIS
                        size_t currentPieceSize = (piece_index == totalPieces - 1) ? (length % pieceLength) : pieceLength;
                        if (currentPieceSize == 0)
                        {
                            currentPieceSize = pieceLength;
                        }
                        size_t remaining = currentPieceSize;
                        size_t offset = 0;
                        std::vector<uint8_t> pieceData(currentPieceSize);
                        
                        // while (remaining > 0)    
                        // do all of the below
                        // TODO: Modify the below code to update the actual piece length
                        while(remaining > 0)
                        {
                            size_t blockSize = std::min(PIECE_BLOCK, remaining);

                            // std::cout << "Block size: " << blockSize << std::endl;

                            request_block(sockfd, piece_index, offset, blockSize);

                            // std::cout << "receiving message..." << std::endl;
                            std::vector<uint8_t> message = receive_message(sockfd);
                            if (message[0] != MessageType::piece)
                            {
                                throw std::runtime_error("Expected piece message");
                            }

                            // Extract piece data
                            int index = ntohl(*reinterpret_cast<int*>(&message[1]));
                            int begin = ntohl(*reinterpret_cast<int*>(&message[5]));
                            const uint8_t* block = &message[9];
                            int blockLength = message.size() - 9;

                            // Save the block data
                            std::memcpy(&pieceData[begin], block, blockLength);
                            remaining -= blockLength;
                            offset += blockLength;
                        }

                        std::cout << "Received blocks successfully" << std::endl;

                        // Verify integrity
                        std::string pieceHash = calculateInfohash(std::string(pieceData.begin(), pieceData.end()));
                        pieceHash = hex_to_binary(pieceHash);
                        int hashLength = 20; // SHA-1 hash length in bytes
                        std::string expectedPieceHash = decoded_torrent["info"]["pieces"].get<std::string>().substr(piece_index * hashLength, hashLength);
                        
                        if (pieceHash != expectedPieceHash)
                        {
                            throw std::runtime_error("Piece hash mismatch");
                        }

                        // Write piece to disk
                        // std::ofstream output(argv[3]);
                        output.write(reinterpret_cast<const char*>(pieceData.data()), pieceData.size());

                        std::cout << "Piece " << piece_index << " downloaded successfully" << std::endl;
                        piece_index++;
                    }
                    catch(const std::exception& e)
                    {
                        std::cerr << e.what() << '\n';
                    }
                }
                
                std::cout << "File downloaded successfully" << std::endl;
                output.close();
                closesocket(sockfd);
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error with peer: " << e.what() << std::endl;
                // continue;
            }
            if (!fileDownloaded) {
                throw std::runtime_error("Failed to download the requested file from any peer");
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}