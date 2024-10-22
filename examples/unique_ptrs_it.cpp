#include <iostream>
#include <vector>
#include <memory>


class DoIPConnection{
public:
    DoIPConnection(int sock):sock(sock){ };
    int sock;
};

std::vector<std::unique_ptr<DoIPConnection>> connections;
std::vector<DoIPConnection> conns;
int main() {
    std::cout << "check iterator of vector of doipconns after the erasing an object from vector" << std::endl;
    conns = {1, 2, 3, 4, 5};

    std::cout << "print vector: \t\t";
    for(auto &conn : conns)
        std::cout << conn.sock << " ";
    std::cout << std::endl;

    auto it_obj1 = conns.end() - 1;
    auto it_obj2 = conns.end() - 2;

    std::cout << "Iterator end()-2 :\t" << (*it_obj2).sock << std::endl;
    std::cout << "Iterator end()-1 :\t" << (*it_obj1).sock << std::endl;

    std::cout << "Erasing first element." << std::endl;
    conns.erase(conns.begin());

    std::cout << "print vector: \t\t";
    for(auto &conn : conns)
        std::cout << conn.sock << " ";
    std::cout << std::endl;

    std::cout << "Iterator end()-2 :\t" << (*it_obj2).sock << std::endl;
    std::cout << "Iterator end()-1 :\t" << (*it_obj1).sock << std::endl;

    std::cout << "check iterator of vector of unique ptrs to doipconns after the erasing an object from vector" << std::endl;
    auto conn1 = std::make_unique<DoIPConnection>(1);
    auto conn2 = std::make_unique<DoIPConnection>(2);
    auto conn3 = std::make_unique<DoIPConnection>(3);
    auto conn4 = std::make_unique<DoIPConnection>(4);
    auto conn5 = std::make_unique<DoIPConnection>(5);

    connections.push_back(std::move(conn1));
    connections.push_back(std::move(conn2));
    connections.push_back(std::move(conn3));
    connections.push_back(std::move(conn4));
    connections.push_back(std::move(conn5));

    std::cout << "print vector: \t\t";
    for(auto &conn : connections)
        std::cout << conn->sock << " ";
    std::cout << std::endl;

    auto it_un1 = connections.end() - 1;
    auto it_un2 = connections.end() - 2;

    std::cout << "Iterator end()-2 :\t" << (*it_un2)->sock << std::endl;
    std::cout << "Iterator end()-1 :\t" << (*it_un1)->sock << std::endl;

    std::cout << "Erasing first element." << std::endl;
    connections.erase(connections.begin());

    std::cout << "print vector: \t\t";
    for(auto &conn : connections)
        std::cout << conn->sock << " ";
    std::cout << std::endl;

    std::cout << "Iterator end()-2 :\t" << (*it_un2)->sock << std::endl;
    std::cout << "Iterator end()-1 :\t" << (*it_un1)->sock << std::endl;

    return 0;
}