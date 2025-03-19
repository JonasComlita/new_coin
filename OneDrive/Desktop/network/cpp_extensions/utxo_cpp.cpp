// blockchain_cpp/utxo.cpp
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <tuple>

namespace py = pybind11;

// Efficient UTXO set implementation in C++
class UTXOSetCpp
{
private:
    std::unordered_map<std::string, std::vector<py::object>> utxos;
    std::unordered_map<std::string, std::unordered_set<uint64_t>> used_nonces;

public:
    UTXOSetCpp() {}

    bool add_utxo(const std::string &tx_id, size_t output_index, py::object output)
    {
        if (utxos.find(tx_id) == utxos.end())
        {
            utxos[tx_id] = std::vector<py::object>();
        }

        // Resize vector if needed
        if (utxos[tx_id].size() <= output_index)
        {
            utxos[tx_id].resize(output_index + 1, py::none());
        }

        utxos[tx_id][output_index] = output;
        return true;
    }

    py::object get_utxo(const std::string &tx_id, size_t output_index)
    {
        if (utxos.find(tx_id) == utxos.end() || utxos[tx_id].size() <= output_index)
        {
            return py::none();
        }
        return utxos[tx_id][output_index];
    }

    bool spend_utxo(const std::string &tx_id, size_t output_index)
    {
        if (utxos.find(tx_id) == utxos.end() || utxos[tx_id].size() <= output_index)
        {
            return false;
        }

        utxos[tx_id][output_index] = py::none();
        return true;
    }

    bool is_nonce_used(const std::string &address, uint64_t nonce)
    {
        return used_nonces.find(address) != used_nonces.end() &&
               used_nonces[address].find(nonce) != used_nonces[address].end();
    }

    void add_nonce(const std::string &address, uint64_t nonce)
    {
        used_nonces[address].insert(nonce);
    }

    size_t utxo_count() const
    {
        size_t count = 0;
        for (const auto &entry : utxos)
        {
            for (const auto &output : entry.second)
            {
                if (!output.is_none())
                {
                    count++;
                }
            }
        }
        return count;
    }

    py::list get_utxos_for_address(const std::string &address)
    {
        py::list result;
        for (const auto &entry : utxos)
        {
            for (size_t i = 0; i < entry.second.size(); i++)
            {
                if (!entry.second[i].is_none())
                {
                    py::object output = entry.second[i];
                    py::object recipient = output.attr("recipient");

                    if (py::cast<std::string>(recipient) == address)
                    {
                        result.append(py::make_tuple(entry.first, i, output));
                    }
                }
            }
        }
        return result;
    }
};

PYBIND11_MODULE(utxo_cpp, m)
{
    m.doc() = "C++ implementation of UTXO set";

    py::class_<UTXOSetCpp>(m, "UTXOSetCpp")
        .def(py::init<>())
        .def("add_utxo", &UTXOSetCpp::add_utxo)
        .def("get_utxo", &UTXOSetCpp::get_utxo)
        .def("spend_utxo", &UTXOSetCpp::spend_utxo)
        .def("is_nonce_used", &UTXOSetCpp::is_nonce_used)
        .def("add_nonce", &UTXOSetCpp::add_nonce)
        .def("utxo_count", &UTXOSetCpp::utxo_count)
        .def("get_utxos_for_address", &UTXOSetCpp::get_utxos_for_address);
}