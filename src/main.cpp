#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <fstream>
#include <memory>

#include "crypter.hpp"

int main(int argc, char* argv[]) {
    try {
        if (argc != 3) {
            printf("Usage: %s <input_file> <output_file>\n", argv[0]);
            return 1;
        }

        // Read input file
        std::ifstream input(argv[1], std::ios::binary);
        if (!input) {
            printf("[-] Failed to open input file: %s\n", argv[1]);
            return 1;
        }

        std::vector<uint8_t> inputData(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        input.close();

        // Process file
        Crypter::Engine engine;
        std::vector<uint8_t> outputData;
        if (!engine.process(inputData, outputData)) {
            printf("[-] Failed to process file\n");
            return 1;
        }

        // Save output file
        std::ofstream output(argv[2], std::ios::binary);
        if (!output) {
            printf("[-] Failed to create output file: %s\n", argv[2]);
            return 1;
        }

        output.write(reinterpret_cast<const char*>(outputData.data()), outputData.size());
        output.close();

        printf("[+] Successfully processed file\n");
        printf("[+] Input size: %zu bytes\n", inputData.size());
        printf("[+] Output size: %zu bytes\n", outputData.size());
        return 0;
    }
    catch (const std::exception& e) {
        printf("[-] Exception: %s\n", e.what());
        return 1;
    }
}
