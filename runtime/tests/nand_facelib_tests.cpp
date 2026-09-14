#include "nand_facelib.h"

#include <cryptopp/sha.h>

#include <array>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

static void Require(bool condition,
                    const char *message = "FaceLib database check failed") {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

static std::vector<std::uint8_t> ReadBytes(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input),
          std::istreambuf_iterator<char>()};
}

static void WriteBytes(const std::filesystem::path &path,
                       const std::vector<std::uint8_t> &bytes) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream output(path, std::ios::binary);
  output.write(reinterpret_cast<const char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
}

static void UpdateCrc(std::vector<std::uint8_t> &bytes) {
  assert(bytes.size() > RuntimeNandFaceLib::kCrcOffset + 1);
  std::uint16_t crc = 0;
  for (std::size_t i = 0; i < RuntimeNandFaceLib::kCrcOffset; ++i) {
    crc ^= static_cast<std::uint16_t>(bytes[i]) << 8;
    for (unsigned bit = 0; bit < 8; ++bit) {
      crc = (crc & 0x8000) != 0
                ? static_cast<std::uint16_t>((crc << 1) ^ 0x1021)
                : static_cast<std::uint16_t>(crc << 1);
    }
  }
  bytes[RuntimeNandFaceLib::kCrcOffset] = static_cast<std::uint8_t>(crc >> 8);
  bytes[RuntimeNandFaceLib::kCrcOffset + 1] = static_cast<std::uint8_t>(crc);
}

int main() {
  const auto root =
      std::filesystem::temp_directory_path() /
      ("wiicomp-nand-facelib-" +
       std::to_string(
           std::chrono::steady_clock::now().time_since_epoch().count()));
  try {
    using namespace RuntimeNandFaceLib;
    const auto blank = BuildBlankDatabase();
    Require(blank.size() == kDatabaseSize, "Blank database size");
    Require(blank[0] == 'R' && blank[1] == 'N' && blank[2] == 'O' &&
                blank[3] == 'D',
            "RNOD magic");
    Require(blank[0x1CEC] == 0x80, "Blank database flag");
    Require(blank[0x1D00] == 'R' && blank[0x1D01] == 'N' &&
                blank[0x1D02] == 'H' && blank[0x1D03] == 'D',
            "RNHD magic");
    Require(blank[0x1D04] == 0xFF && blank[0x1D05] == 0xFF &&
                blank[0x1D06] == 0xFF && blank[0x1D07] == 0xFF,
            "Blank hidden database fields");
    Require(blank[kCrcOffset] == 0x30 && blank[kCrcOffset + 1] == 0xEE,
            "Blank database CRC");
    std::array<unsigned char, CryptoPP::SHA256::DIGESTSIZE> digest{};
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(digest.data(), blank.data(), blank.size());
    const std::array<unsigned char, CryptoPP::SHA256::DIGESTSIZE>
        expectedDigest{
            0x46, 0x51, 0x95, 0xF0, 0x3A, 0xB6, 0x11, 0xA2, 0xDE, 0x3C, 0x16,
            0x0A, 0xB7, 0x29, 0x00, 0x46, 0x3B, 0x59, 0xEC, 0x30, 0xA2, 0xDA,
            0xEA, 0xF6, 0x23, 0xB2, 0x86, 0x16, 0x85, 0xAB, 0xFD, 0xA3,
        };
    if (digest != expectedDigest) {
      for (const auto byte : digest)
        std::fprintf(stderr, "%02x", byte);
      std::fputc('\n', stderr);
    }
    Require(digest == expectedDigest, "Blank database SHA-256");

    std::string error;
    const auto fresh = root / "fresh";
    Require(EnsureDatabase(fresh, error), "Fresh NAND initialization");
    const auto firstBoot = ReadBytes(FilePath(fresh));
    Require(firstBoot == blank, "Fresh NAND bytes");
    Require(EnsureDatabase(fresh, error), "Second NAND initialization");
    Require(ReadBytes(FilePath(fresh)) == firstBoot,
            "Second launch must not change the database");

    auto populated = blank;
    populated[4] = 0xA5;
    UpdateCrc(populated);
    Require(IsValidDatabase(populated), "Populated database validity");
    const auto existing = root / "existing";
    WriteBytes(FilePath(existing), populated);
    Require(EnsureDatabase(existing, error), "Existing database");
    Require(ReadBytes(FilePath(existing)) == populated,
            "Existing database must remain unchanged");

    for (const auto &invalid : std::vector<std::vector<std::uint8_t>>{
             {},
             std::vector<std::uint8_t>(kDatabaseSize - 1),
             [&] {
               auto bytes = blank;
               bytes[0] = 0;
               return bytes;
             }(),
             [&] {
               auto bytes = blank;
               bytes[0x1D00] = 0;
               return bytes;
             }(),
             [&] {
               auto bytes = blank;
               bytes[kCrcOffset] ^= 1;
               return bytes;
             }(),
             std::vector<std::uint8_t>(kDatabaseSize + 1)}) {
      const auto invalidRoot =
          root / ("invalid-" + std::to_string(invalid.size()) + "-" +
                  std::to_string(invalid.empty() ? 0 : invalid[0]));
      WriteBytes(FilePath(invalidRoot), invalid);
      const auto before = ReadBytes(FilePath(invalidRoot));
      Require(!EnsureDatabase(invalidRoot, error),
              "Invalid database must fail");
      Require(ReadBytes(FilePath(invalidRoot)) == before,
              "Invalid database must remain unchanged");
    }

    const auto directoryRoot = root / "directory";
    std::filesystem::create_directories(FilePath(directoryRoot));
    Require(!EnsureDatabase(directoryRoot, error),
            "Directory destination must fail");
    Require(std::filesystem::is_directory(FilePath(directoryRoot)),
            "Directory destination must remain");

#ifndef _WIN32
    const auto symlinkRoot = root / "symlink";
    const auto symlinkTarget = root / "symlink-target.dat";
    WriteBytes(symlinkTarget, populated);
    std::filesystem::create_directories(FilePath(symlinkRoot).parent_path());
    std::filesystem::create_symlink(symlinkTarget, FilePath(symlinkRoot));
    Require(!EnsureDatabase(symlinkRoot, error),
            "Symlink destination must fail");
    Require(ReadBytes(symlinkTarget) == populated,
            "Symlink target must remain unchanged");
#endif

    const auto blockedRoot = root / "blocked";
    std::filesystem::create_directories(blockedRoot);
    {
      std::ofstream output(blockedRoot / "shared2");
      output << "blocked";
    }
    Require(!EnsureDatabase(blockedRoot, error), "Blocked parent must fail");

    const auto concurrent = root / "concurrent";
    std::array<bool, 16> results{};
    std::vector<std::thread> workers;
    for (std::size_t i = 0; i < results.size(); ++i) {
      workers.emplace_back([&, i] {
        std::string detail;
        results[i] = EnsureDatabase(concurrent, detail);
      });
    }
    for (auto &worker : workers)
      worker.join();
    for (const bool result : results)
      Require(result, "Concurrent initialization");
    Require(ReadBytes(FilePath(concurrent)) == blank,
            "Concurrent winner bytes");
    for (const auto &entry : std::filesystem::directory_iterator(
             FilePath(concurrent).parent_path())) {
      Require(entry.path().filename().string().rfind(".setting-init-facelib-",
                                                     0) != 0,
              "Temporary directory must be removed");
    }

    std::filesystem::remove_all(root);
    std::cout << "FaceLib database initialization checks passed\n";
    return 0;
  } catch (const std::exception &exception) {
    std::filesystem::remove_all(root);
    std::cerr << exception.what() << '\n';
    return 1;
  }
}
