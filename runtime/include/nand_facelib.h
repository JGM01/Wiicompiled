#pragma once

#include "nand_settings.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace RuntimeNandFaceLib {

inline constexpr std::size_t kDatabaseSize = 779'968;
inline constexpr std::size_t kCrcOffset = 0x1F1DE;

inline std::filesystem::path FilePath(const std::filesystem::path &nandRoot) {
  assert(nandRoot.is_absolute());
  return nandRoot / "shared2/menu/FaceLib/RFL_DB.dat";
}

inline bool IsValidDatabase(const std::vector<std::uint8_t> &bytes) {
  assert(kCrcOffset + 2 <= kDatabaseSize);
  if (bytes.size() != kDatabaseSize ||
      !std::equal(bytes.begin(), bytes.begin() + 4,
                  std::array<std::uint8_t, 4>{'R', 'N', 'O', 'D'}.begin()) ||
      !std::equal(bytes.begin() + 0x1D00, bytes.begin() + 0x1D04,
                  std::array<std::uint8_t, 4>{'R', 'N', 'H', 'D'}.begin())) {
    return false;
  }
  std::uint16_t crc = 0;
  for (std::size_t i = 0; i < kCrcOffset; ++i) {
    crc ^= static_cast<std::uint16_t>(bytes[i]) << 8;
    for (unsigned bit = 0; bit < 8; ++bit) {
      crc = (crc & 0x8000) != 0
                ? static_cast<std::uint16_t>((crc << 1) ^ 0x1021)
                : static_cast<std::uint16_t>(crc << 1);
    }
  }
  const auto stored = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[kCrcOffset]) << 8) |
      bytes[kCrcOffset + 1]);
  return stored == crc;
}

inline std::vector<std::uint8_t> BuildBlankDatabase() {
  std::vector<std::uint8_t> bytes(kDatabaseSize);
  std::copy_n(std::array<std::uint8_t, 4>{'R', 'N', 'O', 'D'}.begin(), 4,
              bytes.begin());
  bytes[0x1CEC] = 0x80;
  std::copy_n(std::array<std::uint8_t, 4>{'R', 'N', 'H', 'D'}.begin(), 4,
              bytes.begin() + 0x1D00);
  std::fill(bytes.begin() + 0x1D04, bytes.begin() + 0x1D08, 0xFF);
  std::uint16_t crc = 0;
  for (std::size_t i = 0; i < kCrcOffset; ++i) {
    crc ^= static_cast<std::uint16_t>(bytes[i]) << 8;
    for (unsigned bit = 0; bit < 8; ++bit) {
      crc = (crc & 0x8000) != 0
                ? static_cast<std::uint16_t>((crc << 1) ^ 0x1021)
                : static_cast<std::uint16_t>(crc << 1);
    }
  }
  bytes[kCrcOffset] = static_cast<std::uint8_t>(crc >> 8);
  bytes[kCrcOffset + 1] = static_cast<std::uint8_t>(crc);
  assert(IsValidDatabase(bytes));
  return bytes;
}

inline bool EnsureDatabase(const std::filesystem::path &nandRoot,
                           std::string &error) {
  assert(nandRoot.is_absolute());
  const auto path = FilePath(nandRoot);
  const auto readDatabase = [&]() -> std::optional<std::vector<std::uint8_t>> {
    std::error_code statusError;
    const auto status = std::filesystem::symlink_status(path, statusError);
    if (statusError || !std::filesystem::is_regular_file(status)) {
      return std::nullopt;
    }
    std::error_code sizeError;
    const auto size = std::filesystem::file_size(path, sizeError);
    if (sizeError || size != kDatabaseSize) {
      return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(kDatabaseSize);
    std::ifstream input(path, std::ios::binary);
    if (!input.read(reinterpret_cast<char *>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()))) {
      return std::nullopt;
    }
    return bytes;
  };

  std::error_code ec;
  const auto status = std::filesystem::symlink_status(path, ec);
  if (ec && ec != std::errc::no_such_file_or_directory) {
    error = "Cannot inspect RFL_DB.dat: " + ec.message();
    return false;
  }
  if (std::filesystem::exists(status)) {
    const auto existing = readDatabase();
    if (existing && IsValidDatabase(*existing)) {
      assert(IsValidDatabase(*existing));
      return true;
    }
    error = "Existing RFL_DB.dat is unreadable or invalid; restore it from a "
            "trusted backup";
    return false;
  }

  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    error = "Cannot create the FaceLib directory: " + ec.message();
    return false;
  }
  static std::atomic<unsigned> sequence{0};
#ifdef _WIN32
  const auto processId = GetCurrentProcessId();
#else
  const auto processId = getpid();
#endif
  const auto scratch = RuntimeNandSettings::CreateScratchDirectory(
      path.parent_path(),
      "facelib-" + std::to_string(processId) + "-" +
          std::to_string(
              std::chrono::steady_clock::now().time_since_epoch().count()) +
          "-" + std::to_string(sequence++),
      ec);
  if (!scratch) {
    error = "Cannot create temporary FaceLib storage: " + ec.message();
    return false;
  }
  const auto temporary = *scratch / "RFL_DB.dat";
  const auto bytes = BuildBlankDatabase();
  bool written = false;
  {
    std::ofstream output(temporary, std::ios::binary);
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.close();
    written = static_cast<bool>(output);
  }
  bool published = false;
  if (written) {
#ifdef _WIN32
    published = MoveFileExW(temporary.c_str(), path.c_str(),
                            MOVEFILE_WRITE_THROUGH) != 0;
#else
    published = ::link(temporary.c_str(), path.c_str()) == 0;
#endif
  }
  std::error_code cleanupError;
  std::filesystem::remove(temporary, cleanupError);
  std::filesystem::remove(*scratch, cleanupError);

  const auto persisted = readDatabase();
  if (persisted && IsValidDatabase(*persisted)) {
    assert(IsValidDatabase(*persisted));
    return true;
  }
  error =
      published
          ? "Cannot read the initialized RFL_DB.dat"
          : "Cannot persist RFL_DB.dat; check the NAND directory permissions";
  return false;
}

} // namespace RuntimeNandFaceLib
