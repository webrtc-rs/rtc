// Standalone, deterministic packet adapter for upstream WebRTC dcSCTP.
// Test-only: no UDP, DTLS, wall clock, or threads are used by this adapter.
#include <algorithm>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "net/dcsctp/public/dcsctp_message.h"
#include "net/dcsctp/public/dcsctp_options.h"
#include "net/dcsctp/public/timeout.h"
#include "net/dcsctp/socket/dcsctp_socket.h"

namespace {

uint64_t Number(std::string_view value, uint64_t maximum) {
  uint64_t result = 0;
  auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), result);
  if (error != std::errc() || end != value.data() + value.size() ||
      result > maximum) {
    throw std::runtime_error("invalid unsigned integer");
  }
  return result;
}

std::vector<uint8_t> Unhex(std::string_view value) {
  if (value == "-") return {};
  if (value.size() % 2 != 0 || value.size() > 4 * 1024 * 1024) {
    throw std::runtime_error("invalid hex length");
  }
  std::vector<uint8_t> bytes(value.size() / 2);
  for (size_t i = 0; i < bytes.size(); ++i) {
    unsigned int byte = 0;
    auto [end, error] = std::from_chars(value.data() + 2 * i,
                                      value.data() + 2 * i + 2, byte, 16);
    if (error != std::errc() || end != value.data() + 2 * i + 2) {
      throw std::runtime_error("invalid hex digit");
    }
    bytes[i] = static_cast<uint8_t>(byte);
  }
  return bytes;
}

std::string Hex(std::span<const uint8_t> bytes) {
  if (bytes.empty()) return "-";
  static constexpr char digits[] = "0123456789abcdef";
  std::string result(bytes.size() * 2, '0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    result[2 * i] = digits[bytes[i] >> 4];
    result[2 * i + 1] = digits[bytes[i] & 15];
  }
  return result;
}

std::string OneLine(absl::string_view value) {
  std::string result(value);
  std::replace(result.begin(), result.end(), '\n', ' ');
  std::replace(result.begin(), result.end(), '\r', ' ');
  return result;
}

class Peer final : public dcsctp::DcSctpSocketCallbacks {
 public:
  void Init(std::string_view role) {
    if (socket_ || (role != "client" && role != "server")) {
      throw std::runtime_error("INIT requires an uninitialized client or server");
    }
    random_ = role == "client" ? 0x12345678u : 0x87654321u;
    dcsctp::DcSctpOptions options;
    options.local_port = 5000;
    options.remote_port = 5000;
    options.enable_message_interleaving = false;
    options.enable_partial_reliability = true;
    options.heartbeat_interval = dcsctp::DurationMs(0);
    options.max_message_size = 1024 * 1024;
    options.max_send_buffer_size = 2 * 1024 * 1024;
    socket_ = std::make_unique<dcsctp::DcSctpSocket>(
        "interop", *this, nullptr, options);
  }

  bool Command(const std::vector<std::string>& words) {
    if (words.empty()) throw std::runtime_error("empty command");
    const auto& command = words[0];
    if (command == "QUIT" && words.size() == 1) return false;
    if (command == "INIT" && words.size() == 2) {
      Init(words[1]);
      return true;
    }
    if (!socket_) throw std::runtime_error("INIT required");
    if (command == "CONNECT" && words.size() == 1) {
      socket_->Connect();
    } else if (command == "SEND" && words.size() == 6) {
      auto sid = dcsctp::StreamID(Number(words[1], UINT16_MAX));
      dcsctp::SendOptions options;
      if (words[2] != "ordered" && words[2] != "unordered") {
        throw std::runtime_error("expected ordered or unordered");
      }
      options.unordered = dcsctp::IsUnordered(words[2] == "unordered");
      if (words[3].starts_with("timed:")) {
        options.lifetime = dcsctp::DurationMs(
            Number(std::string_view(words[3]).substr(6), INT32_MAX));
      } else if (words[3].starts_with("rexmit:")) {
        options.max_retransmissions =
            Number(std::string_view(words[3]).substr(7), UINT32_MAX);
      } else if (words[3] != "reliable") {
        throw std::runtime_error("unknown reliability policy");
      }
      auto ppid = dcsctp::PPID(Number(words[4], UINT32_MAX));
      auto result = socket_->Send(
          dcsctp::DcSctpMessage(sid, ppid, Unhex(words[5])), options);
      if (result != dcsctp::SendStatus::kSuccess) {
        throw std::runtime_error(std::string(dcsctp::ToString(result)));
      }
    } else if (command == "RESET" && words.size() == 2) {
      std::vector<dcsctp::StreamID> streams;
      std::istringstream list(words[1]);
      for (std::string sid; std::getline(list, sid, ',');) {
        streams.emplace_back(Number(sid, UINT16_MAX));
      }
      if (streams.empty() || words[1].back() == ',') {
        throw std::runtime_error("expected a comma-separated stream list");
      }
      auto result = socket_->ResetStreams(streams);
      if (result != dcsctp::ResetStreamsStatus::kPerformed) {
        throw std::runtime_error(std::string(dcsctp::ToString(result)));
      }
    } else if (command == "INPUT" && words.size() == 2) {
      socket_->ReceivePacket(Unhex(words[1]));
    } else if (command == "TICK" && words.size() == 2) {
      // WebRTC Timestamp internally stores microseconds; leave room for its
      // conversion and for the largest millisecond timeout.
      Advance(Number(words[1], INT64_MAX / 1000 - INT32_MAX - now_ms_));
    } else if (command == "POLL" && words.size() == 1) {
      Advance(0);
    } else {
      throw std::runtime_error("unknown command or argument count");
    }
    return true;
  }

  void SendPacket(std::span<const uint8_t> data) override {
    std::cout << "EVENT packet_time:" << now_ms_ << '\n';
    std::cout << "PACKET " << Hex(data) << '\n';
  }

  std::unique_ptr<dcsctp::Timeout> CreateTimeout(
      webrtc::TaskQueueBase::DelayPrecision) override {
    return std::make_unique<VirtualTimeout>(*this, next_timer_++);
  }

  dcsctp::TimeMs TimeMillis() override { return dcsctp::TimeMs(now_ms_); }
  webrtc::Timestamp Now() override {
    return webrtc::Timestamp::Millis(now_ms_);
  }

  uint32_t GetRandomInt(uint32_t low, uint32_t high) override {
    // Rejection sampling avoids implementation-defined distribution behavior.
    // The seed is fixed per role; this generator is not used for security.
    if (high <= low) throw std::runtime_error("invalid dcSCTP random range");
    const uint32_t width = high - low;
    const uint32_t threshold = -width % width;
    do {
      random_ = random_ * 1664525u + 1013904223u;
    } while (random_ < threshold);
    return low + random_ % width;
  }

  void OnMessageReceived(dcsctp::DcSctpMessage message) override {
    std::cout << "MESSAGE " << *message.stream_id() << ' ' << *message.ppid()
              << ' ' << Hex(message.payload()) << '\n';
  }
  void OnError(dcsctp::ErrorKind error, absl::string_view message) override {
    std::cout << "EVENT error:" << dcsctp::ToString(error) << ':'
              << OneLine(message) << '\n';
  }
  void OnAborted(dcsctp::ErrorKind error, absl::string_view message) override {
    OnError(error, message);
    OnClosed();
  }
  void OnConnected() override { std::cout << "EVENT ready\n"; }
  void OnClosed() override { std::cout << "EVENT closed\n"; }
  void OnConnectionRestarted() override { std::cout << "EVENT restarted\n"; }
  void OnStreamsResetFailed(std::span<const dcsctp::StreamID> streams,
                           absl::string_view reason) override {
    for (auto sid : streams) {
      std::cout << "EVENT reset_failed:" << *sid << ':' << OneLine(reason)
                << '\n';
    }
  }
  void OnStreamsResetPerformed(
      std::span<const dcsctp::StreamID> streams) override {
    for (auto sid : streams) std::cout << "EVENT reset_out:" << *sid << '\n';
  }
  void OnIncomingStreamsReset(
      std::span<const dcsctp::StreamID> streams) override {
    if (streams.empty()) std::cout << "EVENT reset_in:all\n";
    for (auto sid : streams) std::cout << "EVENT reset_in:" << *sid << '\n';
  }

 private:
  struct Timer {
    std::optional<int64_t> deadline;
    dcsctp::TimeoutID timeout_id = dcsctp::TimeoutID(0);
  };

  class VirtualTimeout final : public dcsctp::Timeout {
   public:
    VirtualTimeout(Peer& owner, uint64_t key) : owner_(owner), key_(key) {
      owner_.timers_.emplace(key_, Timer());
    }
    ~VirtualTimeout() override { owner_.timers_.erase(key_); }
    void Start(dcsctp::DurationMs duration,
               dcsctp::TimeoutID timeout_id) override {
      auto& timer = owner_.timers_.at(key_);
      timer.deadline = owner_.now_ms_ + *duration;
      timer.timeout_id = timeout_id;
    }
    void Stop() override { owner_.timers_.at(key_).deadline.reset(); }

   private:
    Peer& owner_;
    uint64_t key_;
  };

  void Advance(int64_t delta_ms) {
    const int64_t target = now_ms_ + delta_ms;
    for (size_t fired = 0;; ++fired) {
      auto next = timers_.end();
      for (auto it = timers_.begin(); it != timers_.end(); ++it) {
        if (it->second.deadline && *it->second.deadline <= target &&
            (next == timers_.end() ||
             *it->second.deadline < *next->second.deadline)) {
          next = it;
        }
      }
      if (next == timers_.end()) break;
      if (fired == 100000) throw std::runtime_error("timeout iteration limit");
      now_ms_ = *next->second.deadline;
      const auto timeout_id = next->second.timeout_id;
      next->second.deadline.reset();
      socket_->HandleTimeout(timeout_id);
    }
    now_ms_ = target;
  }

  int64_t now_ms_ = 0;
  uint32_t random_ = 1;
  uint64_t next_timer_ = 0;
  // Keep these alive until the socket destroys its Timeout instances.
  std::map<uint64_t, Timer> timers_;
  std::unique_ptr<dcsctp::DcSctpSocket> socket_;
};

}  // namespace

int main() {
  Peer peer;
  for (std::string line; std::getline(std::cin, line);) {
    bool keep_running = true;
    try {
      std::istringstream input(line);
      std::vector<std::string> words;
      for (std::string word; input >> word;) words.push_back(std::move(word));
      keep_running = peer.Command(words);
    } catch (const std::exception& error) {
      std::cout << "ERROR " << OneLine(error.what()) << '\n';
    }
    std::cout << "DONE\n" << std::flush;
    if (!keep_running) break;
  }
}
