#include "venues/jito/bundle_codec.hpp"

#include "core/base58.hpp"
#include "core/log.hpp"
#include "core/span_util.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <cstddef>

#include <google/protobuf/arena.h>
#include <grpcpp/grpcpp.h>
#include <sodium.h>

#include "auth.grpc.pb.h"
#include "bundle.pb.h"
#include "packet.pb.h"
#include "searcher.grpc.pb.h"

namespace venues::jito {
namespace {
constexpr std::size_t kMaxBundleTxs   = 5;
constexpr std::size_t kSignatureBytes = 64;
constexpr std::size_t kMaxPacketBytes = 1232;

struct CompactU16 { std::uint16_t value; std::size_t width; };

[[nodiscard]] constexpr std::optional<CompactU16>
read_compact_u16(std::span<const std::byte> in) noexcept {
    std::uint32_t acc = 0;
    for (std::size_t i = 0; i < 3 && i < in.size(); ++i) {
        const auto b = std::to_integer<std::uint32_t>(in[i]);
        acc |= (b & 0x7Fu) << (7 * i);
        if ((b & 0x80u) == 0) {
            if (acc > 0xFFFFu) return std::nullopt;
            return CompactU16{static_cast<std::uint16_t>(acc), i + 1};
        }
    }
    return std::nullopt;
}

google::protobuf::ArenaOptions make_arena_options() {
    google::protobuf::ArenaOptions opts;
    opts.start_block_size = 4096;
    opts.max_block_size   = 16384;
    return opts;
}
}

void encode_packet(std::span<const std::byte> tx, packet::Packet& out) {
    if (tx.empty() || tx.size() > kMaxPacketBytes) throw CodecError("transaction size out of range for a packet");
    out.set_data(tx.data(), tx.size());
    out.mutable_meta()->set_size(static_cast<std::uint64_t>(tx.size()));
}

[[nodiscard]] std::optional<std::string>
first_signature_b58(std::span<const std::byte> tx) {
    const auto count = read_compact_u16(tx);
    if (!count || count->value == 0) return std::nullopt;
    const auto sig = tx.subspan(std::min(count->width, tx.size()));
    if (sig.size() < kSignatureBytes) return std::nullopt;

    return core::base58_encode(sig.first(kSignatureBytes));
}

searcher::SendBundleRequest make_send_request(std::span<const TxBuf> txs) {
    if (txs.empty() || txs.size() > kMaxBundleTxs) throw CodecError("bundle size out of range");
    searcher::SendBundleRequest req;
    bundle::Bundle* b = req.mutable_bundle();
    b->mutable_packets()->Reserve(static_cast<int>(txs.size()));
    for (const TxBuf& t : txs) encode_packet(core::as_bytes_span(t), *b->add_packets());
    if (const auto sig = first_signature_b58(core::as_bytes_span(txs.front()))) {
        LOG_DEBUG("jito: encoded bundle of {} txs, lead sig {}", txs.size(), *sig);
    }
    return req;
}

BundleArena::BundleArena()
    : arena_(make_arena_options()) {}

searcher::SendBundleRequest& BundleArena::build(std::span<const TxBuf> txs) {
    if (txs.empty() || txs.size() > kMaxBundleTxs) throw CodecError("bundle size out of range");
    arena_.Reset();
    auto* req = google::protobuf::Arena::Create<searcher::SendBundleRequest>(&arena_);
    bundle::Bundle* b = req->mutable_bundle();
    for (const TxBuf& t : txs) encode_packet(core::as_bytes_span(t), *b->add_packets());
    return *req;
}

class JitoVenue {
public:
    using SecretKey = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>;

    JitoVenue(const std::shared_ptr<grpc::Channel>& channel, const SecretKey& sk)
        : sk_(sk),
          auth_(auth::AuthService::NewStub(channel)),
          searcher_(searcher::SearcherService::NewStub(channel)) {
        crypto_sign_ed25519_sk_to_pk(pk_.data(), sk_.data());
        pubkey_b58_ = core::base58_encode(std::as_bytes(std::span(pk_)));
        authenticate();
        refresher_ = std::jthread([this](std::stop_token st) { refresh_loop(st); });
        reader_    = std::jthread([this](std::stop_token st) { read_results(st); });
    }

    JitoVenue(const JitoVenue&) = delete;
    JitoVenue& operator=(const JitoVenue&) = delete;

    std::string submit(std::span<const TxBuf> txs) {
        const auto req = make_send_request(txs);
        searcher::SendBundleResponse res;
        grpc::ClientContext ctx;
        authorize(ctx);
        std::lock_guard lk(own_mtx_);
        check(searcher_->SendBundle(&ctx, req, &res), "SendBundle");
        own_.insert(res.uuid());
        sent_.fetch_add(1, std::memory_order_relaxed);
        return res.uuid();
    }

    double land_rate() const noexcept {
        const auto sent = sent_.load(std::memory_order_relaxed);
        if (sent == 0) return 0.0;
        return static_cast<double>(landed_.load(std::memory_order_relaxed)) /
               static_cast<double>(sent);
    }

private:
    static void check(const grpc::Status& s, const char* what) {
        if (!s.ok()) throw std::runtime_error(std::string("jito ") + what + ": " + s.error_message());
    }
    void authorize(grpc::ClientContext& ctx) {
        std::lock_guard lk(tok_mtx_);
        ctx.AddMetadata("authorization", "Bearer " + access_);
    }
    void store_access(const auth::Token& t) {
        const auto left = static_cast<std::int64_t>(t.expires_at_utc().seconds()) -
                          std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) - 60;
        refresh_secs_.store(std::max<std::int64_t>(left, 5));
        std::lock_guard lk(tok_mtx_);
        access_ = t.value();
    }
    void authenticate() {
        auth::GenerateAuthChallengeRequest creq;
        creq.set_role(auth::SEARCHER);
        creq.set_pubkey(pk_.data(), pk_.size());
        auth::GenerateAuthChallengeResponse cres;
        {
            grpc::ClientContext ctx;
            check(auth_->GenerateAuthChallenge(&ctx, creq, &cres), "GenerateAuthChallenge");
        }
        const std::string msg = pubkey_b58_ + "-" + cres.challenge();
        std::array<unsigned char, crypto_sign_BYTES> sig{};
        crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const unsigned char*>(msg.data()),
                             msg.size(), sk_.data());
        auth::GenerateAuthTokensRequest treq;
        treq.set_challenge(msg);
        treq.set_client_pubkey(pk_.data(), pk_.size());
        treq.set_signed_challenge(sig.data(), sig.size());
        auth::GenerateAuthTokensResponse tres;
        grpc::ClientContext ctx;
        check(auth_->GenerateAuthTokens(&ctx, treq, &tres), "GenerateAuthTokens");

        { std::lock_guard lk(tok_mtx_); refresh_ = tres.refresh_token().value(); }
        store_access(tres.access_token());
        LOG_INFO("jito: token issued for {}", pubkey_b58_);
    }
    void refresh_once() {
        auth::RefreshAccessTokenRequest req;
        { std::lock_guard lk(tok_mtx_); req.set_refresh_token(refresh_); }
        auth::RefreshAccessTokenResponse res;
        grpc::ClientContext ctx;
        check(auth_->RefreshAccessToken(&ctx, req, &res), "RefreshAccessToken");
        store_access(res.access_token());
    }
    bool pause(std::stop_token st, std::chrono::seconds d) {
        std::unique_lock lk(tok_mtx_);
        tok_cv_.wait_for(lk, st, d, [] { return false; });
        return !st.stop_requested();
    }
    void refresh_loop(std::stop_token st) {
        for (;;) {
            if (!pause(st, std::chrono::seconds(refresh_secs_.load()))) return;
            try {
                refresh_once();
            } catch (const std::exception& e) {
                LOG_WARN("jito: refresh failed ({}), re-authenticating", e.what());
                try { authenticate(); } catch (const std::exception&) {
                    if (!pause(st, std::chrono::seconds(5))) return;
                }
            }
        }
    }
    void settle(const bundle::BundleResult& r) {
        using R = bundle::BundleResult;
        const bool landed = r.result_case() == R::kProcessed || r.result_case() == R::kFinalized;
        if (!landed && r.result_case() != R::kDropped && r.result_case() != R::kRejected) return;
        {
            std::lock_guard lk(own_mtx_);
            if (own_.erase(r.bundle_id()) == 0) return;
        }
        (landed ? landed_ : dropped_).fetch_add(1, std::memory_order_relaxed);
    }
    void read_results(std::stop_token st) {
        while (!st.stop_requested()) {
            grpc::ClientContext ctx;
            std::stop_callback cancel(st, [&ctx] { ctx.TryCancel(); });
            authorize(ctx);
            const searcher::SubscribeBundleResultsRequest req;
            const auto reader = searcher_->SubscribeBundleResults(&ctx, req);
            bundle::BundleResult r;
            while (reader->Read(&r)) settle(r);
            const grpc::Status s = reader->Finish();
            if (st.stop_requested()) return;
            LOG_WARN("jito: result stream closed: {}", s.error_message());
            if (!pause(st, std::chrono::seconds(1))) return;
        }
    }
    SecretKey sk_;
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pk_{};
    std::string pubkey_b58_;
    std::unique_ptr<auth::AuthService::Stub> auth_;
    std::unique_ptr<searcher::SearcherService::Stub> searcher_;
    std::mutex tok_mtx_;
    std::condition_variable_any tok_cv_;
    std::string access_, refresh_;
    std::atomic<std::int64_t> refresh_secs_{60};
    std::mutex own_mtx_;
    std::unordered_set<std::string> own_;
    std::atomic<std::uint64_t> sent_{0}, landed_{0}, dropped_{0};
    std::jthread refresher_;
    std::jthread reader_;
};
}
